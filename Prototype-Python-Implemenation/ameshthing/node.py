from .constructs import BaseNode, Property, Action
from .broadcast import Broadcast, TransmittableBroadcast, RespCode

from .encoding import encode as m_encode
from .encoding import decode as m_decode

from .util import base64_decode, base64_encode
from os import rename as file_rename

from .exceptions import NotToMeException, ExceptionWithResponse, DecodingError, NotInSecureGroupException, UnknownNodeException, ArgumentValidationError, TransmissionError
from nacl.exceptions import BadSignatureError as nacl_BadSignatureError

from .crypto import Crypto

import logging

from time import time

import struct

class Node(BaseNode):

    def __init__(self):
        super().__init__()

        self.cached_nodes = {} # {addr:Node<>,...}

        self.crypto = Crypto()

        self.joined_groups = set() # 'all groups' names
        self.joined_secure_groups = {} # name : symmetric key bytes


        self.dispatched_requests = []


    @property
    def node_info(self):
        make = {}

        make['addr'] = self.crypto.public_address
        make['kVerify'] = self.crypto.signing_key.verify_key.encode()
        make['kPublic'] = self.crypto.private_key.public_key.encode()

        make['groups'] = {'*':list(self.joined_groups),
                          '#': list(self.joined_secure_groups.keys())}

        make['v'] = '0.1'

        make['netTime'] = -1 # todo

        make['capabilities'] = self._node_info.get('capabilities', [])

        self._node_info.update(make)

        return self._node_info

    @node_info.setter
    def node_info(self, new):
        self._node_info = new


    def broadcast_is_to_this_node(self, b:Broadcast):
        """True if Broadcast is to the node in anyway (group or direct)."""

        return( b.is_to_all() or \
                b.to == self.network_addr or \
                b.to_secure_group() in self.joined_secure_groups or \
                b.to_gen_group() in self.joined_groups)



    def update_cached_properties(self, frm:bytes, resp_annc_obj:dict):
        """Uses a RESP or ANNC broadcast to update values of cached node's properties.
        Actions may be included in the dict, but will ignore them (as they start with `^`)
        """

        cn = self.cached_nodes.get(frm, None)

        if cn != None:
            for key, value in resp_annc_obj.items():

                if value == '\x15': continue # assume does not exist of no access, so skip

                p = cn.property_named(key)
                if not p: continue

                p.value = value  # if all checks out, update cache


    def payload_decryptor(self, payload:bytes, to, frm):
        """Takes a payload, the to, and the from; returns decrpyted and b64 decoded payload.
        Used to decrpyt a payload to this node or a secure group it may be a part of.
        """

        if to.startswith(b'*'): # no extra encryption, just b64 decode
            return base64_decode(payload)

        if len(to) <= 1: # at this point len(to) > 1
            raise ExceptionWithResponse(RespCode.PRSER, "Invalid 'to' address.", back_to=frm)

        if to == self.network_addr: # to == public address

            from_public_key = self.cached_nodes[frm].node_info['kPublic']

            raw_payload = base64_decode(payload)

            return self.crypto.decrypt_from_public_key(raw_payload, from_public_key)

        if to.startswith(b'#'):
            group_name = to

            if group_name in self.joined_secure_groups:

                group_key = self.joined_secure_groups[group_name]

                plain_payload = Crypto.decrypt_symmetrically(base64_decode(payload), group_key)

                return plain_payload
            else:
                return base64_decode(payload)


        return base64_decode(payload) # if cant decrypt, just give it back?? TODO


    def payload_encryptor(self, b:Broadcast, pre_payload:bytes):
        """Encrypts and b64 encodes the constructed payload(pre_payload)
        given the broadcast information."""

        if b.to_gen_group(): #includes 'all' (*)
            return base64_encode(pre_payload)

        if b.to_secure_group():

            group_name = b.to_secure_group()
            if group_name in self.joined_secure_groups:

                group_key = self.joined_secure_groups[group_name]

                payload_encrypted = Crypto.encrypt_symmetrically(pre_payload, group_key)

                return base64_encode(payload_encrypted)
            else:
                raise NotInSecureGroupException(group_name)


        if b.to in self.cached_nodes:

            to_public_key = self.cached_nodes[b.to].node_info['kPublic']

            raw_encrypted = self.crypto.encrypt_to_public_key(pre_payload, to_public_key)

            return base64_encode(raw_encrypted)
        else:
            # unkown node, cant encypt, check if part of marco-polo TODO
            pass
            #raise UnknownNodeException()

        raise Exception('Could not determine how to encrypt/encode the broadcast \
        from the node. This (idealy) should never happen, \
        another Exception should come first if any.')




    def transmission_received_callback(self, raw_data) -> TransmittableBroadcast:
        """The raw, fully network encrypted data. The entry point of an 'off the wire' data. """

        if raw_data.startswith(b'\x01\x05'): # v1, discovery
            return self.handle_discover_broadcast_data(raw_data)
            # return a TransmittableBroadcast from discovery processing
            #  to prevent raw_data interprtaion as normal broadcast

        raw_data = raw_data[4:] # remove version byte, x01 normal 'broadcast byte', and 2 byte len

        try:
            decrypted_signed_data = self.crypto.decrypt_from_network(raw_data)

            frm = decrypted_signed_data[32+32+7:].split(b'|', 3)[2]
            frm_node = self.cached_nodes[frm]

            verify_key_bytes = frm_node.node_info['kVerify']

            broadcast_raw = self.crypto.verify_signed_bytes(decrypted_signed_data, verify_key_bytes)

        except nacl_BadSignatureError:
            logging.error('Bad signature from node: ' + str(frm_node))

            bdsig_resp = Broadcast.RESP(frm, self.network_addr, RespCode.BDSIG)

            return self.make_transmittable_broadcast(bdsig_resp)
        except KeyError as ke:
            logging.error('Unknown node address, unable to verify.')
            ukn_resp = Broadcast.RESP(frm, self.network_addr, RespCode.NAK)
            ukn_resp.resp_payload_obj = 'Unknown node address, unable to verify.'
            return self.make_transmittable_broadcast(ukn_resp)
        except Exception as e:
            logging.error('Parsing error, can\'t respond, exception caught: ' + repr(e))
            # resp = Broadcast.RESP(frm, self.network_addr, RespCode.PRSER)
            return

        return self.process_plain_broadcast_bytes(broadcast_raw)

    def process_plain_broadcast_bytes(self, bcast_bytes:bytes) -> TransmittableBroadcast:
        """Takes the plain network decrpyted level broadcast,
            signature valid, payload may be encrypted"""

        self.did_receive_plain_broadcast(bcast_bytes) # delegate

        def handle_negitive_responce(message:str, to, code):
            neg_resp = Broadcast.RESP(to, self.network_addr, code)
            neg_resp.resp_payload_obj = message # set resp payload

            return self.make_transmittable_broadcast(neg_resp)


        try:
            b = Broadcast.from_plain_broadcast_bytes(bcast_bytes, self.payload_decryptor)
            self.broadcast_processed(b) # delegate
        except ExceptionWithResponse as ewr:
            if ewr.back_to:
                # resp back
                return handle_negitive_responce(ewr.message, back_to, ewr.resp_code)
            else:
                raise Exception('Expected the ExceptionWithResponse to have a `back_to` at this point')

        except Exception as e:
            print(e)
            raise
            pass # could not parse, perhase 'NAK' back here with the `e` as payload
        finally:
            if 'b' not in locals():
                self.process_plain_broadcast_parse_failed(bcast_bytes) # delegate



        try:
            return self.process_payload_from_broadcast(b)
        except DecodingError as dce:
            return handle_negitive_responce(dce, b.frm, RespCode.PRSER)
            logging.warning('Decoding Error when trying to process the payload of %s. %s' % [str(b), dce])
        except ExceptionWithResponse as ewr:
            return handle_negitive_responce(ewr.message, b.to, ewr.resp_code)
            return
        except NotToMeException:
            logging.info('not to me (caught), forwarding along. %s' % str(b))
            # TODO forward along route
            return





    def process_payload_from_broadcast(self, b:Broadcast) -> TransmittableBroadcast:
        """Takes a parsed broadcast and does approproate thing.

        Such things include:
        - Running actions
        - Constructing and sending responces to requested properties
        - Handleing responces
        - Updating cache based on RESP and ANNC objects
        """

        if not self.broadcast_is_to_this_node(b):
            raise NotToMeException()


        if b.kind == 'REQ':

            # Check and return properties
            resp_payload_obj = {}
            OK_resp = True

            def set_prop_in_resp(property_name:str):

                prop = self.property_named(property_name, ensure_public=True)

                if prop:
                    resp_payload_obj[prop.name] = prop.value
                else:
                    resp_payload_obj[property_name] = '\x15'

            # Check and run actions
            for action_name, args in b.payload.request_actions.items():
                action = self.action_named(action_name)

                if action:

                    ret = None

                    try:
                        action.validate_args(*args)
                    except ArgumentValidationError as message:
                        OK_resp = False
                        resp_payload_obj['^'+action_name] = '\x15' + str(message)
                    else:
                        # Finally run the action
                        ret = action.run(*args)

                    if type(ret) == tuple: # if extra properties dict to respond with
                        for prop_name in ret[1]:
                            set_prop_in_resp(prop_name)

                        # set ret to actual return value for further processing
                        ret = ret[0]

                    if ret != None: # if action to return somthing, set it in dict
                        resp_payload_obj['^'+action.name] = ret

                else:
                    resp_payload_obj['^'+action_name] = '\x15'


            # check and build properties in payload (props after running actions)
            for req_prop_name in b.payload.request_prop_names:
                set_prop_in_resp(req_prop_name)

            # prepare and transmit responce to request
            if resp_payload_obj:
                if b.annc_result:
                    resp_bcast = Broadcast.ANNC(self.network_addr, to=b.annc_result)
                else:
                    resp_code = b'OK' if OK_resp else b'NAK' # may replace nak with meh

                    resp_bcast = Broadcast.RESP(b.frm, self.network_addr, resp_code)

                resp_bcast.payload.resp_annc_obj = resp_payload_obj

                return self.make_transmittable_broadcast(resp_bcast)
            else:
                return self.make_transmittable_broadcast(  # ACK back if nothing to respond with
                    Broadcast.RESP(b.frm, self.network_addr, b'ACK')
                )

        elif b.kind == 'ANNC':

            if isinstance(b.payload.resp_annc_obj, BaseNode):
                # the payload is the node struct of the sender ('frm')
                self.cached_nodes[b.frm] = b.payload.resp_annc_obj

            elif type(b.payload.resp_annc_obj) is dict:

                self.update_cached_properties(b.frm, b.payload.resp_annc_obj)

            else:
                raise ExceptionWithResponse(RespCode.PRSER, 'ANNC payload not correct structure.', b.frm)

            return

        elif b.kind == 'RESP':

            # print('recived RESP [%s] payload:' % str(b.resp_code), b.payload.resp_annc_obj)

            if b.resp_code == b'OK' and type(b.payload.resp_annc_obj) is dict:
                self.update_cached_properties(b.frm, b.payload.resp_annc_obj)
                # no 'ACK' if needed, nothing to do specifically

            elif b.resp_code in [RespCode.BDSIG, RespCode.PRSER, RespCode.DENID, RespCode.NAK, RespCode.NUKER]:
                # TODO deal with negative response codes
                pass



            # Process dispatched requests, their callbacks, and timeouts
            # Alternative to using threads that autodelete themselves

            to_be_removed_requests = []
            for r in self.dispatched_requests:

                if r.to == b.frm:
                    r.call_callback(b)
                    to_be_removed_requests.append(r)

                if r.timeout_time < time():
                    r.timeout_callback()
                    to_be_removed_requests.append(r)


            # clear up the self.dispatched_requests array
            for done_r in to_be_removed_requests:
                self.dispatched_requests.remove(done_r)

            return


    def make_transmittable_broadcast(self, broadcast:Broadcast) -> TransmittableBroadcast:
        """Takes a Broadcast object and makes a TransmittableBroadcast object
            which includes the broadcast encoded, encyted, and ready to transmit.
        """

        encrypted = self.crypto.sign_and_encrypt_with_network_key(
                                                    broadcast.encode('0.1', self.payload_encryptor))

        # x01x01 means: version 1, normal broadcast
        return TransmittableBroadcast(b'\x01\x01' + struct.pack('!H', len(encrypted)) + encrypted,
                                      broadcast)



    def do_transmission(self, data:bytes, to):
        """Implement the actual transmission of data."""

        raise NotImplementedError('`do_transmission(data)` must be implemented; it is what actually sends data.')




    def handle_discover_broadcast_data(self, raw_data:bytes) -> TransmittableBroadcast:

        def transmit_discovery_proccess_error(type_:str, message:str=''):
            if type_ not in ['SIG', 'PRSE', 'MSG']:
                logging.warning('In preparing to transmit a marco-polo error, but had invalid type:%s'%type_)
                return

            disc_error = b'\x00\x01|DER-%s|%s' % (str(type_, 'utf-8'), m_encode(message))

            logging.info('To transmit marco-polo error: ' + str(disc_error))

            return TransmittableBroadcast(disc_error, None) # FIXME this None could be bad or okay



        #TODO the user/authority concept is important somewhere in here and needs to be implemented

        raw_data = raw_data[4:] # remove the version, discovery handle byte, and 2 byte length

        disc_bcast = raw_data[64+3:]


        if disc_bcast.startswith(b'MARCO'):
            logging.info('recivced a MARCO')

            if self.crypto.network_secret_box == None: # interested in joining

                other_addr_end = disc_bcast.find(b'|',7)

                other_addr = disc_bcast[6:other_addr_end]

                other_verify_key = disc_bcast[other_addr_end+1:other_addr_end+33] # TODO may rename to include the word users
                other_public_key = disc_bcast[other_addr_end+34:]

                try:
                    self.crypto.verify_signed_bytes(raw_data, other_verify_key)
                except nacl_BadSignatureError as bse:
                    logging.error('Bad signature in recived MARCO.' + str(bse))

                    return transmit_discovery_proccess_error('SIG', 'Recived MARCO, could not verify signature.')

                polo_plain = b'\x00\x01|POLO|%(from)s|%(self_pub_key)s|%(encoded_and_encrypted_self_node)s' % {
                    b'from':other_addr, # the node is encoded then encryted
                    b'self_pub_key': self.crypto.private_key.public_key.encode(),
                    b'encoded_and_encrypted_self_node': self.crypto.encrypt_to_public_key(m_encode(self), other_public_key)
                }

                #sign and transmit polo_plain

                signed_polo = self.crypto.signing_key.sign(polo_plain)

                return TransmittableBroadcast(b'\x01\x05' + struct.pack('!H', len(signed_polo)) + signed_polo,
                                                                        Broadcast('POLO', self.network_addr, other_addr))

            else:
                pass # TODO ignore if part of a network, but forward

        elif disc_bcast.startswith(b'POLO'):
            logging.info('recivced a POLO')

            to_addr, frm_pub_key_and_node_struct = disc_bcast[5:].split(b'|', 1)
            frm_pub_key = frm_pub_key_and_node_struct[:32]
            en_node_struct = frm_pub_key_and_node_struct[33:]

            if to_addr == self.network_addr: # i.e. if user/authority getting polo after marco

                node_struct = self.crypto.decrypt_from_public_key(en_node_struct, frm_pub_key)

                new_node = m_decode(node_struct) # TODO catch decoding Error then aise ExceptionWithResponse

                try:
                    self.crypto.verify_signed_bytes(raw_data, new_node.node_info['kVerify'])
                except nacl_BadSignatureError:
                    logging.error('Bad POLO signature')
                    return transmit_discovery_proccess_error('SIG', 'Recived POLO, could not verify signature.')
                else:
                    pass
                    # TODO check the address can be derived



                # TODO here is where the user determins wether to accept the node or not

                signed_new_struct = self.crypto.signing_key.sign(node_struct) # TODO temp, sign with user key
                encoded_payload = m_encode(
                        [self.crypto.network_secret_box.secret_key, self, signed_new_struct]
                    )

                acpt_plain = b'\x00\x01|ACPT|%(new_node_addr)s|%(self_pub_key)s|%(encrypted_encoded_payload)s' % {
                    b'new_node_addr': new_node.network_addr,
                    b'self_pub_key': self.crypto.private_key.public_key.encode(),
                    b'encrypted_encoded_payload': self.crypto.encrypt_to_public_key(encoded_payload, frm_pub_key)
                }

                signed_acpt = self.crypto.signing_key.sign(acpt_plain)

                self.cached_nodes[new_node.network_addr] = new_node  # TODO this, but when a node is not chached but has the net key (for all other nodes in network to learn about the new node on first bootstrap ANNC)

                return TransmittableBroadcast(b'\x01\x05'+ struct.pack('!H', len(signed_acpt)) + signed_acpt,
                                             Broadcast('ACPT', self.network_addr, new_node.network_addr)
                )

            else:
                pass # forward on


        elif disc_bcast.startswith(b'ACPT'):
            logging.info('recivced a ACPT')

            to_addr, rest_of_acpt = disc_bcast[5:].split(b'|', 1) #


            if to_addr == self.network_addr:

                discoverer_public_key = rest_of_acpt[:32]
                encrypted_payload = rest_of_acpt[33:]

                payload = self.crypto.decrypt_from_public_key(encrypted_payload, discoverer_public_key)

                payload_list = m_decode(payload)  # TODO catch decoding Error then raise some kind of ExceptionWithResponse

                bootstrap_node = payload_list[1]

                try:
                    self.crypto.verify_signed_bytes(raw_data, bootstrap_node.node_info['kVerify'])
                except nacl_BadSignatureError:
                    logging.error('Bad ACPT signature')
                    return transmit_discovery_proccess_error('SIG', 'Recived ACPT, could not verify signature.')
                else:
                    pass
                    # TODO check the address can be derived



                # Assuming all is good, add self to network, and bootstrape node to cache:

                self.crypto.set_network_key(payload_list[0])

                self.cached_nodes[bootstrap_node.network_addr] = bootstrap_node

                user_signed_self_struct = payload_list[2]
                aqua_plain = b'\x00\x01|AQUA|%s' %  user_signed_self_struct

                aqua_en = self.crypto.sign_and_encrypt_with_network_key(aqua_plain)

                return TransmittableBroadcast(b'\x01\x05' + struct.pack('!H', len(aqua_en)) + aqua_en,
                                                Broadcast('AQUA', self.network_addr, b'*')
                )
            else:
                pass # forward on




        elif disc_bcast.startswith(b'DER-'):
            pass # TODO something here, even a delegate callback maybe


        else: # TODO may want to try/catch VvV
            if self.crypto.decrypt_from_network(raw_data)[64+3:].startswith(b'AQUA'):
                logging.info(b'recivced a AQUA')

                signed_payload = self.crypto.decrypt_from_network(raw_data)[64+3+5:]
                # payload  = TODO use user key to verify, if good, m_decode and add to known nodes



        # can't match, ignore
        return


    def start_MarcoPolo(self):
        marco = b'\x00\x01|MARCO|%s|%s|%s' % (
            self.network_addr,
            self.crypto.signing_key.verify_key.encode(), # TODO these should be user keys, from user/authority
            self.crypto.private_key.public_key.encode()
        )



        try:
            packet_payload = self.crypto.signing_key.sign(marco)
            self.do_transmission(b'\x01\x05'+ struct.pack('!H', len(packet_payload)) + packet_payload, b'*') # TODO, ^^ also sigend by user/authority
            # x05 is the discovery mark

        except TransmissionError as te:
            logging.error('Error transmitting MARCO. ' + str(te))



    def save_node_volatile_data_to_file(self, filename=None):
        if not filename:
            filename='node%s.save' % self.network_addr

        prop_vals = {p.name:p.value for p in self.properties.values()}

        out = { 'propvals': prop_vals, # stores the property names with its value, # IDEA later, no current support of last change meta
                'nodeinfo': self.node_info,
                'groups': {
                    'gen': list(self.joined_groups),
                    'sec': self.joined_secure_groups },
                'cryto': self.crypto.get_save_key_dict(),
                'cached_nodes': self.cached_nodes
                # TODO known nodes routes, neabhors, etc
              }

        try:
            with open(filename+'.tmp', 'bw') as f:
                f.seek(0)
                f.write(m_encode(out))
        except Exception:
            return False

        file_rename(filename+'.tmp', filename)

        return True




    def load_node_volatile_data_from_file(self, filename='node.save'):

        try:
            with open(filename, 'br') as f:
                in_ = m_decode(f.read())
        except FileNotFoundError:
            return False # if no file just ignore, to assume there is no save.


        propvals = in_['propvals']

        # set property values from save
        for prop_name in propvals:
            p = self.property_named(prop_name)
            if p:
                p.value = propvals[prop_name]

        # node info update, ensure saved info overwritten by code defined.

        saved_node_info = in_.get('nodeinfo', {})
        # saved_node_info.update(self.node_info)
        self._node_info = saved_node_info

        self.crypto.load_keys_from_save_dict(in_['cryto'])

        # load joined groups
        self.joined_groups = set(in_.get('groups', {}).get('gen', []))
        self.joined_secure_groups = in_.get('groups', {}).get('sec', {})

        self.cached_nodes =in_.get('cached_nodes', {})

        return True



    ## Broacast Delegate-like Signals - node subclass implemntation optional ##

    def process_plain_broadcast_parse_failed(self, bcast_bytes:bytes):
        """If the parsing fails, the network decryted bytes will be passed here."""
        pass

    def did_receive_plain_broadcast(self, b:bytes):
        """Called as soon a first layer of network encyption is removed, no other processing."""
        pass

    def broadcast_processed(self, broadcast:Broadcast):
        """Called once a plain broadcast is parsed."""
        pass
