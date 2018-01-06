from .util import base64_decode, base64_encode
from .encoding import encode as m_encode
from .encoding import decode as m_decode

from .exceptions import ExceptionWithResponse, DecodingError

from nacl.utils import random  as nacl_random


class RespCode():
    # IDEA make values shorter, even int/byte

    ACK = b'ACK' # 10
    OK = b'OK' # 11

    BDSIG = b'BDSIG' # bad signature 20
    PRSER = b'PRSER' # parse error 21
    DENID = b'DENID' # denied 22

    NAK = b'NAK' # 30
    NUKER = b'NUKER' # 31

    codes = [ACK, OK, BDSIG, PRSER, DENID, NAK, NUKER]

    # ?? 'Unknown node address, unable to verify.'

    # human friendly helpers ?
    # BADSIG = BDSIG
    # PRARSEERROR = PRSER
    # DENIED = DENID

class TransmittableBroadcast:
    """A struct containing the ready to go `data` bytes and its assosiated `broadcast` object"""

    __slots__ = 'data', 'broadcast'

    def __init__(self, raw_data:bytes, assosiated_broadcast):
        self.data = raw_data
        self.broadcast = assosiated_broadcast

# class DiscoveryTransmittableBroadcast(TransmittableBroadcast):
#     def __init__(self, raw_data:bytes):
#         self.data = raw_data
#         self.broadcast = None

class Payload():

    def __init__(self, raw_bytes=None):

        self.raw_bytes = raw_bytes

        # filled up if kind == REQ
        self.__request_prop_names = None # []
        self.__request_actions = None # {} # {name:[params list],...}

        self.__resp_annc_obj = None # {} use with RESP and ANNC to make payload


    @property
    def request_prop_names(self):
        if self.__request_prop_names == None:
            self.to_requested_things()
        return self.__request_prop_names

    @request_prop_names.setter
    def request_prop_names(self, val):
        self.__request_prop_names = val


    @property
    def request_actions(self):
        if self.__request_actions == None:
            self.to_requested_things()
        return self.__request_actions

    @request_actions.setter
    def request_actions(self, val):
        self.__request_actions = val


    @property
    def resp_annc_obj(self):
        """The object contained in the payload of a resp or annc broadcast.
        Decodes payload there is one, will raise DecodingError if can't decode;
        returns None if there is no raw_payload
        """

        if self.__resp_annc_obj == None:
            if self.raw_bytes != None:
                self.__resp_annc_obj = m_decode(self.raw_bytes)


        return self.__resp_annc_obj

    @resp_annc_obj.setter
    def resp_annc_obj(self, val):
        self.__resp_annc_obj = val




    def to_requested_things(self):
        """Parses through the payload data for a request broadcast and parses
        into the properties and actions that the request is requesting.

        Property names go into the `self.request_prop_names` array.

        Actions (with args) go the `self.request_actions` dict where
        the value is and array of the requested arguments.
        """

        if self.__request_prop_names == None:
            self.__request_prop_names = []

        if self.__request_actions == None:
            self.__request_actions = {}

        if self.raw_bytes == None: # no payload to process, keep vars as empty
            return None

        data = self.raw_bytes

        while data != b'':
            if data[0] == ord('^'): # action
                name_end = data.find(b'(')
                args_end = data.find(b')')

                if name_end == -1 or args_end == -1:
                    raise ExceptionWithResponse(RespCode.PRSER, 'Expected start of action arguments.')
                if args_end == -1:
                    raise ExceptionWithResponse(RespCode.PRSER, 'Expected end of action arguments.')


                name = data[1:name_end].decode('utf-8')
                args_list = m_decode(b'l%s;' % data[name_end+1:args_end]) # fake a list for easy decoding

                self.__request_actions[name] = args_list # add

                data = data[args_end+2:]

            else: # property
                name_end = data.find(b',') # anther act/prop or end of data(-1)
                if name_end == -1:
                    name_end = len(data) # ensures full name and proper ending

                name = data[:name_end].decode('utf-8')

                self.__request_prop_names.append(name) # add

                data = data[name_end+1:]



        return (self.request_prop_names, self.request_actions)


class Broadcast():

    def __init__(self, kind, frm, to, annc_result=None, resp_code=None, raw_payload=None):
        """Represents, decodes, and encodes the various kinds of broadcasts.

        :kind: kind of broadcast (e.g. 'REQ')
        :frm: from node
        :to: destination node, group or all ('*')
        :annc_result: applicable for 'REQ' only --
            if the reciver node should announce the result of the request.
        :resp_code: applicable for 'RESP' only,
            use of RespCode.xxx recomended (RespCode.ACK)
        :raw_payload: write a custom broadcast payload (NOT recommended), when encoding
            a broadcast, it will not get overriten. Somewhat usefull for unittests.

        """

        if kind not in ['REQ', 'ANNC', 'RESP'] + ['MARCO', 'POLO', 'ACPT', 'AQUA']:
            raise ValueError('Invalid broadcast type.')


        if kind == 'REQ':
            pass # nothing required (yet?)

        if kind == 'ANNC':
            pass # nothing required (yet?)

        if kind == 'RESP':
            if resp_code not in RespCode.codes:
                raise ValueError("'%s' not a valid response code." % resp_code)

        self.kind = kind
        self.frm = frm
        self.payload = Payload(raw_payload)
        self.to = to

        self.annc_result = annc_result
        self.resp_code = resp_code


    def __repr__(self):
        return "<Broadcast kind='%s'>" % (self.kind)


    @classmethod
    def REQ(cls, to, frm, raw_payload=None, annc_result=None):
        return cls('REQ', frm=frm, to=to, annc_result=annc_result, raw_payload=raw_payload)

    @classmethod
    def ANNC(cls, frm, to=b'*', raw_payload=None):
        return cls('ANNC', frm=frm, to=to, raw_payload=raw_payload)

    @classmethod
    def RESP(cls, to, frm, resp_code, raw_payload=None):
        return cls('RESP', frm=frm, to=to, resp_code=resp_code, raw_payload=raw_payload)


    def is_to_all(self):
        """If the broadcast is to all nodes. (i.e. where 'to'=='*')"""
        return self.to == b'*'

    def to_secure_group(self):
        """The group the broadcast is addressed to (False if not a group)"""
        if self.to.startswith(b'#') and len(self.to) > 1:
            return self.to
        else:
            return False

    def to_gen_group(self): # includes 'all' ('*')
        if self.to[0:1] == b'*' and len(self.to) >= 1:
            return self.to
        return False

    def is_to_only_one(self):
        # return not (self.is_to_all() or self.to_secure_group or self.to_gen_group)

        return not (self.to.startswith(b'#') or self.to.startswith(b'*'))


    def encode(self, version_str='0.1', payload_encryptor=lambda b,pyld: base64_encode(pyld)): #feels like HACK, may remove defaults
        """Creates a raw broadcast byte string.

        :version_str: version being used in form: ('#.#')

        :payload_encryptor: callback to a function (such as in a node) that
            takes the broadcast and constructed payload (without encryption)
            and encrypts the _payload_(not broadcast) as necessary; the result
            (with encrption or not) must be base 64 encoded.
        """

        if version_str not in ['0.1']:
            raise ValueError('Invalid version: %s' % version_str)

        pre_payload = self.payload.raw_bytes

        if self.kind == 'REQ' and pre_payload== None:
            props_encoded = [p.encode('utf-8') for p in self.payload.request_prop_names]

            actions_encoded = []
            for action_name, args in self.payload.request_actions.items():
                args_join_encoded = b''.join([m_encode(arg) for arg in args])

                encoded_action = b'%s(%s)' % (
                    action_name.encode('utf-8'), args_join_encoded)

                actions_encoded.append(encoded_action)

            pre_payload = b','.join(props_encoded+actions_encoded)

        if (self.kind == 'RESP' or self.kind == 'ANNC') and pre_payload == None:
            if self.payload.resp_annc_obj:
                pre_payload = m_encode(self.payload.resp_annc_obj)
            else: # else there is no payload, make null
                pre_payload = m_encode(None)




        # may be encrypted if broadcast 'to' warents it
        b64d_final_payload = payload_encryptor(self, pre_payload)

        fill = {
            b'v': bytes([int(n) for n in version_str.split('.')]),
            b'nonce': nacl_random(4),
            b'kind': self.kind.encode('utf-8'),
            b'to': self.to,
            b'frm': self.frm,
            b'payload_b64': b64d_final_payload,
            b'annc_result': self.annc_result.encode('utf-8') if self.annc_result else b'\x00',
            b'resp_code': self.resp_code or b'n'
        }

        if self.kind == 'REQ':
            template = b'%(v)s%(nonce)s|%(kind)s|%(to)s|%(frm)s|%(payload_b64)s|%(annc_result)s'
        elif self.kind == 'ANNC':
            template = b'%(v)s%(nonce)s|%(kind)s|%(to)s|%(frm)s|%(payload_b64)s'
        elif self.kind ==  'RESP':
            template = b'%(v)s%(nonce)s|%(kind)s|%(to)s|%(frm)s|%(resp_code)s|%(payload_b64)s'

        return template % fill


    @classmethod
    def from_plain_broadcast_bytes(cls, bcast:str, payload_decrypter):
        """Takes the raw network decrpyted level broadcast, returns broadcast object.
        If not to == *[group], then an extra layer of encyption still exists on the payload

        :decrypt_payload_callback: a callback from the node to decypt and b64 decode the payload
        """

        # use the first 6 bytes to get version and bcast id
        protocol_version = '.'.join([str(bcast[:2][i]) for i in range(2)])
        b_nonce_id = bcast[2:6]

        s = bcast[7:].split(b'|')

        kind = s[0]
        section_count = len(s) + 1 # plus the v/id section

        to = s[1]
        frm = s[2] #from


        def decrypt_payload(payload):
            return payload_decrypter(payload, to, frm)

        if kind == b'REQ' and section_count == 6:
            payload = decrypt_payload(s[3])
            annc_result = s[4] if s[4] != b'\x00' else None

            return cls.REQ(to, frm, payload, annc_result)

        elif kind == b'ANNC' and section_count == 5:
            payload = decrypt_payload(s[3])

            return cls.ANNC(frm, to, payload)

        elif kind == b'RESP' and section_count == 6:
            resp_code = s[3]

            payload = decrypt_payload(s[4])

            return cls.RESP(to, frm, resp_code, payload)

        else:
            error_text = 'Unable to parse broadcast of kind: %s with %i sections ' % (kind, section_count)
            raise ExceptionWithResponse(RespCode.NAK, error_text, frm)
