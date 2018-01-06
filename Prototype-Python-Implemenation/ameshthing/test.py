"""Unit tests"""

import unittest

from .node import Node
from .crypto import Crypto
from .broadcast import Broadcast
from .constructs import BaseConstruct, Property, Action, ActionParameter
from .types import types
from .util import base64_decode

import struct

from .encoding import encode, decode

from .exceptions import DecodingError, ExceptionWithResponse, ArgumentValidationError

# ChaCha Test suite too
from .chacha20.test import *

class NodeTests(unittest.TestCase):
    def setUp(self):
        self.n = Node()
        self.n.crypto.create_dual_keys()

        self.n.node_info['addr'] = b'abc'

        self.n.add_property(Property('foo', types.string))
        self.n.add_property(Property('_private', types.string))

        self.n.add_action(Action('actbar', lambda:_, None,types.null))

        # on prop and action
        self.n.add_property(Property('on', types.bool))
        def set_on_state(req_state):
            # print('req state =', req_state)
            self.n.property_named('on').value = req_state
        self.n.add_action(Action('setState', set_on_state, [ActionParameter('on', types.bool)], types.null))

    def test_getting_prop_by_ref(self):

        self.n.property_named('foo').value = 'one'

        p = self.n.property_named('foo')

        self.assertEqual(p.value, 'one')

        p.value = 'two'

        self.assertEqual(self.n.property_named('foo').value, p.value)
        self.assertEqual(self.n.property_named('foo').value, 'two')

        self.assertIsNone(self.n.property_named('non-existant'))
        self.assertIsNone(self.n.property_named('_private', ensure_public=True))

    def test_exception_bad_prop_or_action_key(self):
        self.assertIsNone(self.n.property_named('fake key not real'))
        self.assertIsNone(self.n.action_named('fake key not real'))

    def test_name_immutable(self):
        def settingNameAtAll():
            self.n.properties['foo'].name = 'bar'
        self.assertRaises(AttributeError, settingNameAtAll)

    def test_property_has_not_dict(self):
        self.assertRaises(AttributeError, lambda: self.n.properties['foo'].__dict__)

    def test_okay_name_for_base_node_thing(self):
        invalid_names = [' ', '', 'bla+bla=!']
        for bad_name in invalid_names:
            self.assertRaises(Exception, BaseConstruct, (bad_name, types.string))

    def test_process_plain_broadcast_bytes(self):

        faux_network_key = b'test' * 8

        sender = Node() # test reciver node
        sender.crypto.create_dual_keys()

        self.n.cached_nodes[sender.network_addr] = sender # add test reciver to test node
        sender.cached_nodes[self.n.network_addr] = self.n

        self.n.crypto.set_network_key(faux_network_key)
        sender.crypto.set_network_key(faux_network_key)

        b = Broadcast.REQ(self.n.network_addr, sender.network_addr, raw_payload=b'^setState(T)')
        fake_data = b.encode('0.1', sender.payload_encryptor)

        self.n.process_plain_broadcast_bytes(fake_data)

        self.assertTrue(self.n.property_named('on').value)

        b = Broadcast.REQ(self.n.network_addr, sender.network_addr, raw_payload=b'^setState(F)') # to false
        fake_data = b.encode('0.1', sender.payload_encryptor)

        self.n.process_plain_broadcast_bytes(fake_data)

        self.assertFalse(self.n.property_named('on').value)


    def test_bad_sig(self):

        faux_network_key = b'test' * 8

        sender = Node() # test reciver node
        sender.crypto.create_dual_keys()
        sender.crypto.set_network_key(faux_network_key)

        self.n.cached_nodes[sender.network_addr] = sender # add test reciver to test node
        sender.cached_nodes[self.n.network_addr] = self.n

        self.n.crypto.set_network_key(faux_network_key)

        b = Broadcast.REQ(self.n.network_addr, sender.network_addr, raw_payload=b'^setState(T)')
        fake_plain = b.encode('0.1')

        signed = sender.crypto.signing_key.sign(fake_plain)
        signed = b'\x00\x01\x02\x04' + signed[4:] # make it invalid

        encrypted = sender.crypto.network_secret_box.encrypt(signed, b'testnonc')

        self.n.transmission_received_callback(b'\x01\x01' + struct.pack('!H', len(encrypted)) + encrypted)

    def test_to_groups_broacast_encoding_via_node(self):
        self.n.joined_secure_groups[b'#asecgroup'] = b'\x7c' * 32

        b = Broadcast.REQ(b'*somegroup', b'zyx', raw_payload=b'foo')
        fake_data = b.encode('0.1', self.n.payload_encryptor)

        b = Broadcast.REQ(b'#asecgroup', b'zyx', raw_payload=b'foo')
        fake_data = b.encode('0.1', self.n.payload_encryptor)


    def test_action_params_never_none(self):
        self.assertListEqual(self.n.action_named('actbar').action_parameters, [],
                    'An action parameter must not be None. (Only empty)')

    def test_action_no_callback_exception(self):
        a = Action('turnOn')
        self.assertRaises(TypeError, a.run, ())


    def test_discovery_functionality(self):

        starter = Node()
        starter.crypto.set_network_key(b'test'*8)
        starter.crypto.create_dual_keys()

        tobe = Node()
        tobe.crypto.create_dual_keys()

        def starter_dotrans(data, _):
            disc_resp = tobe.transmission_received_callback(data)

            disc_back = starter.transmission_received_callback(disc_resp.data)

            if disc_back:
                starter.do_transmission(disc_back.data, '')


        starter.do_transmission = starter_dotrans

        starter.start_MarcoPolo()

        self.assertIsNotNone(tobe.cached_nodes.get(starter.network_addr, None), msg='ToBe did not add starter node to cache')
        self.assertIsNotNone(starter.cached_nodes.get(tobe.network_addr, None), msg='ToBe is not in starter cache')

        self.assertIsNotNone(tobe.crypto.network_secret_box, msg='ToBe did not set network secret key')

        # TODO add final assert for adding new node when user verification stuff is implemented



class CryptoTests(unittest.TestCase):

    def test_dict_create_and_load_dict(self):
        c = Crypto()

        c.network_secret_box = ChaChaBox(b'\x7c' * 32)

        c.create_dual_keys()

        save = c.get_save_key_dict()

        c.load_keys_from_save_dict(save)

    def test_generate_public_address(self):
        c = Crypto()
        c.create_dual_keys()
        c.public_address


    def test_network_level_symmetric_cases(self):
        c = Crypto()
        c.create_dual_keys()
        c.network_secret_box = ChaChaBox(b'\x44'*32) # fake symmettric

        test_message = b'TestingTesting\x00\x01\x02!'

        en = c.sign_and_encrypt_with_network_key(test_message)

        de_signed = c.decrypt_from_network(en)
        de = c.verify_signed_bytes(de_signed, c.signing_key.verify_key.encode())

        self.assertEqual(de, test_message)

    def test_standard_symmetric_functions(self):

        test_key = b'\x4a' * 32
        test_message = b'TestingTesting\x00\x01\x02!'

        en = Crypto.encrypt_symmetrically(test_message, test_key)

        de = Crypto.decrypt_symmetrically(en, test_key)




class ConstructsTests(unittest.TestCase):

    def test_action_validation(self):
        on_act_param = ActionParameter('on', types.bool)
        some_foo_param = ActionParameter('foo', types.string)

        a = Action('acter', lambda _:_, [on_act_param, some_foo_param])

        # test normal, should work, no errors
        a.validate_args(True, 'some string')

        # test none ignoring
        a.validate_args(True, None)

        args = ('not bool', 123)
        self.assertRaises(ArgumentValidationError, a.validate_args, *args)


class UtilTests(unittest.TestCase):

    def test_base64_decode(self):
        encoded = b'V2h5IGhlbGxvIHRoZXJlIQ=='
        encoded_bad_pad = b'V2h5IGhlbGxvIHRoZXJlIQ'

        self.assertEqual(base64_decode(encoded), b'Why hello there!')
        self.assertEqual(base64_decode(encoded_bad_pad), b'Why hello there!')


class BroadcastTests(unittest.TestCase):

    def setUp(self):
        self.req = Broadcast.REQ(b'abc', b'zyx', raw_payload=b'^turnOn()n')
        self.annc = Broadcast.ANNC(b'abc', to=b'*', raw_payload=b's6:foobar')
        self.resp = Broadcast.RESP(b'abc', b'zyx', b'OK', raw_payload=b's6:foobar')


    def test_broadcast_encoding(self):
        self.assertEqual(self.req.encode('0.1')[6:], b'|REQ|abc|zyx|XnR1cm5Pbigpbg==|\x00')
        self.assertEqual(self.annc.encode('0.1')[6:], b'|ANNC|*|abc|czY6Zm9vYmFy')
        self.assertEqual(self.resp.encode('0.1')[6:], b'|RESP|abc|zyx|OK|czY6Zm9vYmFy')

    def test_group_helper_functions(self):
        """Tests for checking the `to` for general, secure groups or all(*)."""

        b = self.req = Broadcast.ANNC('abc', to=b'*', raw_payload=b's6:foobar')

        self.assertTrue(b.is_to_all())

        b.to = b'fake-address'
        self.assertTrue(b.is_to_only_one())
        self.assertFalse(b.is_to_all())
        self.assertFalse(b.to_secure_group())
        self.assertFalse(b.to_gen_group())


        b.to = b'*gen-group'
        self.assertFalse(b.is_to_all())
        self.assertEqual(b.to_gen_group(), b'*gen-group')
        self.assertFalse(b.to_secure_group())
        self.assertFalse(b.is_to_only_one())

        b.to = b'#sec-group'
        self.assertEqual(b.to_secure_group(), b'#sec-group')
        b.to = b'#'
        self.assertFalse(b.to_secure_group())
        self.assertFalse(b.to_gen_group())
        self.assertFalse(b.is_to_only_one())



    def test_parse_req_payload(self):
        """Tests the seperation of actions and params from a raw payload."""

        test_payload = b'fooprop,^zargact(),^unargact(i42;),somerandplaceprop,^severlargact(s3:barf4.2;)'

        r = Broadcast.REQ(b'abc', b'zyx', raw_payload=test_payload)

        self.assertEqual(r.payload.request_actions, {'zargact': [], 'unargact': [42], 'severlargact': ['bar', 4.2]})
        self.assertEqual(r.payload.request_prop_names, ['fooprop', 'somerandplaceprop'])

    def test_parse_error_resp_raise(self):

        req = Broadcast.REQ(b'abc', b'zyx', raw_payload=b'^turnOn)')
        self.assertRaises(ExceptionWithResponse, req.payload.to_requested_things)

        annc = Broadcast.ANNC(b'abc', b'zyx', raw_payload=b'di42;')
        self.assertRaises(DecodingError, lambda : annc.payload.resp_annc_obj)

        resp = Broadcast.RESP(b'abc', b'zyx', b'OK', raw_payload=b'node>')
        self.assertRaises(DecodingError, lambda: resp.payload.resp_annc_obj)


class EncodingTests(unittest.TestCase):

    def test_encodings_basic_types(self):
        self.assertEqual(encode('Hello world!'), b's12:Hello world!')
        self.assertEqual(encode('Emoji=🌡'), b's10:Emoji=\xf0\x9f\x8c\xa1')

        self.assertEqual(encode(42), b'i42;')
        self.assertEqual(encode(9999999), b'i9999999;')
        self.assertEqual(encode(25.972372), b'f25.972372;')

        self.assertEqual(encode(True), b'T')
        self.assertEqual(encode(False), b'F')
        self.assertEqual(encode(None), b'\x00')

        self.assertEqual(encode([1,2,3]), b'li1;i2;i3;;')
        self.assertEqual(encode([1,2,True]), b'li1;i2;T;')

        self.assertEqual(encode({'a':1,'b':2}), b'ds1:ai1;s1:bi2;;')
        self.assertEqual(encode({'a':{'c':[{'d':99}]},'b':'o'}), b'ds1:ads1:clds1:di99;;;;s1:bs1:o;')

    def test_encodings_mesh_structures(self):
        a1 = Action('turnOn', lambda:_, None,types.null)

        self.assertEqual(encode(a1), b'^turnOn()n;')

        on_act_param = ActionParameter('on', types.bool)
        some_foo_param = ActionParameter('foo', types.string)
        a2 = Action('setState', lambda:_, [on_act_param, some_foo_param], types.null)

        self.assertEqual(encode(a2), b'^setState($on|b|d;;$foo|s|d;;)n;')

        p1 = Property('some_str', types.string)
        p1.value = 'Hello'
        p1.meta = {'desc':'a string for testing encoding', 'nesting-test':[{}]}

        self.assertEqual(encode(p1), b'psome_str|s|s5:Hello|ds4:descs29:a string for testing encodings12:nesting-testld;;;;')

        n1 = Node()
        n1.node_info = {'ni-test':'bla bla'}
        n1.crypto.create_dual_keys()

        n1.add_action(a2)
        n1.add_property(p1)


        if not encode(n1).startswith(b'node<psome_str|s|s5:Hello|ds4:descs29:a string for testing encodings12:nesting-testld;;;;|^setState($on|b|d;;$foo|s|d;;)n;|'):
            raise AssertionError(b'Node encoding (excluding node info) is not correct. Got:\n' + encode(n1))


    def test_decodings_basic_types(self):
        self.assertEqual(decode(b's12:Hello world!'), 'Hello world!')
        self.assertEqual(decode(b's10:Emoji=\xf0\x9f\x8c\xa1'), 'Emoji=🌡')

        self.assertEqual(decode(b'i42;'), 42)
        self.assertEqual(decode(b'i999999;'), 999999)

        self.assertEqual(decode(b'f4.2;'), 4.2)
        self.assertEqual(decode(b'f123.987;'), 123.987)

        self.assertEqual(decode(b'T'), True)
        self.assertEqual(decode(b'F'), False)
        self.assertEqual(decode(b'\x00'), None)

        self.assertEqual(decode(b'li1;i2;i3;;'), [1,2,3])

        self.assertEqual(decode(b'ds1:ads1:clds1:di99;;;;s1:bs1:o;'), {'a':{'c':[{'d':99}]},'b':'o'})


    def test_decodings_mesh_structures(self):

        a1_d = decode(b'^turnOn()n;')

        self.assertEqual(a1_d.name, 'turnOn')
        self.assertEqual(a1_d.return_type, types.null)
        self.assertEqual(a1_d.action_parameters, [])


        a2_d = decode(b'^setState($on|b|d;;$foo|s|d;;)n;')

        self.assertEqual(a2_d.name, 'setState')
        self.assertEqual(a2_d.action_parameters[0].name, 'on')
        self.assertEqual(a2_d.action_parameters[0].type_T, types.bool)
        self.assertEqual(a2_d.action_parameters[0].meta, {})

        self.assertEqual(a2_d.action_parameters[1].name, 'foo')
        self.assertEqual(a2_d.action_parameters[1].type_T, types.string)
        self.assertEqual(a2_d.action_parameters[1].meta, {})

        p1_d = decode(b'psome_str|s|s5:Hello|ds4:descs29:a string for testing encodings12:nesting-testld;;;;')

        self.assertEqual(p1_d.name, 'some_str')
        self.assertEqual(p1_d.type_T, types.string)
        self.assertEqual(p1_d.value, 'Hello')
        self.assertEqual(p1_d.meta, {'desc':'a string for testing encoding','nesting-test':[{}]})

        n1_d = decode(b'node<psome_str|s|s5:Hello|ds4:descs29:a string for testing encodings12:nesting-testld;;;;|^setState($on|b|d;;$foo|s|d;;)n;|ds7:ni-tests7:bla bla;>')

        self.assertEqual(len(n1_d.properties), 1)
        self.assertEqual(len(n1_d.actions), 1)

        self.assertEqual(n1_d.property_named('some_str').value, 'Hello')

        self.assertEqual(n1_d.node_info, {'ni-test': 'bla bla'})


    def test_decoding_errors_basic_types(self):

        self.assertRaises(DecodingError, decode, (b'i'))
        self.assertRaises(DecodingError, decode, (b'i7'))
        self.assertRaises(DecodingError, decode, (b'i4.2'))

        self.assertRaises(DecodingError, decode, (b'f'))
        self.assertRaises(DecodingError, decode, (b'f7'))
        self.assertRaises(DecodingError, decode, (b'f4.2'))

        self.assertRaises(DecodingError, decode, (b'l'))
        self.assertRaises(DecodingError, decode, (b'li1;i2;i3;'))

        self.assertRaises(DecodingError, decode, (b'd'))
        self.assertRaises(DecodingError, decode, (b'di1;i2;'))

        # bad type (x)
        self.assertRaises(DecodingError, decode, (b'psome_str|x|s5:Hello|\x00'))

    def test_decoding_errors_mesh_structures(self):

        # Action
        self.assertRaises(DecodingError, decode, (b'^test($foo|s|\x00;n')) # no end pren
        self.assertRaises(DecodingError, decode, (b'^test($foo|s|\x00;)')) # no return type

        # Node
        # error in props
        self.assertRaises(DecodingError, decode, (b'node<psome_str|s|s5:NotRightLen|\x00;|^setState($on|b|d;;$foo|s|\x00;)n;|d;>'))
        # error in actions
        self.assertRaises(DecodingError, decode, (b'node<psome_str|s|s5:Hello|\x00;|^setState($on|xx|d;;$foo|s|\x00;)n;|d;>'))
        # error in node info dict
        self.assertRaises(DecodingError, decode, (b'node<psome_str|s|s5:Hello|\x00;|^setState($on|b|d;;$foo|s|\x00;)n;|d>'))



    def test_depth_limit(self):

        deep_list_str = b'l' * 201 + b'i42;' + b';' * 201
        self.assertRaises(RecursionError, decode, (deep_list_str))

        deep_dict_str = b'ds1:V' * 201 + b'i42;' + b';' * 201
        self.assertRaises(RecursionError, decode, (deep_dict_str))


if __name__ == '__main__':
    unittest.main()
