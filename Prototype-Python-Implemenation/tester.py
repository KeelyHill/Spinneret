# -*- coding: utf-8 -*-

# Not for unit tests, but testing implementation.


from ameshthing.encoding import decode, encode

from ameshthing.node import Node

from ameshthing.broadcast import Broadcast

from ameshthing.constructs import Property, Action, ActionParameter
from ameshthing.types import types




class Lamp(Node):

    def __init__(self):
        super().__init__()

        # self.load_node_volatile_data_from_file()

        # self.crypto.create_dual_keys()

        self.add_property(Property('on', types.bool))
        self.add_action(Action('turnOn', self.turn_on, None,types.null))

        ssp = self.add_property(Property('some_str', types.string))
        ssp.value = 'Hello'

        ssp.meta = {'desc':'a string for testing encoding', 'inside':[{}]}

        on_act_param = ActionParameter('on', types.bool)
        some_foo_param = ActionParameter('foo', types.string)
        self.add_action(
            Action('setState', self.set_on_state, [on_act_param, some_foo_param], types.null)
        )

        # must load volitile data prior to setting node info
        self.load_node_volatile_data_from_file()

        self.node_info['protocolVersion'] = '0.1'
        self.node_info['netAddress'] = b'lampaddr'

        self.validate_node_info()


    def my_save(self):
        self.save_node_volatile_data_to_file()

    def turn_on(self):
        self.property_named('on').value = True
        print('Turned on!')
        self.my_save()


    def set_on_state(self, req_state, foo=0):
        print('setting lamp state to: %s' % str(req_state))
        self.property_named('on').value = req_state
        self.my_save()


    def fake_process_plain_broadcast(self, data):
        self.process_plain_broadcast_bytes(data)




    def do_transmission(self, data, to): # overridden correctly
        print('lamp out: ', data)
        user_in_fake(data)
        pass


l = Lamp()



user = Node()
user.crypto.create_dual_keys()

def user_in_fake(data):
    # print('user in: ', data)
    print('user net dec', user.crypto.decrypt_from_network(data))
    #print(user.crypto.network_secret_box)

l.cached_nodes[b'user'] = user


l.joined_secure_groups[b'#abc'] = b'\x55' * 32 #test key

l.joined_groups.add(b'*abc')

b = Broadcast.REQ(b'*abc', b'user')
b.payload.request_actions['^setState'] = [True, 'foo']

fake_data = b.encode(version_str='0.1')


l.process_plain_broadcast_bytes(fake_data)


print('-')

b = Broadcast.REQ(b'*abc', b'user', annc_result='fake')
b.payload.request_prop_names = ['on']

fake_data = b.encode(version_str='0.1')

l.fake_process_plain_broadcast(fake_data)




print('\n--')

l.joined_secure_groups[b'#abc'] = b'\x55' * 32 #test key

b = Broadcast.RESP(b'#abc', b'user', b'OK')
b.payload.raw_bytes = b's3:bar'

#l.fake_process_plain_broadcast(l.prepare_broadcast(b))




print('\n---')


import logging

logging.warning('Test')  # will print a message to the console
logging.info('Test I told you so')  # will not print anything
