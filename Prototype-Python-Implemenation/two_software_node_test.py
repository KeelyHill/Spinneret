
from ameshthing.node import Node
from ameshthing.constructs import Property, Action, ActionParameter

from ameshthing.types import types

from ameshthing.broadcast import Broadcast


import nacl.utils

import logging
logging.getLogger().setLevel(logging.INFO)






other = Lamp() # just some other node


class Human(Node):

    def __init__(self, faux_other_node):
        super().__init__()

        self.faux_other_node = faux_other_node

        name = self.add_property(Property('name', types.string))
        name.value = "Keely"
        name.meta = {'desc': 'the name of the human'}

        # for now instead of saving and loading
        self.crypto.create_dual_keys()


    def do_transmission(self, data:bytes, to):
        print('>*>*>user sending: '+str(data) +'\n')
        # other.transmission_received_callback(data)
        self.faux_other_node.transmission_received_callback(data)


class CeilFan(Node):

    def __init__(self, faux_other_node):
        super().__init__()

        self.faux_other_node = faux_other_node

        self.light_on = self.add_property(Property('lightOn', types.bool))
        self.light_on.value = False

        set_on_param = ActionParameter('on', types.bool)
        self.add_action(
            Action('setLightState', self.set_light_state, [set_on_param], types.null)
        )

        # for now instead of saving and loading
        self.crypto.create_dual_keys()


    def set_light_state(self, state):
        self.light_on.value = state
        logging.info("light state set to: " + str(state))
        return (None, ['lightOn'])


    def do_transmission(self, data:bytes, to):
        print('>*>*> fan sending: '+str(data) +'\n')
        other.transmission_received_callback(data)
        self.faux_other_node.transmission_received_callback(data)


network_key = nacl.utils.random(32)

other.crypto.create_dual_keys()
other.crypto.set_network_key(network_key)


human = None # to pass in then set
fan = CeilFan(human)

human = Human(fan)
fan.faux_other_node = human

fan.crypto.set_network_key(network_key)
human.crypto.set_network_key(network_key)

# do 'discovery' manually for now
human.cached_nodes[fan.crypto.public_address] = fan
fan.cached_nodes[human.crypto.public_address] = human


#
# testB = Broadcast.REQ(fan.crypto.public_address, human.crypto.public_address)
# # testB.payload.request_prop_names = ['lightOn']
# testB.payload.request_actions['^setLightState'] = [True]
#
# human.transmit_broadcast(testB, lambda b:print('aoooo ha', b))



print('\n--\n')

fan.crypto.network_secret_box = None


# disc = b'\x00\x01|MARCO|%s|%s|%s' % (human.network_addr,
#                                     human.crypto.signing_key.verify_key.encode(),
#                                     human.crypto.private_key.public_key.encode())
#

human.start_MarcoPolo()
