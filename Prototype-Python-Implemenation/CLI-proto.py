import threading
import asyncio

import logging
logging.basicConfig(
    # level=logging.DEBUG,
    format="\n%(levelname)s:%(name)s:%(message)s",
    # datefmt="%H:%M:%S",
    # stream=sys.stdout
    )

try:
    import readline
except: print('`readline` not found, cli history will not work.')

if 'libedit' in readline.__doc__:
    readline.parse_and_bind("bind -e")
    readline.parse_and_bind("bind '\t' rl_complete")
else:
    readline.parse_and_bind("tab: complete")

from ameshthing.node import Node
from ameshthing.constructs import Property, Action, ActionParameter
from ameshthing.types import types

from ameshthing.broadcast import Broadcast

from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey, PublicKey
from nacl.encoding import Base32Encoder

from ameshthing.networking import TCPNode

class Lamp(TCPNode):

    def __init__(self):
        super().__init__()

        self.crypto.create_dual_keys()

        self.add_property(Property('on', types.bool))
        self.property_named('on').value = False
        # self.add_action(Action('turnOn', self.turn_on, None,types.null))

        ssp = self.add_property(Property('some_str', types.string))
        ssp.value = 'Hello'

        ssp.meta = {'desc':'a string for testing encoding'}

        on_act_param = ActionParameter('on', types.bool)
        some_foo_param = ActionParameter('foo', types.string)
        self.add_action(
            Action('setState', self.set_on_state, [on_act_param, some_foo_param], types.null)
        )

        self.node_info['capabilities'] = ['www', 'ip']

        self.start_tcp('127.0.0.1')


    def set_on_state(self, req_state, foo=0):
        print('setting lamp state to: %s' % str(req_state))
        self.property_named('on').value = req_state

    def do_transmission(self, data, to):
        print('TODO lamp transmission implementation')


other = Lamp() # just some other node

# other.crypto.set_network_key(b'testkey!'*4)

class CLI_Node(TCPNode):

    do_live_listen = False

    def __init__(self):
        super().__init__()
        self.crypto.create_dual_keys()
        self.node_info['nick'] = 'CLI Python'

        # self.cached_nodes[other.network_addr] = other

        self.auth_signing_key = None  # authority's keys for 'private' network
        self.auth_private_key = None

        # TODO try loading keys from save else:
        self.auth_signing_key = SigningKey.generate()
        self.auth_private_key = PrivateKey.generate()

        self.start_tcp()

    def do_transmission(self, data:bytes, to):
        TCPNode.do_transmission(self, data, to)

        # other.transmission_received_callback(data)

    # Override
    def live_print(self, message):
        if self.do_live_listen:
            print('\n->', message, end='\n% ')


help_string = """\
 help
 list
 detail [addr] ('all')
 do [addr|group] [action name] [params as python list]
 marco (ip) (port)
 listenlive
 authkeys ('private')
 """

class CLI(threading.Thread):

    def __init__(self):
        super().__init__()
        self.daemon = True
        self.focused_addr = None

        self.node = CLI_Node()

        readline.set_completer(self.completer)

    def run(self): # Thread start and do input loop
        print('^C to exit\n')

        while True:
            cmd = input('% ')
            self.process_command(cmd)

    def completer(self, text, state):
        options = ['help', 'list', 'detail', 'do', 'listenlive', 'authkeys']
        if state == 0:
            if text:
                self.matches = [s for s in options
                                if s and s.startswith(text)]
            else:
                self.matches = options[:]


        origline = readline.get_line_buffer()

        if origline.startswith('authkeys '):
            self.matches = ['private']

        # Address completion
        if origline.startswith('detail '):
            self.matches = [str(n.network_addr, 'utf-8') for n in self.node.cached_nodes.values()
                                                        if str(n.network_addr, 'utf-8').startswith(text)][:20]

        if origline.startswith('do '):
            self.matches = [str(n.network_addr, 'utf-8') for n in self.node.cached_nodes.values()
                                                        if str(n.network_addr, 'utf-8').startswith(text)][:20]
            if not text:
                self.matches.append('*')

        # return if can
        try:
            return self.matches[state]
        except IndexError:
            return None

    def process_command(self, cmd:str):

        if cmd.lower().startswith('help'):
            print(help_string, end='')

        elif cmd == 'list':
            self.focused_addr = None

            if len(self.node.cached_nodes) == 0:
                print(' No known nodes.')
            else:
                print(' {:^10} | {:^10} | {:^20}'.format('addr', 'nick', 'groups'))
                print('-'*45)
                for n in self.node.cached_nodes.values():
                    # groups_list = list(n.joined_groups) + list(n.joined_secure_groups.keys())
                    groups_list = list(n.node_info.get('*', []) +  n.node_info.get('#', []))

                    print(' {:10} | {:10.10} | {:20}'.format(str(n.network_addr, 'utf-8'),
                                                            n.node_info.get('nick', ' '),
                                                             ','.join(groups_list)
                                                            ))

        elif cmd.startswith('detail'):
            # prints: addr, props/vals, actions, meta, pubkeys, & groups

            cmd = cmd.split(' ')
            if len(cmd) >= 2:
                addr = cmd[1]
                self.focused_addr = addr

                show_all = False
                if len(cmd) == 3:
                    if cmd[2] == 'all': show_all = True # verbose


                det_node = self.node.cached_nodes.get(addr.encode('utf-8'), None)

                if det_node:

                    print('\033[1m''Detail: %s\033[0m' % det_node.network_addr.decode('utf-8'))

                    # Properties
                    if det_node.properties:
                        print('\nProperties:')
                        for prop in det_node.properties.values():
                            print(' %-s:%-s = %-30s' % (prop.name, prop.type_T.name, str(prop.value)))
                            print('    %s' % str(prop.meta))
                    else:
                        print('No properties')

                    # Actions
                    if det_node.actions:
                        print('\nActions:')
                        for act in det_node.actions.values():
                            print(' ^%s->%s' % (act.name, act.return_type.name))

                            for param in act.action_parameters:
                                print('  $%-s:%-s' % (param.name, param.type_T.name))
                                print('    %-s\n' % str(param.meta), end='')

                                # maybe some last run/call info too
                    else:
                        print('No actions')


                    # Node Info

                    print('\nGroups:')
                    # groups_list = list(det_node.joined_groups) + list(det_node.joined_secure_groups.keys())
                    groups_list = list(det_node.node_info.get('*', []) +  det_node.node_info.get('#', []))

                    if groups_list:
                        print('  ', ', '.join(groups_list))
                    else:
                        print('  No joined groups.')


                    print('\nNode info:')

                    print(' Verify key:', det_node.node_info['kVerify'])
                    print(' Public key:', det_node.node_info['kPublic'])
                    print(' Capabilities:' , ', '.join(det_node.node_info['capabilities']) or 'None')

                    if show_all:
                        print(' All Raw:')
                        print('   ', det_node.node_info)

                else:
                    print('Unknown node with address', addr)

            else:
                print('Expected address to show info on.')

        elif cmd.startswith('do'):
            cmd_parts = cmd.split(' ', 2)
            if len(cmd_parts) == 3:
                addr = cmd_parts[1] # _can_ be a group and *
                action_raw = cmd_parts[2]

                action_name, params = action_raw.split(' ', 1)

                if not action_name.startswith('^'):
                    action_name = '^' + action_name

                try:
                    py_params = eval(params, {}, {}) # convert user input to py variables in list
                except SyntaxError:
                    print('Synax Error, write the params as a python list.')
                else:
                    # TODO checking params before sending would be good

                    b = Broadcast.REQ(addr.encode('utf-8'), self.node.network_addr)
                    b.payload.request_actions[action_name] = py_params


                    tbcast = self.node.make_transmittable_broadcast(b)
                    self.node.do_transmission(tbcast.data, tbcast.broadcast.to)

            else:
                print('Expected addres and action.')

        elif cmd.startswith('marco'):
            cmd_parts = cmd.split(' ')

            if len(cmd_parts) >= 2:
                host = cmd_parts[1]
                port = 7770
                if len(cmd_parts) == 3:
                    port = cmd_parts[2]


            self.node.start_MarcoPolo()




        elif cmd == 'listenlive': # allow for --all and --to-me

            self.node.do_live_listen = not self.node.do_live_listen

            if not self.node.do_live_listen:
                print('No longer printing live.')
            else:
                print('Live listening printing started.\n`listenlive` again to stop')

        elif cmd.startswith('authkeys'):
            print("This node's address: %s" % self.node.network_addr)

            print("User node's/authority public keys (base 32):")
            print(" Verify Key: %s" % self.node.auth_signing_key.verify_key.encode(encoder=Base32Encoder).decode('utf-8'))
            print(" Public Key: %s" % self.node.auth_private_key.public_key.encode(encoder=Base32Encoder).decode('utf-8'))

            show_private = cmd.split(' ')
            if len(show_private) == 2:
                if show_private[1].startswith('priv'):
                    print("User node's/authority private keys (base 32):")
                    print(" Signing Key: %s" % self.node.auth_signing_key.encode(encoder=Base32Encoder).decode('utf-8'))
                    print(" Private Key: %s" % self.node.auth_private_key.encode(encoder=Base32Encoder).decode('utf-8'))


        elif cmd == '':
            pass

        else:
            print('Unknown command.')
            # print(help_string)

        print() # always \n at end


cli = CLI()

cli.node.crypto.set_network_key(b'testkey!'*4)

other.cached_nodes[cli.node.network_addr] = cli.node


try:
    cli.start()

    asyncio.get_event_loop().run_forever()
    # while True:pass
except (KeyboardInterrupt,SystemExit):
    print('\nbye'+ chr(9995))
    cli.node.stop_tcp()
    exit(0)
