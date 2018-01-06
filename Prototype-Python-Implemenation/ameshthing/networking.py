import asyncio
from socket import gethostname, gethostbyname

from .node import Node


def get_host_ip() -> str:
    """The ip address of the computer on its LAN"""
    return gethostbyname(gethostname())

class TCPNode(Node):
    """Adds TCP tranmission functionality, as a listener and sender for peer-to-peer.

    >>> class MyNode(TCPNode):
            def __init__(self):
                self.start_tcp()

    >>> try: asyncio.get_event_loop().run_forever() # starts listening and sending loop
    """

    LISTEN_PORT = 7770

    def __init__(self):
        super().__init__()

        self.my_tcp_node_routes = {} # TODO load from save # {node_addr:writer object}

    def start_tcp(self, host=None):
        if not host:
            host = get_host_ip()

        print('Starting tcp on %s:%i' % (host, self.LISTEN_PORT))

        self.loop = asyncio.get_event_loop() # uses asyncio tcp stream
        coro = asyncio.start_server(self.server_handle, host, self.LISTEN_PORT, loop=self.loop)

        self.server = self.loop.run_until_complete(coro)

        self.host = host

        # self.loop.run_forever()

    def send_data_to(self, data:bytes, remote_host, remote_port=LISTEN_PORT):
        # self.loop.run_until_complete(self.client_do(data, remote_host, remote_port))

        # This is contrived, but is the only way i can get it to work
        self.loop.call_soon_threadsafe(lambda:self.loop.create_task(self.client_do(data, remote_host, remote_port)))



    @asyncio.coroutine
    def client_do(self, data, remote_host, remote_port=LISTEN_PORT):
        reader, writer = yield from asyncio.open_connection(remote_host, remote_port,
                                                            loop=self.loop,)
                                                            # local_addr=(self.host, self.CLIENT_PORT))


        writer.write(data)


        data = yield from reader.read(65536)
        self.live_print('Received back: %r' % data)

        trctb = self.transmission_received_callback(data)
        if trctb:
            self.send_data_to(trctb.data, remote_host, remote_port)

        writer.close()

    @asyncio.coroutine
    def server_handle(self, reader, writer):
        data = yield from reader.read(65536)
        addr, port = writer.get_extra_info('peername')

        self.live_print("Received %r \nfrom %r:%i" % (data, addr,port))
        # print("Received %r \nfrom %r:%i" % (data, addr,port))

        trctb = self.transmission_received_callback(data)

        print('TRCTB?:', trctb)

        if trctb != None:
            pass # do stuff with it  (i.e. possibly send back)
            writer.write(trctb.data)
        # else:
        #     writer.write(b'')

        yield from writer.drain()

        # writer.close()
        print('saving writer for addr: ', trctb.broadcast.to)
        self.my_tcp_node_routes[trctb.broadcast.to] = writer



    def stop_tcp(self):
        self.server.close()
        self.loop.run_until_complete(self.server.wait_closed())

    # overridden -- required
    def do_transmission(self, data:bytes, to):
        # TODO figure out what ip it goes to

        print('tcp do transmition, to:', to)

        if to in self.my_tcp_node_routes:
            print('using old writer')
            n_writer = self.my_tcp_node_routes[to]
            writer.write(data)
            # yield from writer.drain()
        else:
            print('no known writter, making new')
            rhost = '127.0.0.1'
            rport = 7770

            self.send_data_to(data, rhost, rport)

    def live_print(self, message):
        """Optionaly overridden to get log messages showing the network functioning."""
        pass










# class PeerTCP():
#     """Uses a listening socket and dynamic clients to use p2p TCP.
#
#     Basic usage:
#     >>> import asyncio
#     >>> p = PeerTCP('127.0.0.1')
#     >>> p.send_data_to(b'data', 'example.com', port=7770)  # default port
#     >>> try: asyncio.get_event_loop().run_forever()  # does first send, and starts listener
#     >>> p.send_data_to(b'more data', 'example.com', port=7770)  # works fine
#     """
#
#     LISTEN_PORT = 7770 # where the server listens
#     # CLIENT_PORT = 7771 # where a peer writes from when not a server responce
#
#
#     def __init__(self, host=None):
#         if not host:
#             host = get_host_ip()
#
#         self.loop = asyncio.get_event_loop() # uses asyncio tcp stream
#         coro = asyncio.start_server(self.server_handle, host, self.LISTEN_PORT, loop=self.loop)
#
#         self.server = self.loop.run_until_complete(coro)
#
#         self.host = host
#
#     @staticmethod
#     def get_host_ip():
#         """The ip address of the computer on its LAN"""
#         return get_host_ip()
#
#
#     def send_data_to(self, data:bytes, host, port=LISTEN_PORT):
#         # self.loop.run_until_complete(self.client_do(data, host, port))
#         asyncio.ensure_future(self.client_do(data, host, port))
#
#
#
#     @asyncio.coroutine
#     def server_handle(self, reader, writer):
#         data = yield from reader.read(100)
#         message = data
#         addr = writer.get_extra_info('peername')
#         print("Received %r from %r" % (message, addr))
#
#         writer.write(data)
#         yield from writer.drain()
#
#         writer.close()
#
#
#
#
#     @asyncio.coroutine
#     def client_do(self, data, host, port=LISTEN_PORT):
#         reader, writer = yield from asyncio.open_connection(host, port,
#                                                             loop=self.loop,)
#                                                             # local_addr=(self.host, self.CLIENT_PORT))
#
#
#         writer.write(data)
#
#
#         data = yield from reader.read(100)
#         print('Received: %r' % data)
#
#         writer.close()
#
#
#
#     def close(self):
#         self.server.close()
#         self.loop.run_until_complete(self.server.wait_closed())
#         # self.loop.close()
