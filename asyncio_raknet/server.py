import asyncio

from asyncio_raknet.packets import *
from asyncio_raknet.protocol import Protocol


class Server(asyncio.DatagramProtocol, asyncio.AbstractServer):
    def __init__(self, conn_callback):
        self.conn_callback = conn_callback
        self.transport = None
        self.protocols = {}
        self.close_future = asyncio.get_event_loop().create_future()

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, exc):
        self.close_future.set_result(None)

    def datagram_received(self, data, addr):
        protocol = self.protocols.get(addr)
        if protocol is None:
            if magic not in data:
                return
            protocol = Protocol()
            transport = ServerTransport(self, protocol, addr)
            protocol.connection_made(transport)
            self.protocols[addr] = protocol
            asyncio.Task(self.conn_callback(protocol))
        protocol.datagram_received(data)

    def close(self):
        self.transport.close()

    def is_serving(self):
        return not self.transport.is_closing()

    async def start_serving(self):
        pass

    async def serve_forever(self):
        await self.wait_closed()

    async def wait_closed(self):
        await self.close_future


class ServerTransport(asyncio.DatagramTransport):
    def __init__(self, server, protocol, addr):
        super().__init__()
        self.server = server
        self.protocol = protocol
        self.addr = addr
        self.closed = False

    def get_extra_info(self, name, default=None):
        if name == 'peername':
            return self.addr
        return self.server.transport.get_extra_info(name, default)

    def is_closing(self):
        return self.closed

    def close(self):
        if not self.closed:
            self.closed = True
            self.protocol.connection_lost(None)
            del self.server.protocols[self.addr]

    def sendto(self, data, addr=None):
        self.server.transport.sendto(data, self.addr)

    def abort(self):
        self.close()


async def create_server(conn_callback, host, port, **kwargs):
    local_addr = (host, port)
    loop = asyncio.get_event_loop()
    server = Server(conn_callback)
    await loop.create_datagram_endpoint(lambda: server, local_addr=local_addr, **kwargs)
    return server


async def listen(host, port, status_callback, login_callback, **kwargs):

    async def handler(protocol):
        packet = await protocol.read()
        if type(packet) in (UnconnectedPing, UnconnectedPingOpenConnections):
            status = await status_callback(protocol)
            protocol.write(UnconnectedPong(
                guid=protocol.guid,
                remote_time=packet.local_time,
                status=status))
            protocol.tick()
            protocol.transport.close()
            return

        assert type(packet) is OpenConnectionRequest1
        protocol.mtu = packet.mtu
        protocol.version = packet.version
        protocol.write(OpenConnectionReply1(
            guid=protocol.guid,
            mtu=protocol.mtu,
            security=False))

        packet = await protocol.read()
        assert type(packet) is OpenConnectionRequest2
        protocol.mtu = packet.mtu
        protocol.write(OpenConnectionReply2(
            guid=protocol.guid,
            mtu=protocol.mtu,
            remote_address=protocol.remote_address,
            encryption=False))

        packet = await protocol.read()
        assert type(packet) is ConnectionRequest
        protocol.online = True
        protocol.write(ConnectionRequestAccepted(
            remote_time=packet.local_time,
            local_time=0,
            remote_address=protocol.remote_address,
            internal_addresses=[Address.empty() for _ in range(10)],
            system_idx=0))

        await login_callback(protocol)

    server = await create_server(handler, host, port, **kwargs)
    return server
