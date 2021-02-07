import asyncio

from asyncio_raknet.packets import *
from asyncio_raknet.protocol import Protocol


async def connect(host, port, **kwargs):
    loop = asyncio.get_event_loop()
    protocol = Protocol()
    await loop.create_datagram_endpoint(lambda: protocol, remote_addr=(host, port), **kwargs)
    return protocol


async def status(host, port, **kwargs):
    protocol = await connect(host, port, **kwargs)
    protocol.write(UnconnectedPing(protocol.guid, 0))
    packet = await protocol.read()
    protocol.transport.close()
    assert type(packet) is UnconnectedPong
    return packet.status


async def login(host, port, **kwargs):
    protocol = await connect(host, port, **kwargs)
    protocol.write(OpenConnectionRequest1(
        mtu=protocol.mtu,
        version=protocol.version))

    while True:
        packet = await protocol.read()
        if type(packet) is OpenConnectionReply1:
            protocol.mtu = packet.mtu
            protocol.write(OpenConnectionRequest2(
                guid=protocol.guid,
                mtu=protocol.mtu,
                remote_address=protocol.remote_address))
        elif type(packet) is OpenConnectionReply2:
            protocol.mtu = packet.mtu
            protocol.online = True
            break
        else:
            raise ValueError(packet)

    return protocol
