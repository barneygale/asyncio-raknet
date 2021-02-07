from asyncio_raknet.types import *

"""
x   00 CONNECTED_PING
x   01 UNCONNECTED_PING
x   02 UNCONNECTED_PING_OPEN_CONNECTIONS
x   03 CONNECTED_PONG
    04 DETECT_LOST_CONNECTIONS
x   05 OPEN_CONNECTION_REQUEST_1
x   06 OPEN_CONNECTION_REPLY_1
x   07 OPEN_CONNECTION_REQUEST_2
x   08 OPEN_CONNECTION_REPLY_2
x   09 CONNECTION_REQUEST
    0a REMOTE_SYSTEM_REQUIRES_PUBLIC_KEY
    0b OUR_SYSTEM_REQUIRES_SECURITY
    0c PUBLIC_KEY_MISMATCH
    0d OUT_OF_BAND_INTERNAL
    0e SND_RECEIPT_ACKED
    0f SND_RECEIPT_LOSS
x   10 CONNECTION_REQUEST_ACCEPTED
    11 CONNECTION_ATTEMPT_FAILED
    12 ALREADY_CONNECTED
x   13 NEW_INCOMING_CONNECTION
    14 NO_FREE_INCOMING_CONNECTIONS
x   15 DISCONNECTION_NOTIFICATION
    16 CONNECTION_LOST
    17 CONNECTION_BANNED
    18 INVALID_PASSWORD
x   19 INCOMPATIBLE_PROTOCOL_VERSION
    1a IP_RECENTLY_CONNECTED
    1b TIMESTAMP
    1c UNCONNECTED_PONG
    1d ADVERTISE_SYSTEM
    1e DOWNLOAD_PROGRESS
"""


# Receipt, Reliable, Sequenced, Ordered
reliability_types = [
    (0, 0, 0, 0),  # 0: Unreliable
    (0, 0, 1, 1),  # 1: Unreliable Sequenced
    (0, 1, 0, 0),  # 2: Reliable
    (0, 1, 0, 1),  # 3: Reliable Ordered
    (0, 1, 1, 1),  # 4: Reliable Sequenced
    (1, 0, 0, 0),  # 5: Receipt + Unreliable
    (1, 1, 0, 0),  # 6: Receipt + Reliable
    (1, 1, 1, 1),  # 7: Receipt + Reliable Sequenced
]


packet_types = {}


def packet_type(cls):
    packet_types[cls.ident] = cls
    return cls


@packet_type
class ConnectedPing(Serializable):
    ident = 0x00

    def __init__(self, local_time):
        self.local_time = local_time

    @classmethod
    def unpack(cls, buff):
        assert unpack_uint8(buff) == cls.ident
        return cls(unpack_uint64(buff))

    def pack(self):
        return pack_uint8(self.ident) + pack_uint64(self.local_time)


@packet_type
class UnconnectedPing(Serializable):
    ident = 0x01

    def __init__(self, guid, local_time):
        self.guid = guid
        self.local_time = local_time

    @classmethod
    def unpack(cls, buff):
        assert unpack_uint8(buff) == cls.ident
        local_time = unpack_uint64(buff)
        assert buff.read(16) == magic
        guid = GUID.unpack(buff)
        return cls(guid, local_time)

    def pack(self):
        return pack_uint8(self.ident) + pack_uint64(self.local_time) + magic + self.guid.pack()


@packet_type
class UnconnectedPingOpenConnections(UnconnectedPing):
    ident = 0x02


@packet_type
class ConnectedPong(Serializable):
    ident = 0x03

    def __init__(self, remote_time, local_time):
        self.remote_time = remote_time
        self.local_time = local_time

    @classmethod
    def unpack(cls, buff):
        assert unpack_uint8(buff) == cls.ident
        remote_time = unpack_uint64(buff)
        local_time = unpack_uint64(buff)
        return cls(remote_time, local_time)

    def pack(self):
        return pack_uint8(self.ident) + \
               pack_uint64(self.remote_time) + \
               pack_uint64(self.local_time)


@packet_type
class OpenConnectionRequest1(Serializable):
    ident = 0x05

    def __init__(self, mtu, version):
        self.mtu = mtu
        self.version = version

    @classmethod
    def unpack(cls, buff):
        assert unpack_uint8(buff) == cls.ident
        assert buff.read(16) == magic
        version = unpack_uint8(buff)
        mtu = len(buff.read()) + 46
        return cls(mtu, version)

    def pack(self):
        return pack_uint8(self.ident) + magic + pack_uint8(self.version) + b'\x00' * (self.mtu - 46)


@packet_type
class OpenConnectionReply1(Serializable):
    ident = 0x06

    def __init__(self, guid, mtu, security):
        self.guid = guid
        self.mtu = mtu
        self.security = security

    @classmethod
    def unpack(cls, buff):
        assert unpack_uint8(buff) == cls.ident
        assert buff.read(16) == magic
        guid = GUID.unpack(buff)
        security = unpack_bool(buff)
        mtu = unpack_uint16(buff)
        return cls(guid, mtu, security)

    def pack(self):
        return pack_uint8(self.ident) + magic + self.guid.pack() + \
               pack_bool(self.security) + pack_uint16(self.mtu)


@packet_type
class OpenConnectionRequest2(Serializable):
    ident = 0x07

    def __init__(self, guid, mtu, remote_address):
        self.guid = guid
        self.mtu = mtu
        self.remote_address = remote_address

    @classmethod
    def unpack(cls, buff):
        assert unpack_uint8(buff) == cls.ident
        assert buff.read(16) == magic
        remote_address = Address.unpack(buff)
        mtu = unpack_uint16(buff)
        guid = GUID.unpack(buff)
        return cls(guid, mtu, remote_address)

    def pack(self):
        return pack_uint8(self.ident) + magic + self.remote_address.pack() + \
               pack_uint16(self.mtu) + self.guid.pack()


@packet_type
class OpenConnectionReply2(Serializable):
    ident = 0x08

    def __init__(self, guid, mtu, remote_address, encryption):
        self.guid = guid
        self.mtu = mtu
        self.remote_address = remote_address
        self.encryption = encryption

    @classmethod
    def unpack(cls, buff):
        assert unpack_uint8(buff) == cls.ident
        assert buff.read(16) == magic
        guid = GUID.unpack(buff)
        remote_address = Address.unpack(buff)
        mtu = unpack_uint16(buff)
        encryption = unpack_bool(buff)
        return cls(guid, mtu, remote_address, encryption)

    def pack(self):
        return pack_uint8(self.ident) + magic + self.guid.pack() + \
               self.remote_address.pack() + pack_uint16(self.mtu) + pack_bool(self.encryption)


@packet_type
class ConnectionRequest(Serializable):
    ident = 0x09

    def __init__(self, guid, local_time, security):
        self.guid = guid
        self.local_time = local_time
        self.security = security

    @classmethod
    def unpack(cls, buff):
        assert unpack_uint8(buff) == cls.ident
        guid = GUID.unpack(buff)
        local_time = unpack_uint64(buff)
        security = unpack_bool(buff)
        return cls(guid, local_time, security)

    def pack(self):
        return pack_uint8(self.ident) + self.guid.pack() + \
               pack_uint64(self.local_time) + pack_bool(self.security)


@packet_type
class ConnectionRequestAccepted(Serializable):
    ident = 0x10

    def __init__(self, remote_time, local_time, remote_address, internal_addresses, system_idx):
        self.remote_time = remote_time
        self.local_time = local_time
        self.remote_address = remote_address
        self.internal_addresses = internal_addresses
        self.system_idx = system_idx

    @classmethod
    def unpack(cls, buff):
        assert unpack_uint8(buff) == cls.ident
        remote_address = Address.unpack(buff)
        system_idx = unpack_uint16(buff)
        internal_addresses = [Address.unpack(buff) for _ in range(20)]
        remote_time = unpack_uint64(buff)
        local_time = unpack_uint64(buff)
        return cls(remote_time, local_time, remote_address, internal_addresses, system_idx)

    def pack(self):
        return pack_uint8(self.ident) + self.remote_address.pack() + pack_uint16(self.system_idx) + \
               b''.join(address.pack() for address in self.internal_addresses) + \
               pack_uint64(self.remote_time) + pack_uint64(self.local_time)


@packet_type
class NewIncomingConnection(Serializable):
    ident = 0x13

    def __init__(self, remote_address, internal_addresses):
        self.remote_address = remote_address
        self.internal_addresses = internal_addresses

    @classmethod
    def unpack(cls, buff):
        assert unpack_uint8(buff) == cls.ident
        remote_address = Address.unpack(buff)
        internal_addresses = [Address.unpack(buff) for _ in range(10)]
        return cls(remote_address, internal_addresses)
    
    def pack(self):
        return pack_uint8(self.ident) + self.remote_address.pack() + \
               b"".join(address.pack() for address in self.internal_addresses)


@packet_type
class DisconnectionNotification(Serializable):
    ident = 0x15

    @classmethod
    def unpack(cls, buff):
        return cls()

    def pack(self):
        return b''


@packet_type
class IncompatibleProtocolVersion(Serializable):
    ident = 0x19

    def __init__(self, guid, version):
        self.guid = guid
        self.version = version

    @classmethod
    def unpack(cls, buff):
        assert unpack_uint8(buff) == cls.ident
        version = unpack_uint8(buff)
        assert buff.read(16) == magic
        guid = GUID.unpack(buff)
        return cls(guid, version)

    def pack(self):
        return pack_uint8(self.ident) + pack_uint8(self.version) + \
               magic + self.guid.pack()


@packet_type
class UnconnectedPong(Serializable):
    ident = 0x1c

    def __init__(self, guid, remote_time, status):
        self.guid = guid
        self.remote_time = remote_time
        self.status = status

    @classmethod
    def unpack(cls, buff):
        assert unpack_uint8(buff) == cls.ident
        remote_time = unpack_uint64(buff)
        guid = GUID.unpack(buff)
        assert buff.read(16) == magic
        length = unpack_uint16(buff)
        status = buff.read(length)
        return cls(guid, remote_time, status)

    def pack(self):
        return pack_uint8(self.ident) + \
               pack_uint64(self.remote_time) + \
               self.guid.pack() + \
               magic + \
               pack_uint16(len(self.status)) + \
               self.status


@packet_type
class Game(Serializable):
    ident = 0xfe

    def __init__(self, payload):
        self.payload = payload

    @classmethod
    def unpack(cls, buff):
        return cls(buff.read())

    def pack(self):
        return self.payload


@packet_type
class ACK(Serializable):
    ident = 0xc0

    def __init__(self, indices):
        self.indices = indices

    @classmethod
    def unpack(cls, buff):
        assert unpack_uint8(buff) == cls.ident
        indices = []
        for _ in range(unpack_uint16(buff)):
            single = unpack_bool(buff)
            if single:
                indices.append(unpack_uint24le(buff))
            else:
                indices.extend(range(unpack_uint24le(buff),
                                     unpack_uint24le(buff)))
        return cls(indices)

    def pack(self):
        entries = []
        for idx in self.indices:
            if not entries or entries[-1][-1] != (idx - 1):
                entries.append([])
            entries[-1].append(idx)

        out = pack_uint8(self.ident)
        out += pack_uint16(len(entries))
        for entry in entries:
            out += pack_bool(len(entry) == 1)
            out += pack_uint24le(entry[0])
            if len(entry) != 1:
                out += pack_uint24le(entry[-1])
        return out


@packet_type
class NACK(ACK):
    ident = 0xa0


@packet_type
class FrameSet(Serializable):
    ident = 0x88

    def __init__(self, idx, frames):
        self.idx = idx
        self.frames = frames

    def pack(self):
        out = b'\x88' + pack_uint24le(self.idx)
        for frame in self.frames:
            out += frame.pack()
        return out

    @classmethod
    def unpack(cls, buff):
        unpack_uint8(buff)
        idx = unpack_uint24le(buff)
        frames = []
        while True:
            try:
                frames.append(Frame.unpack(buff))
            except Underrun:
                break
        return cls(idx, frames)


class Frame(Serializable):
    def __init__(self, payload, reliable_idx=None, order_idx=None,
                 fragment_idx=None, fragment_count=None, fragment_chan=None):
        self.payload = payload
        self.reliable_idx = reliable_idx
        self.order_idx = order_idx
        self.fragment_idx = fragment_idx
        self.fragment_chan = fragment_chan
        self.fragment_count = fragment_count

    @property
    def reliable(self):
        return self.reliable_idx is not None

    @property
    def ordered(self):
        return self.order_idx is not None

    @property
    def fragmented(self):
        return self.fragment_idx is not None

    @classmethod
    def from_fragments(cls, fragments):
        return cls(
            payload=b"".join(fragment.payload for fragment in fragments),
            reliable_idx=fragments[0].reliable_idx,
            order_idx=fragments[0].order_idx)

    @classmethod
    def unpack(cls, buff):
        flags = unpack_uint8(buff)
        length = unpack_uint16(buff) >> 3

        # Load flags
        receipt, reliable, sequenced, ordered = reliability_types[flags >> 5]
        fragmented = flags & (1 << 4)
        assert not sequenced
        assert not receipt

        # Load optional fields
        reliable_idx = None
        order_idx = None
        fragment_idx = None
        fragment_chan = None
        fragment_count = None
        if reliable:
            reliable_idx = unpack_uint24le(buff)
        if ordered:
            order_idx = unpack_uint24le(buff)
            order_chan = unpack_uint8(buff)
            assert order_chan == 0
        if fragmented:
            fragment_count = unpack_uint32(buff)
            fragment_chan = unpack_uint16(buff)
            fragment_idx = unpack_uint32(buff)

        # Load payload
        payload = buff.read(length)

        return cls(payload, reliable_idx, order_idx, fragment_idx, fragment_count, fragment_chan)

    def pack(self):
        flags = 0
        flags |= reliability_types.index((0, self.reliable, 0, self.ordered)) << 5
        flags |= int(self.fragmented) << 4
        data = bytes([flags])
        data += pack_uint16(8 * len(self.payload))
        if self.reliable:
            data += pack_uint24le(self.reliable_idx)
        if self.ordered:
            data += pack_uint24le(self.order_idx)
            data += b'\x00'  # channel
        if self.fragmented:
            data += pack_uint32(self.fragment_count)
            data += pack_uint16(self.fragment_chan)
            data += pack_uint32(self.fragment_idx)
        data += self.payload
        return data
