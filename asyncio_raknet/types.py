import os
import socket
import struct

magic = b'\x00\xff\xff\x00' \
        b'\xfe\xfe\xfe\xfe' \
        b'\xfd\xfd\xfd\xfd' \
        b'\x12\x34\x56\x78'


class Underrun(Exception):
    pass


def unpack_bytes(buff, n):
    data = buff.read(n)
    if len(data) < n:
        raise Underrun()
    return data


def unpack_bool(buff):
    return unpack_bytes(buff, 1) == b'\x01'


def pack_bool(val):
    return bytes([int(val)])


def unpack_uint8(buff):
    return unpack_bytes(buff, 1)[0]


def pack_uint8(val):
    return bytes([val])


def unpack_uint16(buff):
    return struct.unpack('>H', unpack_bytes(buff, 2))[0]


def pack_uint16(val):
    return struct.pack('>H', val)


def unpack_uint24le(buff):
    data = unpack_bytes(buff, 3)
    return data[0] + (data[1] << 8) + (data[2] << 16)


def pack_uint24le(val):
    return bytes([0xFF & val, 0xFF & (val >> 8), 0xFF & (val >> 16)])


def unpack_uint32(buff):
    return struct.unpack('>I', unpack_bytes(buff, 4))[0]


def pack_uint32(val):
    return struct.pack('>I', val)


def unpack_uint64(buff):
    return struct.unpack('>Q', unpack_bytes(buff, 8))[0]


def pack_uint64(val):
    return struct.pack('>Q', val)


class Serializable(object):
    @classmethod
    def unpack(cls, buff):
        raise NotImplementedError

    def pack(self):
        raise NotImplementedError


class GUID(Serializable):
    def __init__(self, value):
        self.value = value

    @classmethod
    def random(cls):
        return cls(os.urandom(8))

    @classmethod
    def unpack(cls, buff):
        return cls(unpack_bytes(buff, 8))

    def pack(self):
        return self.value


class Address(Serializable):
    def __init__(self, family, host, port):
        self.family = family
        self.host = host
        self.port = port

    def __repr__(self):
        return "Address(%r, %r, %r)" % (self.family, self.host, self.port)

    @classmethod
    def empty(cls):
        return cls(socket.AF_INET, '255.255.255.255', 0)

    @classmethod
    def unpack(cls, buff):
        version = unpack_uint8(buff)
        assert version in (4, 6)
        if version == 4:
            family = socket.AF_INET
            host = socket.inet_ntop(family, unpack_bytes(buff, 4))
            port = unpack_uint16(buff)
        else:
            family = socket.AF_INET6
            unpack_bytes(buff, 2)
            port = unpack_uint16(buff)
            unpack_bytes(buff, 4)
            host = socket.inet_ntop(family, unpack_bytes(buff, 16))
            unpack_bytes(buff, 4)
        return cls(family, host, port)

    def pack(self):
        if self.family == socket.AF_INET:
            return b'\x04' + \
                   socket.inet_pton(socket.AF_INET, self.host) + \
                   pack_uint16(self.port)
        else:
            return b'\x06\x17\x00' + \
                   pack_uint16(self.port) + \
                   b'\x00\x00\x00\x00' + \
                   socket.inet_pton(socket.AF_INET6, self.host) + \
                   b'\x00\x00\x00\x00'
