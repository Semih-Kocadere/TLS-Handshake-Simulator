from cryptography.hazmat.primitives import serialization
import struct
class ServerKeyExchange:
    def __init__(self, public_key_bytes):
        self.public_key_bytes = public_key_bytes

    def to_bytes(self):
        length = len(self.public_key_bytes)
        return b'\x04' + struct.pack('!H', length) + self.public_key_bytes

    @classmethod
    def from_bytes(cls, data):
        if data[0] != 0x04:
            raise ValueError("Not a ServerKeyExchange message.")
        length = struct.unpack('!H', data[1:3])[0]
        pubkey_bytes = data[3:3+length]
        return cls(pubkey_bytes)
