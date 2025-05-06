import hmac
import hashlib
import struct

class Finished:
    def __init__(self, verify_data):
        self.verify_data = verify_data

    def to_bytes(self):
        return b'\x07' + struct.pack('!H', len(self.verify_data)) + self.verify_data

    @classmethod
    def from_bytes(cls, data):
        if data[0] != 0x07:
            raise ValueError("Invalid Finished message")
        length = struct.unpack('!H', data[1:3])[0]
        verify_data = data[3:3+length]
        return cls(verify_data)

def compute_verify_data(handshake_bytes, session_key):
    return hmac.new(session_key, handshake_bytes, hashlib.sha256).digest()
