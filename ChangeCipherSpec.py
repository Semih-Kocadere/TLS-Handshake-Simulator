import struct
class ChangeCipherSpec:
    def to_bytes(self):
        return b'\x06' + struct.pack('!H', 1) + b'\x01'

    @classmethod
    def from_bytes(cls, data):
        if data[0] != 0x06 or data[3] != 0x01:
            raise ValueError("Invalid ChangeCipherSpec message")
        return cls()
