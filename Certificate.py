import struct
class Certificate:
    def __init__(self, cert_bytes):
        self.cert_bytes = cert_bytes

    def to_bytes(self):
        length = len(self.cert_bytes)
        return b'\x03' + struct.pack('!H', length) + self.cert_bytes

    @classmethod
    def from_bytes(cls, data):
        if data[0] != 0x03:
            raise ValueError("Not a Certificate message.")
        length = struct.unpack('!H', data[1:3])[0]
        cert_bytes = data[3:3+length]
        return cls(cert_bytes)
