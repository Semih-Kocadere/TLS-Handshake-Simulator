import os
import struct

class ClientHello:
    def __init__(self, client_random=None, cipher_suites=None):
        self.client_random = client_random or os.urandom(32)
        self.cipher_suites = cipher_suites or [0x0033]  # örnek cipher suite (DHE_RSA_WITH_AES_128_CBC_SHA)

    def to_bytes(self):
        suites_bytes = b''.join(struct.pack('!H', cs) for cs in self.cipher_suites)
        length = 32 + 2 + len(suites_bytes)
        return b'\x01' + struct.pack('!H', length) + self.client_random + struct.pack('!H', len(self.cipher_suites)) + suites_bytes

    @classmethod
    def from_bytes(cls, data):
        if data[0] != 0x01:
            raise ValueError("Not a ClientHello message.")
        length = struct.unpack('!H', data[1:3])[0]
        client_random = data[3:35]
        suite_count = struct.unpack('!H', data[35:37])[0]
        cipher_suites = [struct.unpack('!H', data[37+i*2:39+i*2])[0] for i in range(suite_count)]
        return cls(client_random, cipher_suites)
