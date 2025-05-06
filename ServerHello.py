import os
import struct
class ServerHello:
    def __init__(self, server_random=None, selected_cipher_suite=0x0033):
        self.server_random = server_random or os.urandom(32)
        self.selected_cipher_suite = selected_cipher_suite

    def to_bytes(self):
        return b'\x02' + struct.pack('!H', 34) + self.server_random + struct.pack('!H', self.selected_cipher_suite)

    @classmethod
    def from_bytes(cls, data):
        if len(data) < 37:
            raise ValueError("Incomplete ServerHello message.")
        if data[0] != 0x02:
            raise ValueError("Not a ServerHello message.")
        ...

