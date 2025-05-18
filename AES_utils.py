# aes_utils.py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class AESUtils:
    @staticmethod
    def encrypt(key: bytes, plaintext: bytes) -> bytes:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit nonce
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext  # nonce + ciphertext birlikte gönderilir

    @staticmethod
    def decrypt(key: bytes, message: bytes) -> bytes:
        aesgcm = AESGCM(key)
        nonce = message[:12]
        ciphertext = message[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)