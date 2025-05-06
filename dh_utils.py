from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def get_common_dh_parameters():
    from cryptography.hazmat.primitives.asymmetric import dh
    from cryptography.hazmat.backends import default_backend

    param_numbers = dh.DHParameterNumbers(
        p=int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
              "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
              "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
              "E485B576625E7EC6F44C42E9A63A36210000000000090563", 16),
        g=2
    )
    return param_numbers.parameters(default_backend())


def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters

def generate_keypair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_key(own_private_key, peer_public_key):
    shared_key = own_private_key.exchange(peer_public_key)
    return shared_key  # bu shared_key üzerinden session key türetilecek

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_key_bytes):
    return serialization.load_der_public_key(
        public_key_bytes,
        backend=default_backend()
    )


