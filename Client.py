import socket
import hmac
from ClientHello import ClientHello
from ServerHello import ServerHello
from Certificate import Certificate
from ServerKeyExchange import ServerKeyExchange
from ClientKeyExchange import ClientKeyExchange
from dh_utils import *
from ChangeCipherSpec import ChangeCipherSpec
from Finished import Finished, compute_verify_data

# 1. Socket aç ve sunucuya bağlan
sock = socket.create_connection(('localhost', 12345))

# 2. ClientHello oluştur ve gönder
print("Sending ClientHello...")
client_hello = ClientHello()
sock.sendall(client_hello.to_bytes())
print("ClientHello sent")
transcript = client_hello.to_bytes()

# 3. ServerHello al
print("Waiting for ServerHello...")
data = sock.recv(4096)
server_hello = ServerHello.from_bytes(data)
print("ServerHello received")
transcript += data

# 4. Certificate al
print("Waiting for Certificate...")
data = sock.recv(4096)
if data[0] != 0x03:
    raise ValueError("Invalid Certificate message")
certificate = Certificate.from_bytes(data)
print("Certificate received")
transcript += data

# 5. ServerKeyExchange al
print("Waiting for ServerKeyExchange...")
data = sock.recv(4096)
if data[0] != 0x04:
    raise ValueError("Invalid ServerKeyExchange message")
ske = ServerKeyExchange.from_bytes(data)
server_pubkey = deserialize_public_key(ske.public_key_bytes)
print("ServerKeyExchange received")
transcript += data

# 6. Kendi DH anahtarlarını üret
print("Generating DH keypair...")
params = get_common_dh_parameters()
client_priv, client_pub = generate_keypair(params)
client_pub_bytes = serialize_public_key(client_pub)
print("Client public key generated")

# 7. ClientKeyExchange gönder
print("Sending ClientKeyExchange...")
cke = ClientKeyExchange(client_pub_bytes)
cke_bytes = cke.to_bytes()
sock.sendall(cke_bytes)
transcript += cke_bytes
print("ClientKeyExchange sent")

# 8. Shared secret hesapla
print("Deriving shared key...")
shared_key = derive_shared_key(client_priv, server_pubkey)

# 9. ChangeCipherSpec gönder
print("Sending ChangeCipherSpec...")
ccs = ChangeCipherSpec()
ccs_bytes = ccs.to_bytes()
sock.sendall(ccs_bytes)
print("ChangeCipherSpec sent")

# 10. Finished mesajı oluştur ve gönder
print("Sending Finished...")
verify_data = compute_verify_data(transcript, shared_key)
finished = Finished(verify_data)
finished_bytes = finished.to_bytes()
sock.sendall(finished_bytes)
print("Finished sent")

# 11. Sunucudan ChangeCipherSpec al
print("Waiting for ChangeCipherSpec...")
data = sock.recv(4096)
print("ChangeCipherSpec received")

# 12. Sunucudan Finished al
print("Waiting for Finished...")
data = sock.recv(4096)
server_finished = Finished.from_bytes(data)
expected = compute_verify_data(transcript, shared_key)
print("Finished received")

# 13. Karşılaştır
if hmac.compare_digest(server_finished.verify_data, expected):
    print("Handshake successful 🎉")
else:
    print("Handshake failed 🚫")

print("Closing connection.")
sock.close()