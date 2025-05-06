import socket
from ServerHello import ServerHello
from ClientHello import ClientHello
from cert_utils import generate_self_signed_cert
from Certificate import Certificate
from dh_utils import *
from ServerKeyExchange import ServerKeyExchange
from ClientKeyExchange import ClientKeyExchange
from Finished import Finished, compute_verify_data
import hmac
from ChangeCipherSpec import ChangeCipherSpec

# 1. Socket başlat, client’ı bekle
sock = socket.socket()
sock.bind(('localhost', 12345))
sock.listen(1)
conn, _ = sock.accept()

# 2. ClientHello al
print("Waiting for ClientHello...")
data = conn.recv(4096)
client_hello = ClientHello.from_bytes(data)
print("ClientHello received")
transcript = data

# 3. ServerHello oluştur ve gönder
print("Sending ServerHello...")
server_hello = ServerHello()
server_hello_bytes = server_hello.to_bytes()
conn.sendall(server_hello_bytes)
print("ServerHello sent")
transcript += server_hello_bytes

print("Generating self-signed certificate...")
# 4. Sertifika oluştur ve gönder
cert_bytes = generate_self_signed_cert()  # bunu sen yazmıştın
certificate = Certificate(cert_bytes)
cert_bytes = certificate.to_bytes()
conn.sendall(cert_bytes)
print("Certificate sent")
transcript += cert_bytes

# 5. DH keypair oluştur, ServerKeyExchange gönder
print("Generating DH keypair...")
params = get_common_dh_parameters()
server_priv, server_pub = generate_keypair(params)
server_pub_bytes = serialize_public_key(server_pub)
print("DH keypair generated")
ske = ServerKeyExchange(server_pub_bytes)
ske_bytes = ske.to_bytes()
conn.sendall(ske_bytes)
print("ServerKeyExchange sent")
transcript += ske_bytes

# 6. ClientKeyExchange al
print("Waiting for ClientKeyExchange...")
data = conn.recv(4096)
print("ClientKeyExchange received")
cke = ClientKeyExchange.from_bytes(data)
client_pub = deserialize_public_key(cke.public_key_bytes)
transcript += data

# 7. Shared key hesapla
print("Calculating shared key...")
shared_key = derive_shared_key(server_priv, client_pub)

# 8. ChangeCipherSpec al
conn.recv(4096)

# 9. Finished al
print("Waiting for Finished...")
data = conn.recv(4096)
print("Finished received")
client_finished = Finished.from_bytes(data)
expected = compute_verify_data(transcript, shared_key)

# 10. Doğrula
if not hmac.compare_digest(client_finished.verify_data, expected):
    print("Handshake failed 🚫")
    conn.close()
    exit()

# 11. ChangeCipherSpec gönder
ccs = ChangeCipherSpec()
conn.sendall(ccs.to_bytes())

# 12. Finished mesajı oluştur ve gönder
verify_data = compute_verify_data(transcript, shared_key)
finished = Finished(verify_data)
conn.sendall(finished.to_bytes())

print("Handshake completed successfully ✅")

conn.close()