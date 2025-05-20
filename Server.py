import socket
import hmac
import logging
import threading
import json

from ClientHello import ClientHello
from ServerHello import ServerHello
from Certificate import Certificate
from ServerKeyExchange import ServerKeyExchange
from ClientKeyExchange import ClientKeyExchange
from dh_utils import *
from ChangeCipherSpec import ChangeCipherSpec
from Finished import Finished, compute_verify_data
from cert_utils import generate_self_signed_cert
from AES_utils import AESUtils

logging.basicConfig(level=logging.INFO, format='[SERVER] %(message)s')

running = True

def handle_tls_connection(conn, addr):
    try:
        conn.settimeout(3.0)
        logging.info(f"Connection accepted from {addr}")

        # 1. ClientHello
        data = conn.recv(4096)
        client_hello = ClientHello.from_bytes(data)
        transcript = data
        logging.info("ClientHello received")

        # 2. ServerHello
        server_hello = ServerHello()
        server_hello_bytes = server_hello.to_bytes()
        conn.sendall(server_hello_bytes)
        transcript += server_hello_bytes
        logging.info("ServerHello sent")

        # 3. Certificate
        cert_bytes = generate_self_signed_cert()
        certificate = Certificate(cert_bytes)
        cert_msg = certificate.to_bytes()
        conn.sendall(cert_msg)
        transcript += cert_msg
        logging.info("Certificate sent")

        # 4. ServerKeyExchange
        params = get_common_dh_parameters()
        server_priv, server_pub = generate_keypair(params)
        pub_bytes = serialize_public_key(server_pub)
        ske = ServerKeyExchange(pub_bytes)
        ske_bytes = ske.to_bytes()
        conn.sendall(ske_bytes)
        transcript += ske_bytes
        logging.info("ServerKeyExchange sent")

        # 5. ClientKeyExchange
        data = conn.recv(4096)
        cke = ClientKeyExchange.from_bytes(data)
        client_pub = deserialize_public_key(cke.public_key_bytes)
        transcript += data
        logging.info("ClientKeyExchange received")

        # 6. Ortak anahtar hesapla
        shared_key = derive_shared_key(server_priv, client_pub)
        aes_key = shared_key[:32]

        # 7. ChangeCipherSpec + Finished tek pakette gelir
        data = conn.recv(4096)
        if data[0] == 0x06:
            logging.info("ChangeCipherSpec received")
            client_finished = Finished.from_bytes(data[4:])
        else:
            client_finished = Finished.from_bytes(data)

        expected = compute_verify_data(transcript, shared_key)
        logging.info("Finished received")
        if not hmac.compare_digest(client_finished.verify_data, expected):
            logging.error("Finished verify failed.")
            return

        logging.info("Finished verify succeeded")

        # 8. Server taraflı ChangeCipherSpec + Finished
        conn.sendall(ChangeCipherSpec().to_bytes())
        logging.info("ChangeCipherSpec sent")

        verify_data = compute_verify_data(transcript, shared_key)
        finished = Finished(verify_data)
        conn.sendall(finished.to_bytes())
        logging.info("Finished sent")

        # 9. Şifreli mesajı al
        logging.info("Waiting for encrypted message from client...")
        try:
            data = conn.recv(4096)
            decrypted = AESUtils.decrypt(aes_key, data)
        except Exception as e:
            logging.error(f"[DECRYPT ERROR] {e}")
            return

        # 10. Mesajı çöz ve logla
        try:
            user_data = json.loads(decrypted.decode())
            name = user_data.get("name", "")
            surname = user_data.get("surname", "")
            password = user_data.get("password", "")
            message = user_data.get("custom_message", "")

            logging.info(f"[KULLANICI GİRİŞİ]")
            logging.info(f"Ad: {name}")
            logging.info(f"Soyad: {surname}")
            logging.info(f"Parola: {password}")
            logging.info(f"Mesaj: {message}")

            response = f"Sunucu mesajı aldı: {message}"
        except Exception as e:
            logging.error(f"[JSON ERROR] {e}")
            response = "❌ Bilgiler okunamadı."

        # 11. Şifreli yanıt gönder
        encrypted_response = AESUtils.encrypt(aes_key, response.encode())
        conn.sendall(encrypted_response)
        logging.info("Encrypted response sent")

    except socket.timeout:
        logging.error("Timeout.")
    except Exception as e:
        logging.error(f"Error: {e}")
    finally:
        conn.close()
        logging.info("Connection closed")

def server_loop():
    global running
    server_socket = socket.socket()
    server_socket.bind(('localhost', 12345))
    server_socket.listen(5)
    server_socket.settimeout(1.0)
    logging.info("Server is listening... (Press ENTER to stop)\n")

    while running:
        try:
            conn, addr = server_socket.accept()
            handle_tls_connection(conn, addr)
        except socket.timeout:
            continue
        except Exception as e:
            logging.error(f"Server error: {e}")
            break

    server_socket.close()
    logging.info("Server stopped.")

def wait_for_enter():
    global running
    input()
    running = False

# Başlat
threading.Thread(target=server_loop).start()
threading.Thread(target=wait_for_enter).start()
