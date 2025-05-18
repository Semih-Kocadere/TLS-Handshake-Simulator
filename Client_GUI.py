import socket
import hmac
import logging
import json
import tkinter as tk
from tkinter import messagebox
import time

from ClientHello import ClientHello
from ServerHello import ServerHello
from Certificate import Certificate
from ServerKeyExchange import ServerKeyExchange
from ClientKeyExchange import ClientKeyExchange
from dh_utils import *
from ChangeCipherSpec import ChangeCipherSpec
from Finished import Finished, compute_verify_data
from AES_utils import AESUtils

logging.basicConfig(level=logging.INFO, format='[CLIENT-GUI] %(message)s')

def perform_tls_communication(fullname, password):
    try:
        sock = socket.create_connection(('localhost', 12345))
        transcript = b''

        # 1. ClientHello
        client_hello = ClientHello()
        ch_bytes = client_hello.to_bytes()
        sock.sendall(ch_bytes)
        transcript += ch_bytes

        # 2. ServerHello
        data = sock.recv(4096)
        server_hello = ServerHello.from_bytes(data)
        transcript += data

        # 3. Certificate
        data = sock.recv(4096)
        certificate = Certificate.from_bytes(data)
        transcript += data

        # 4. ServerKeyExchange
        data = sock.recv(4096)
        ske = ServerKeyExchange.from_bytes(data)
        server_pubkey = deserialize_public_key(ske.public_key_bytes)
        transcript += data

        # 5. ClientKeyExchange
        params = get_common_dh_parameters()
        client_priv, client_pub = generate_keypair(params)
        pub_bytes = serialize_public_key(client_pub)
        cke = ClientKeyExchange(pub_bytes)
        cke_bytes = cke.to_bytes()
        sock.sendall(cke_bytes)
        transcript += cke_bytes

        # 6. Shared key
        shared_key = derive_shared_key(client_priv, server_pubkey)
        aes_key = shared_key[:32]

        # 7. ChangeCipherSpec
        sock.sendall(ChangeCipherSpec().to_bytes())

        # 8. Finished
        verify_data = compute_verify_data(transcript, shared_key)
        finished = Finished(verify_data)
        sock.sendall(finished.to_bytes())

        # 9. Receive server's Finished
        sock.recv(4096)
        data = sock.recv(4096)
        server_finished = Finished.from_bytes(data)
        expected = compute_verify_data(transcript, shared_key)

        if not hmac.compare_digest(server_finished.verify_data, expected):
            return "❌ TLS handshake doğrulaması başarısız!"

        # ✅ GECİKME
        time.sleep(0.1)

        # ✂️ Ad ve soyad ayır
        parts = fullname.strip().split()
        name = parts[0]
        surname = " ".join(parts[1:]) if len(parts) > 1 else ""

        # 10. Kullanıcı verisini gönder
        payload = json.dumps({
            "name": name,
            "surname": surname,
            "password": password
        }).encode()
        encrypted = AESUtils.encrypt(aes_key, payload)
        sock.sendall(encrypted)

        # 11. Yanıtı al
        response = sock.recv(4096)
        decrypted = AESUtils.decrypt(aes_key, response)
        sock.close()

        return f"👋 Hoşgeldiniz, {name} {surname}!\n\n✅ Server yanıtı:\n{decrypted.decode()}"

    except Exception as e:
        logging.error(f"Hata: {e}")
        return f"⚠️ Hata oluştu:\n{e}"

def on_send():
    fullname = entry_fullname.get()
    password = entry_pass.get()
    result = perform_tls_communication(fullname, password)
    messagebox.showinfo("Server Response", result)

# GUI
root = tk.Tk()
root.title("TLS Client GUI")
root.geometry("320x260")

frame = tk.Frame(root)
frame.pack(pady=20)

tk.Label(frame, text="Ad Soyad:").grid(row=0, column=0, sticky='e')
entry_fullname = tk.Entry(frame)
entry_fullname.grid(row=0, column=1)

tk.Label(frame, text="Parola:").grid(row=1, column=0, sticky='e')
entry_pass = tk.Entry(frame, show="*")
entry_pass.grid(row=1, column=1)

tk.Button(root, text="Connect & Send", command=on_send).pack(pady=20)

root.mainloop()
