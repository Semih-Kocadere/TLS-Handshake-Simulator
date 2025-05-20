import socket
import hmac
import logging
import json
import tkinter as tk
from tkinter import messagebox
import time
import binascii

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

def perform_tls_communication(fullname, password, message, log_fn=lambda msg: None):
    try:
        sock = socket.create_connection(('localhost', 12345))
        transcript = b''
        log_fn("🔌 Bağlantı sağlandı.")

        # 1. ClientHello
        client_hello = ClientHello()
        ch_bytes = client_hello.to_bytes()
        sock.sendall(ch_bytes)
        transcript += ch_bytes
        log_fn("📤 ClientHello gönderildi")

        # 2. ServerHello
        data = sock.recv(4096)
        server_hello = ServerHello.from_bytes(data)
        transcript += data
        log_fn("📥 ServerHello alındı")

        # 3. Certificate
        data = sock.recv(4096)
        certificate = Certificate.from_bytes(data)
        transcript += data
        log_fn("📥 Certificate alındı")

        # 4. ServerKeyExchange
        data = sock.recv(4096)
        ske = ServerKeyExchange.from_bytes(data)
        server_pubkey = deserialize_public_key(ske.public_key_bytes)
        transcript += data
        log_fn("📥 ServerKeyExchange alındı")

        # 5. ClientKeyExchange
        params = get_common_dh_parameters()
        client_priv, client_pub = generate_keypair(params)
        pub_bytes = serialize_public_key(client_pub)
        cke = ClientKeyExchange(pub_bytes)
        cke_bytes = cke.to_bytes()
        sock.sendall(cke_bytes)
        transcript += cke_bytes
        log_fn("📤 ClientKeyExchange gönderildi")

        # 6. Shared key
        shared_key = derive_shared_key(client_priv, server_pubkey)
        aes_key = shared_key[:32]
        log_fn("🔐 Ortak anahtar türetildi")

        # 7. ChangeCipherSpec + Finished birlikte gönder
        verify_data = compute_verify_data(transcript, shared_key)
        finished = Finished(verify_data)
        combined_msg = ChangeCipherSpec().to_bytes() + finished.to_bytes()
        sock.sendall(combined_msg)
        log_fn("📤 ChangeCipherSpec + Finished gönderildi")

        # 8. Server Finished
        sock.recv(4096)
        data = sock.recv(4096)
        server_finished = Finished.from_bytes(data)
        expected = compute_verify_data(transcript, shared_key)

        if not hmac.compare_digest(server_finished.verify_data, expected):
            return "❌ TLS handshake doğrulaması başarısız!"

        log_fn("✅ Handshake başarılı")

        # 9. Kullanıcı verisi ve mesajı gönder
        parts = fullname.strip().split()
        name = parts[0]
        surname = " ".join(parts[1:]) if len(parts) > 1 else ""

        payload = json.dumps({
            "name": name,
            "surname": surname,
            "password": password,
            "custom_message": message
        }).encode()

        encrypted = AESUtils.encrypt(aes_key, payload)
        sock.sendall(encrypted)
        log_fn(f"📤 Mesaj şifreli olarak gönderildi")

        # --- Yeni: GUI'de göster ---
        original_message_text.delete(1.0, tk.END)
        original_message_text.insert(tk.END, message)

        encrypted_text.delete(1.0, tk.END)
        encrypted_text.insert(tk.END, binascii.hexlify(encrypted).decode())

        # 10. Cevabı al
        response = sock.recv(4096)
        decrypted = AESUtils.decrypt(aes_key, response)
        log_fn("📥 Şifreli yanıt alındı")
        sock.close()

        decrypted_text.delete(1.0, tk.END)
        decrypted_text.insert(tk.END, decrypted.decode())

        return f"✅ Server yanıtı:\n{decrypted.decode()}"

    except Exception as e:
        log_fn(f"⚠️ Hata oluştu: {e}")
        return f"⚠️ Hata oluştu:\n{e}"

# === GUI ===
root = tk.Tk()
root.title("TLS Client GUI")
root.geometry("700x650")

frame = tk.Frame(root)
frame.pack(pady=10)

tk.Label(frame, text="Ad Soyad:").grid(row=0, column=0, sticky='e')
entry_fullname = tk.Entry(frame, width=30)
entry_fullname.grid(row=0, column=1)

tk.Label(frame, text="Parola:").grid(row=1, column=0, sticky='e')
entry_pass = tk.Entry(frame, show="*", width=30)
entry_pass.grid(row=1, column=1)

tk.Label(frame, text="Mesaj:").grid(row=2, column=0, sticky='e')
entry_message = tk.Entry(frame, width=30)
entry_message.grid(row=2, column=1)

tk.Button(root, text="Connect & Send", command=lambda: on_send()).pack(pady=10)

log_text = tk.Text(root, height=10, width=80)
log_text.pack(pady=10)

def log_gui(message):
    log_text.insert(tk.END, message + "\n")
    log_text.see(tk.END)

# === Yeni Metin Alanları ===
tk.Label(root, text="📨 Orijinal Mesaj").pack()
original_message_text = tk.Text(root, height=2, width=80)
original_message_text.pack()

tk.Label(root, text="🔐 Şifrelenmiş Veri (hex)").pack()
encrypted_text = tk.Text(root, height=4, width=80)
encrypted_text.pack()

tk.Label(root, text="📄 Sunucudan Gelen Açık Yanıt").pack()
decrypted_text = tk.Text(root, height=4, width=80)
decrypted_text.pack()

def on_send():
    fullname = entry_fullname.get().strip()
    password = entry_pass.get().strip()
    message = entry_message.get().strip()

    if not fullname or not password:
        messagebox.showerror("Hata", "Lütfen tüm alanları doldurun.")
        return
    if len(password) < 4:
        messagebox.showerror("Hata", "Parola en az 4 karakter olmalıdır.")
        return

    log_text.delete(1.0, tk.END)
    result = perform_tls_communication(fullname, password, message, log_gui)
    messagebox.showinfo("Sunucu Yanıtı", result)

root.mainloop()
