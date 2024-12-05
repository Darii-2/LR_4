import ssl
import socket
from threading import Thread
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
import json
import os

def generate_certificates():
    """Генерує самопідписані сертифікати для клієнта та сервера."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Kyiv"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Kyiv"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TestOrganization"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )

    with open("server.key", "wb") as key_file:
        key_file.write(key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))

    with open("server.crt", "wb") as cert_file:
        cert_file.write(cert.public_bytes(Encoding.PEM))

    # Генерація клієнтського сертифіката
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(client_key, hashes.SHA256())
    )

    with open("client.key", "wb") as key_file:
        key_file.write(client_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))

    with open("client.crt", "wb") as cert_file:
        cert_file.write(client_cert.public_bytes(Encoding.PEM))

# Генеруємо сертифікати, якщо їх немає
if not os.path.exists("server.key") or not os.path.exists("server.crt"):
    generate_certificates()

def server():
    """Реалізація SSL-сервера."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile="client.crt")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('localhost', 8443))
        server_socket.listen(5)
        print("Сервер очікує з'єднання...")

        with context.wrap_socket(server_socket, server_side=True) as tls_server_socket:
            conn, addr = tls_server_socket.accept()
            print(f"Клієнт підключився: {addr}")

            # Отримання даних
            data = conn.recv(1024).decode('utf-8')
            message = json.loads(data)
            print(f"Отримано від клієнта: {message}")

            # Надсилаємо відповідь
            response = json.dumps({"status": "success", "received": message})
            conn.send(response.encode('utf-8'))


def client():
    """Реалізація SSL-клієнта."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain(certfile="client.crt", keyfile="client.key")
    context.load_verify_locations(cafile="server.crt")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        with context.wrap_socket(client_socket, server_hostname="localhost") as tls_client_socket:
            tls_client_socket.connect(('localhost', 8443))
            print("Підключено до сервера.")

            # Відправка даних
            message = json.dumps({"action": "greet", "message": "Hello, Server!"})
            tls_client_socket.send(message.encode('utf-8'))

            # Отримання відповіді
            response = tls_client_socket.recv(1024).decode('utf-8')
            print(f"Відповідь від сервера: {response}")

# Запускаємо сервер і клієнт в окремих потоках
server_thread = Thread(target=server)
server_thread.start()

client_thread = Thread(target=client)
client_thread.start()

server_thread.join()
client_thread.join()
