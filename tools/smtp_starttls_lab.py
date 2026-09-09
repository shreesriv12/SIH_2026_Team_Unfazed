"""Local, single-use SMTP STARTTLS server/client for a reproducible PCAP lab."""
from __future__ import annotations

import argparse
import socket
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
CERT, KEY = ROOT / "pcaps" / "lab-cert.pem", ROOT / "pcaps" / "lab-key.pem"
HOST, PORT = "127.0.0.1", 2525
PLAIN_PORT = 2526
REJECT_PORT = 2527
BROKEN_PORT = 2528
IGNORED_PORT = 2529

def make_certificate() -> None:
    CERT.parent.mkdir(exist_ok=True)
    if CERT.exists() and KEY.exists(): return
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "securemailscope.local")])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(private_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(private_key, hashes.SHA256()))
    CERT.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    KEY.write_bytes(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

def line(connection: socket.socket) -> bytes:
    data = b""
    while not data.endswith(b"\r\n"):
        part = connection.recv(1)
        if not part: raise ConnectionError("client closed connection")
        data += part
    return data

def server() -> None:
    make_certificate()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(CERT, KEY)
    with socket.create_server((HOST, PORT), reuse_port=False) as listener:
        print(f"SMTP lab server listening on {HOST}:{PORT}; waiting for one client...")
        connection, _ = listener.accept()
        with connection:
            connection.sendall(b"220 securemailscope.local ESMTP lab\r\n")
            assert line(connection).upper().startswith(b"EHLO")
            connection.sendall(b"250-securemailscope.local\r\n250-STARTTLS\r\n250 SIZE 1048576\r\n")
            assert line(connection).upper() == b"STARTTLS\r\n"
            connection.sendall(b"220 Ready to start TLS\r\n")
            with context.wrap_socket(connection, server_side=True) as tls:
                print("TLS handshake completed.")
                line(tls); tls.sendall(b"250 secure TLS active\r\n")

def client() -> None:
    with socket.create_connection((HOST, PORT), timeout=10) as connection:
        print(line(connection).decode().strip())
        connection.sendall(b"EHLO securemailscope-client.local\r\n")
        while True:
            response = line(connection); print(response.decode().strip())
            if response.startswith(b"250 "): break
        connection.sendall(b"STARTTLS\r\n"); print(line(connection).decode().strip())
        context = ssl.create_default_context(); context.check_hostname = False; context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(connection, server_hostname="localhost") as tls:
            print("Client negotiated:", tls.version(), tls.cipher()[0])
            tls.sendall(b"EHLO encrypted-client.local\r\n"); print(line(tls).decode().strip())

def plain_server() -> None:
    """Intentionally insecure SMTP service for the missing-STARTTLS rule fixture."""
    with socket.create_server((HOST, PLAIN_PORT), reuse_port=False) as listener:
        print(f"Plain SMTP lab server listening on {HOST}:{PLAIN_PORT}; waiting for one client...")
        connection, _ = listener.accept()
        with connection:
            connection.sendall(b"220 insecure-lab.local ESMTP lab\r\n")
            assert line(connection).upper().startswith(b"EHLO")
            connection.sendall(b"250 insecure-lab.local\r\n")
            assert line(connection).upper().startswith(b"QUIT")
            connection.sendall(b"221 Bye\r\n")

def plain_client() -> None:
    with socket.create_connection((HOST, PLAIN_PORT), timeout=10) as connection:
        print(line(connection).decode().strip())
        connection.sendall(b"EHLO insecure-client.local\r\n"); print(line(connection).decode().strip())
        connection.sendall(b"QUIT\r\n"); print(line(connection).decode().strip())

def starttls_response_server(port: int, response: bytes, label: str) -> None:
    with socket.create_server((HOST, port), reuse_port=False) as listener:
        print(f"{label} SMTP lab server listening on {HOST}:{port}; waiting for one client...")
        connection, _ = listener.accept()
        with connection:
            connection.sendall(b"220 securemailscope-lab.local ESMTP lab\r\n")
            assert line(connection).upper().startswith(b"EHLO")
            connection.sendall(b"250-securemailscope-lab.local\r\n250 STARTTLS\r\n")
            assert line(connection).upper() == b"STARTTLS\r\n"
            connection.sendall(response)

def reject_server() -> None:
    starttls_response_server(REJECT_PORT, b"454 TLS temporarily unavailable\r\n", "STARTTLS-rejection")

def broken_server() -> None:
    starttls_response_server(BROKEN_PORT, b"220 Ready to start TLS\r\n", "STARTTLS-broken")

def ignored_server() -> None:
    """Advertises STARTTLS; the paired client deliberately continues in plaintext."""
    with socket.create_server((HOST, IGNORED_PORT), reuse_port=False) as listener:
        print(f"STARTTLS-advertised/ignored SMTP lab on {HOST}:{IGNORED_PORT}; waiting for one client...")
        connection, _ = listener.accept()
        with connection:
            connection.sendall(b"220 securemailscope-lab.local ESMTP lab\r\n")
            assert line(connection).upper().startswith(b"EHLO")
            connection.sendall(b"250-securemailscope-lab.local\r\n250 STARTTLS\r\n")
            assert line(connection).upper().startswith(b"MAIL FROM")
            connection.sendall(b"250 plaintext accepted for controlled fixture\r\n")

def starttls_client(port: int) -> None:
    with socket.create_connection((HOST, port), timeout=10) as connection:
        print(line(connection).decode().strip())
        connection.sendall(b"EHLO transition-test.local\r\n")
        while True:
            response = line(connection); print(response.decode().strip())
            if response.startswith(b"250 "): break
        connection.sendall(b"STARTTLS\r\n"); print(line(connection).decode().strip())

def reject_client() -> None: starttls_client(REJECT_PORT)
def broken_client() -> None: starttls_client(BROKEN_PORT)

def ignored_client() -> None:
    with socket.create_connection((HOST, IGNORED_PORT), timeout=10) as connection:
        print(line(connection).decode().strip()); connection.sendall(b"EHLO transition-test.local\r\n")
        while True:
            response = line(connection); print(response.decode().strip())
            if response.startswith(b"250 "): break
        connection.sendall(b"MAIL FROM:<fixture@securemailscope.local>\r\n"); print(line(connection).decode().strip())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("mode", choices=["server", "client", "server-plain", "client-plain", "server-reject", "client-reject", "server-broken", "client-broken", "server-ignored", "client-ignored"])
    args = parser.parse_args()
    {"server": server, "client": client, "server-plain": plain_server, "client-plain": plain_client,
     "server-reject": reject_server, "client-reject": reject_client, "server-broken": broken_server, "client-broken": broken_client, "server-ignored": ignored_server, "client-ignored": ignored_client}[args.mode]()
