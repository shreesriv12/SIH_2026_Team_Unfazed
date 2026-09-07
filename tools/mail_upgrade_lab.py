"""Local IMAP STARTTLS and POP3 STLS lab server/client fixtures."""
from __future__ import annotations
import argparse, socket, ssl
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CERT, KEY = ROOT / "pcaps" / "lab-cert.pem", ROOT / "pcaps" / "lab-key.pem"
HOST = "127.0.0.1"
PORTS = {"imap": 2143, "imap-reject": 2144, "pop3": 2110, "pop3-reject": 2111}

def recvline(sock: socket.socket) -> bytes:
    data = b""
    while not data.endswith(b"\r\n"):
        data += sock.recv(1)
    return data

def context() -> ssl.SSLContext:
    if not CERT.exists() or not KEY.exists(): raise RuntimeError("Run smtp_starttls_lab.py server once to create the local lab certificate.")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.minimum_version = ssl.TLSVersion.TLSv1_2; ctx.load_cert_chain(CERT, KEY)
    return ctx

def server(protocol: str, reject: bool) -> None:
    port = PORTS[f"{protocol}-reject"] if reject else PORTS[protocol]
    with socket.create_server((HOST, port), reuse_port=False) as listener:
        print(f"{protocol.upper()} lab on {HOST}:{port}; waiting for one client...")
        conn, _ = listener.accept()
        with conn:
            if protocol == "imap":
                conn.sendall(b"* OK SecureMailScope IMAP lab\r\n")
                assert b"STARTTLS" in recvline(conn).upper()
                if reject: conn.sendall(b"a001 NO STARTTLS unavailable\r\n"); return
                conn.sendall(b"a001 OK Begin TLS negotiation now\r\n")
            else:
                conn.sendall(b"+OK SecureMailScope POP3 lab\r\n")
                assert recvline(conn).upper().startswith(b"STLS")
                if reject: conn.sendall(b"-ERR STLS unavailable\r\n"); return
                conn.sendall(b"+OK Begin TLS negotiation now\r\n")
            with context().wrap_socket(conn, server_side=True) as tls:
                print("TLS handshake completed.")
                recvline(tls)

def client(protocol: str, reject: bool) -> None:
    port = PORTS[f"{protocol}-reject"] if reject else PORTS[protocol]
    with socket.create_connection((HOST, port), timeout=10) as conn:
        print(recvline(conn).decode().strip())
        command = b"a001 STARTTLS\r\n" if protocol == "imap" else b"STLS\r\n"
        conn.sendall(command); response = recvline(conn); print(response.decode().strip())
        if reject: return
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(conn, server_hostname="localhost") as tls:
            print("Client negotiated:", tls.version(), tls.cipher()[0])
            tls.sendall(b"a002 NOOP\r\n" if protocol == "imap" else b"NOOP\r\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("mode", choices=["imap-server", "imap-client", "imap-server-reject", "imap-client-reject", "pop3-server", "pop3-client", "pop3-server-reject", "pop3-client-reject"])
    mode = parser.parse_args().mode
    protocol = "imap" if mode.startswith("imap") else "pop3"; reject = mode.endswith("reject")
    server(protocol, reject) if "server" in mode else client(protocol, reject)
