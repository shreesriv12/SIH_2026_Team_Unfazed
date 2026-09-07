"""Create a TLS 1.2 SMTP STARTTLS PCAP with an intentionally expired certificate."""
from __future__ import annotations
import argparse, socket, ssl, subprocess, sys, time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]; HOST, PORT = "127.0.0.1", 2529
CERT, KEY = ROOT / "pcaps" / "expired-cert.pem", ROOT / "pcaps" / "expired-key.pem"
OUTPUT = ROOT / "pcaps" / "smtp_tls12_expired_cert_retry.pcapng"; TSHARK = Path(r"C:\Program Files\Wireshark\tshark.exe")
def cert():
    if CERT.exists(): return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048); name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"expired.securemailscope.local")])
    now=datetime.now(UTC); value=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=30)).not_valid_after(now-timedelta(days=1)).sign(key,hashes.SHA256()))
    CERT.write_bytes(value.public_bytes(serialization.Encoding.PEM)); KEY.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()))
def line(sock: socket.socket)->bytes:
    data=b""
    while not data.endswith(b"\r\n"): data+=sock.recv(1)
    return data
def server():
    cert(); ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_2; ctx.load_cert_chain(CERT,KEY)
    with socket.create_server((HOST,PORT),reuse_port=False) as listener:
        conn,_=listener.accept()
        with conn:
            conn.sendall(b"220 expired-cert.lab ESMTP\r\n"); line(conn); conn.sendall(b"250-expired-cert.lab\r\n250 STARTTLS\r\n"); line(conn); conn.sendall(b"220 Ready to start TLS\r\n")
            with ctx.wrap_socket(conn,server_side=True) as tls: line(tls)
def client():
    with socket.create_connection((HOST,PORT),timeout=10) as conn:
        line(conn); conn.sendall(b"EHLO client.local\r\n"); line(conn); line(conn); conn.sendall(b"STARTTLS\r\n"); line(conn)
        ctx=ssl.create_default_context(); ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE;ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_2
        with ctx.wrap_socket(conn,server_hostname="localhost") as tls: print("Client negotiated",tls.version(),tls.cipher()[0]); tls.sendall(b"EHLO encrypted.local\r\n")
def capture():
    cert()
    if OUTPUT.exists(): raise FileExistsError(f"Refusing to overwrite {OUTPUT}")
    s=subprocess.Popen([sys.executable,__file__,"server"],cwd=ROOT); t=None
    try:
        time.sleep(1); t=subprocess.Popen([str(TSHARK),"-i","8","-f",f"tcp port {PORT}","-w",str(OUTPUT)],cwd=ROOT); time.sleep(2)
        subprocess.run([sys.executable,__file__,"client"],cwd=ROOT,check=True); time.sleep(1)
    finally:
        if t: t.terminate();t.wait(timeout=5)
        s.wait(timeout=5)
    print("Created",OUTPUT)
if __name__=="__main__":
    mode=argparse.ArgumentParser();mode.add_argument("mode",choices=["server","client","capture"]);a=mode.parse_args().mode
    {"server":server,"client":client,"capture":capture}[a]()
