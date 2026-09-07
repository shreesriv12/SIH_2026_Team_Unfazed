"""Create a controlled TLS 1.0 SMTP STARTTLS PCAP for the deprecated-TLS rule."""
from __future__ import annotations
import socket, ssl, subprocess, sys, time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]; HOST,PORT="127.0.0.1",2530
CERT,KEY=ROOT/"pcaps"/"lab-cert.pem",ROOT/"pcaps"/"lab-key.pem"; OUT=ROOT/"pcaps"/"smtp_tls10_deprecated.pcapng"; TSHARK=Path(r"C:\Program Files\Wireshark\tshark.exe")
def line(s):
 data=b""
 while not data.endswith(b"\r\n"): data+=s.recv(1)
 return data
def server():
 ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1;ctx.set_ciphers("DEFAULT:@SECLEVEL=0");ctx.load_cert_chain(CERT,KEY)
 with socket.create_server((HOST,PORT),reuse_port=False) as l:
  c,_=l.accept()
  with c:
   c.sendall(b"220 deprecated-tls.lab ESMTP\r\n");line(c);c.sendall(b"250-deprecated-tls.lab\r\n250 STARTTLS\r\n");line(c);c.sendall(b"220 Ready to start TLS\r\n")
   with ctx.wrap_socket(c,server_side=True) as t: line(t)
def client():
 with socket.create_connection((HOST,PORT),timeout=10) as c:
  line(c);c.sendall(b"EHLO client.local\r\n");line(c);line(c);c.sendall(b"STARTTLS\r\n");line(c)
  ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE;ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1;ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
  with ctx.wrap_socket(c,server_hostname="localhost") as t: print("Client negotiated",t.version(),t.cipher()[0]);t.sendall(b"EHLO encrypted.local\r\n")
def capture():
 if OUT.exists():raise FileExistsError(f"Refusing to overwrite {OUT}")
 s=subprocess.Popen([sys.executable,__file__,"server"],cwd=ROOT);t=None
 try:
  time.sleep(1);t=subprocess.Popen([str(TSHARK),"-i","8","-f",f"tcp port {PORT}","-w",str(OUT)],cwd=ROOT);time.sleep(2);subprocess.run([sys.executable,__file__,"client"],cwd=ROOT,check=True);time.sleep(1)
 finally:
  if t:t.terminate();t.wait(timeout=5)
  s.wait(timeout=5)
 print("Created",OUT)
if __name__=="__main__":
 mode=sys.argv[1] if len(sys.argv)>1 else "capture";{"server":server,"client":client,"capture":capture}[mode]()
