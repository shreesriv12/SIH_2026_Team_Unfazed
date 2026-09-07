"""Generate IMAP STARTTLS and POP3 STLS rejection PCAP fixtures on Windows loopback."""
from __future__ import annotations
import subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TSHARK = Path(r"C:\Program Files\Wireshark\tshark.exe")

def capture(protocol: str, port: int, output: str) -> None:
    path = ROOT / "pcaps" / output
    if path.exists(): raise FileExistsError(f"Refusing to overwrite {path}")
    server = subprocess.Popen([sys.executable, "tools/mail_upgrade_lab.py", f"{protocol}-server-reject"], cwd=ROOT)
    tshark = None
    try:
        time.sleep(1)
        tshark = subprocess.Popen([str(TSHARK), "-i", "8", "-f", f"tcp port {port}", "-w", str(path)], cwd=ROOT)
        time.sleep(1)
        subprocess.run([sys.executable, "tools/mail_upgrade_lab.py", f"{protocol}-client-reject"], cwd=ROOT, check=True)
        time.sleep(1)
    finally:
        if tshark: tshark.terminate(); tshark.wait(timeout=5)
        server.wait(timeout=5)
    print(f"Created {path}")

if __name__ == "__main__":
    capture("imap", 2144, "imap_starttls_rejected.pcapng")
    capture("pop3", 2111, "pop3_stls_rejected.pcapng")
