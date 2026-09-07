"""Generate a reproducible SMTP STARTTLS-rejection PCAP on Windows loopback."""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TSHARK = Path(r"C:\Program Files\Wireshark\tshark.exe")
OUTPUT = ROOT / "pcaps" / "smtp_starttls_rejected_true.pcapng"

if not TSHARK.exists(): raise SystemExit("TShark was not found.")
if OUTPUT.exists(): raise SystemExit(f"Refusing to overwrite existing capture: {OUTPUT}")

server = subprocess.Popen([sys.executable, "tools/smtp_starttls_lab.py", "server-reject"], cwd=ROOT)
capture = None
try:
    time.sleep(1)
    capture = subprocess.Popen([str(TSHARK), "-i", "8", "-f", "tcp port 2527", "-w", str(OUTPUT)], cwd=ROOT)
    time.sleep(1)
    client = subprocess.run([sys.executable, "tools/smtp_starttls_lab.py", "client-reject"], cwd=ROOT, check=True)
    time.sleep(1)
finally:
    if capture:
        capture.terminate()
        try: capture.wait(timeout=5)
        except subprocess.TimeoutExpired: capture.kill()
    try: server.wait(timeout=5)
    except subprocess.TimeoutExpired: server.kill()

print(f"Created {OUTPUT}")
