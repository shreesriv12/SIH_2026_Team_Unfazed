"""Deterministic dependency-free smoke fuzzer for the upload boundary."""
import random, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi import HTTPException
from capture_security import validate_capture_content

def main(iterations: int = 5000) -> None:
    randomizer = random.Random(20260908); accepted = 0
    for _ in range(iterations):
        try: validate_capture_content(randomizer.randbytes(randomizer.randint(0, 256))); accepted += 1
        except HTTPException: pass
    if accepted: raise RuntimeError(f"Fuzzer accepted {accepted} random non-PCAP inputs.")
    print(f"Rejected {iterations} deterministic hostile inputs without a crash.")

if __name__ == "__main__": main()
