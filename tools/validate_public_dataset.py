from __future__ import annotations
import hashlib, json, os, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT)); os.environ["SECUREMAILSCOPE_ZEEK_URL"] = ""
from core.analyzer import analyze_pcap

def main() -> None:
    manifest = json.loads((ROOT / "benchmarks/public-validation.json").read_text(encoding="utf-8")); correct = sessions = 0
    for item in manifest["captures"]:
        path = ROOT / item["file"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]: raise RuntimeError(f"Provenance hash mismatch: {path.name}")
        result = analyze_pcap(path); sessions += len(result.sessions)
        if any(s.protocol == item["expected_protocol"] and s.transition == item["expected_transition"] for s in result.sessions): correct += 1
    summary = {"captures": len(manifest["captures"]), "sessions": sessions, "correct": correct, "protocol_transition_accuracy": round(correct / len(manifest["captures"]), 4)}
    print(json.dumps(summary, indent=2))
    if correct != len(manifest["captures"]): raise RuntimeError("Public validation expectations failed.")

if __name__ == "__main__": main()
