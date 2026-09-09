"""Run: python tools/evaluate_benchmark.py benchmarks/manifest.json"""
from __future__ import annotations
import json, sys
from pathlib import Path
from core.analyzer import analyze_pcap

def evaluate(manifest: dict) -> dict:
    expected, actual = set(), set(); total = len(manifest["captures"])
    for capture in manifest["captures"]:
        name = capture["file"]; wanted = set(capture.get("expected_rules", []))
        if not Path(name).exists(): continue
        found = {item["rule"] for item in analyze_pcap(Path(name)).findings}
        expected |= {(name, rule) for rule in wanted}; actual |= {(name, rule) for rule in found}
    true_positive = len(expected & actual); false_positive = len(actual - expected); false_negative = len(expected - actual)
    return {"captures": total, "true_positive": true_positive, "false_positive": false_positive, "false_negative": false_negative, "precision": round(true_positive / max(true_positive + false_positive, 1), 3), "recall": round(true_positive / max(true_positive + false_negative, 1), 3), "coverage": round(sum(1 for item in manifest["captures"] if item.get("expected_rules")) / max(total, 1), 3)}

if __name__ == "__main__": print(json.dumps(evaluate(json.loads(Path(sys.argv[1]).read_text())), indent=2))
