import hashlib, json
from pathlib import Path

def test_public_dataset_files_match_provenance_hashes():
    manifest = json.loads(Path("benchmarks/public-validation.json").read_text(encoding="utf-8"))
    assert len(manifest["captures"]) >= 4
    for item in manifest["captures"]:
        assert hashlib.sha256(Path(item["file"]).read_bytes()).hexdigest() == item["sha256"]
