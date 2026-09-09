import json
from pathlib import Path

def write_report(result, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result.as_dict(), indent=2), encoding="utf-8")
