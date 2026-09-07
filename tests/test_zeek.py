from pathlib import Path
from core.zeek import load_json_logs

def test_no_zeek_logs_in_test_directory():
    assert load_json_logs(Path("tests")) == {}
