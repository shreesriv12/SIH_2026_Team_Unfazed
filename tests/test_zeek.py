from pathlib import Path
from unittest.mock import patch

from core.zeek import engine, load_json_logs

def test_no_zeek_logs_in_test_directory():
    assert load_json_logs(Path("tests")) == {}


def test_missing_zeek_and_docker_is_optional():
    with patch("core.zeek.shutil.which", return_value=None):
        assert engine() is None
