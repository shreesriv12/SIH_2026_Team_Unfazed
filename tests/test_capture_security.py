import pytest
from fastapi import HTTPException

from capture_security import validate_capture_content, validate_capture_name


def test_capture_extension_is_required():
    with pytest.raises(HTTPException) as error:
        validate_capture_name("notes.txt")
    assert error.value.status_code == 400


def test_fake_capture_content_is_rejected():
    with pytest.raises(HTTPException) as error:
        validate_capture_content(b"this is not really a packet capture")
    assert error.value.status_code == 422


def test_archives_are_rejected_without_decompression():
    with pytest.raises(HTTPException) as error:
        validate_capture_content(b"PK\x03\x04" + b"x" * 32)
    assert error.value.status_code == 415


@pytest.mark.parametrize("magic", [b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"])
def test_supported_capture_headers_are_accepted(magic):
    validate_capture_content(magic + bytes(24))
