from __future__ import annotations

import os
from pathlib import Path

from fastapi import HTTPException, UploadFile
from config import settings

ALLOWED_SUFFIXES = {".pcap", ".pcapng", ".cap"}
MAX_CAPTURE_BYTES = settings.max_upload_bytes
READ_CHUNK_BYTES = 1024 * 1024
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",  # microsecond PCAP
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",  # nanosecond PCAP
    b"\x0a\x0d\x0d\x0a",                          # PCAPNG
}
ARCHIVE_MAGICS = (b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c", b"Rar!")


def validate_capture_name(filename: str | None) -> str:
    if not filename or Path(filename).suffix.lower() not in ALLOWED_SUFFIXES:
        raise HTTPException(400, "Upload a .pcap, .pcapng, or .cap capture.")
    return Path(filename).suffix.lower()


def validate_capture_content(content: bytes) -> None:
    if content.startswith(ARCHIVE_MAGICS):
        raise HTTPException(415, "Compressed or archived captures are not accepted; upload the raw PCAP/PCAPNG file.")
    if len(content) < 24:
        raise HTTPException(422, "Capture is empty or too short to contain a valid header.")
    if content[:4] not in PCAP_MAGICS:
        raise HTTPException(422, "File content is not a supported PCAP or PCAPNG capture.")


async def read_capture(upload: UploadFile) -> tuple[bytes, str]:
    suffix = validate_capture_name(upload.filename)
    chunks: list[bytes] = []
    total = 0
    while chunk := await upload.read(READ_CHUNK_BYTES):
        total += len(chunk)
        if total > MAX_CAPTURE_BYTES:
            raise HTTPException(413, f"Capture exceeds the {MAX_CAPTURE_BYTES // (1024 * 1024)} MB limit.")
        chunks.append(chunk)
    content = b"".join(chunks)
    validate_capture_content(content)
    return content, suffix
