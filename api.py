from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from core.analyzer import analyze_pcap

app = FastAPI(title="SecureMailScope API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"], allow_methods=["*"], allow_headers=["*"])

@app.get("/api/health")
def health() -> dict[str, str]: return {"status": "ok", "engine": "TShark"}

@app.post("/api/analyse")
async def analyse(file: UploadFile = File(...)) -> dict:
    if not file.filename or Path(file.filename).suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
        raise HTTPException(400, "Upload a .pcap, .pcapng, or .cap capture.")
    content = await file.read()
    if len(content) > 50 * 1024 * 1024: raise HTTPException(413, "Capture exceeds the 50 MB v0.1 limit.")
    with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.filename).suffix) as temp:
        temp.write(content); path = Path(temp.name)
    try:
        result = analyze_pcap(path).as_dict()
        result["file"] = file.filename
        result["sha256"] = hashlib.sha256(content).hexdigest()
        return result
    except Exception as error: raise HTTPException(422, str(error)) from error
    finally: os.unlink(path)
