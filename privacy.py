from __future__ import annotations
import re
from typing import Any
EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
SECRET = re.compile(r"(?i)(password|authorization|token)\s*[:=]\s*[^\s,;]+")
def redact(value: Any) -> Any:
    if isinstance(value, str): return SECRET.sub(lambda match: match.group(1) + "=[REDACTED]", EMAIL.sub("[REDACTED_EMAIL]", value))
    if isinstance(value, list): return [redact(item) for item in value]
    if isinstance(value, dict): return {key: redact(item) for key, item in value.items()}
    return value
