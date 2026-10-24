"""Small helpers shared by every module."""

from __future__ import annotations

import hashlib
import os
from typing import Iterator

PRINTABLE = bytes(range(0x20, 0x7F)) + b"\t\r\n"


def read_file(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are plain ASCII printable / whitespace."""
    if not data:
        return 0.0
    hits = sum(1 for b in data if b in PRINTABLE)
    return hits / len(data)


def iter_chunks(data: bytes, size: int) -> Iterator[bytes]:
    for i in range(0, len(data), size):
        yield data[i:i + size]


def cstr(data: bytes, off: int | None, limit: int = 512) -> str:
    """Read a NUL-terminated ASCII string, tolerating junk."""
    if off is None or off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off, min(len(data), off + limit))
    if end < 0:
        end = min(len(data), off + limit)
    raw = data[off:end]
    return raw.decode("latin-1", errors="replace")


def hexdump(data: bytes, base: int = 0, limit: int = 4096, width: int = 16) -> str:
    lines = []
    view = data[:limit]
    for i in range(0, len(view), width):
        chunk = view[i:i + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        hexpart = hexpart.ljust(width * 3 - 1)
        text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{base + i:08x}  {hexpart}  |{text}|")
    if len(data) > limit:
        lines.append(f"... ({len(data) - limit} more bytes)")
    return "\n".join(lines)


def human_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    val = float(n)
    for unit in units:
        if val < 1024 or unit == units[-1]:
            return f"{val:.1f}{unit}" if unit != "B" else f"{int(val)}B"
        val /= 1024
    return f"{n}B"


def iter_files(root: str) -> Iterator[str]:
    """Walk a directory (or yield a single file), skipping huge trees quietly."""
    if os.path.isfile(root):
        yield root
        return
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            yield os.path.join(dirpath, name)
