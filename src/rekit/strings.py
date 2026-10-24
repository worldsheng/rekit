"""String extraction: ASCII, UTF-16LE, and UTF-8 (CJK).

The point of doing this by hand instead of calling `strings.exe` is that we keep
offsets, so the output can be correlated with disassembly addresses later.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_ASCII_CACHE: dict[int, re.Pattern] = {}


@dataclass
class Found:
    offset: int
    kind: str
    text: str

    def __str__(self) -> str:
        return f"{self.offset:08x}  {self.kind:<8}  {self.text}"


def _ascii_re(min_len: int) -> re.Pattern:
    if min_len not in _ASCII_CACHE:
        _ASCII_CACHE[min_len] = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    return _ASCII_CACHE[min_len]


def ascii_strings(data: bytes, min_len: int = 4) -> list[Found]:
    out = []
    for m in _ascii_re(min_len).finditer(data):
        out.append(Found(m.start(), "ascii", m.group().decode("ascii")))
    return out


def _is_wide_printable(code: int) -> bool:
    if 0x20 <= code <= 0x7E:          # BASIC LATIN
        return True
    if 0x4E00 <= code <= 0x9FFF:      # CJK Unified Ideographs
        return True
    if 0x3000 <= code <= 0x303F:      # CJK punctuation
        return True
    if 0x3040 <= code <= 0x30FF:      # Hiragana / Katakana
        return True
    if 0xAC00 <= code <= 0xD7AF:      # Hangul
        return True
    if code in (0x09, 0x0A, 0x0D):
        return True
    return False


def utf16_strings(data: bytes, min_len: int = 4) -> list[Found]:
    out: list[Found] = []
    buf: list[str] = []
    start = 0
    i = 0
    n = len(data) - 1
    while i < n:
        code = data[i] | (data[i + 1] << 8)
        if _is_wide_printable(code):
            if not buf:
                start = i
            buf.append(chr(code))
            i += 2
            continue
        if len(buf) >= min_len:
            out.append(Found(start, "utf16le", "".join(buf)))
        buf = []
        i += 2
    if len(buf) >= min_len:
        out.append(Found(start, "utf16le", "".join(buf)))
    return out


_UTF8_CJK = re.compile(
    rb"(?:[\xe4-\xe9][\x80-\xbf][\x80-\xbf]|[\x20-\x7e]){%d,}" % 2
)


def utf8_strings(data: bytes, min_len: int = 4) -> list[Found]:
    """Catch UTF-8 CJK runs that plain ASCII scanning misses."""
    out = []
    for m in _UTF8_CJK.finditer(data):
        raw = m.group()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if len(text) < min_len:
            continue
        # Skip if it is pure ASCII, ascii_strings already covers it.
        if all(ord(c) < 0x80 for c in text):
            continue
        out.append(Found(m.start(), "utf8", text))
    return out


def extract(data: bytes, min_len: int = 4, kinds: tuple[str, ...] = ("ascii", "utf16le", "utf8")) -> list[Found]:
    found: list[Found] = []
    if "ascii" in kinds:
        found += ascii_strings(data, min_len)
    if "utf16le" in kinds:
        found += utf16_strings(data, min_len)
    if "utf8" in kinds:
        found += utf8_strings(data, min_len)
    found.sort(key=lambda f: f.offset)
    return found
