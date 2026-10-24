"""File format identification by magic bytes, then by structure.

Deliberately no `file` / `libmagic` dependency: this has to run on a bare
Windows box with nothing installed.
"""

from __future__ import annotations

import io
import struct
import zipfile
from dataclasses import dataclass


@dataclass
class Format:
    name: str
    detail: str = ""
    confidence: str = "high"   # high | medium | low

    def __str__(self) -> str:
        return f"{self.name} ({self.detail})" if self.detail else self.name


MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce": ("Mach-O", "32-bit big-endian"),
    b"\xfe\xed\xfa\xcf": ("Mach-O", "64-bit big-endian"),
    b"\xce\xfa\xed\xfe": ("Mach-O", "32-bit little-endian"),
    b"\xcf\xfa\xed\xfe": ("Mach-O", "64-bit little-endian"),
}


def _zip_kind(data: bytes) -> Format:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
    except Exception:
        return Format("ZIP", "unreadable central directory", "low")

    if any(n == "AndroidManifest.xml" for n in names):
        return Format("APK", "android package", "high")
    if any(n.startswith("classes") and n.endswith(".dex") for n in names):
        return Format("JAR/DEX", "java archive", "high")
    if "META-INF/MANIFEST.MF" in names:
        return Format("JAR", "java archive", "high")
    if any(n == "[Content_Types].xml" for n in names):
        if any("word/" in n for n in names):
            return Format("DOCX", "office open xml", "high")
        if any("xl/" in n for n in names):
            return Format("XLSX", "office open xml", "high")
        if any("ppt/" in n for n in names):
            return Format("PPTX", "office open xml", "high")
        return Format("OOXML", "office open xml", "medium")
    if any(n.endswith(".app/") or n.startswith("Payload/") for n in names):
        return Format("IPA", "ios app package", "high")
    return Format("ZIP", f"{len(names)} entries", "high")


def identify(data: bytes, path: str = "") -> Format:
    if len(data) < 2:
        return Format("empty", "file too small", "low")

    if data[:2] == b"MZ":
        if len(data) > 0x40:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if 0 <= e_lfanew <= len(data) - 4 and data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
                return Format("PE", "windows executable", "high")
        return Format("DOS/MZ", "MZ header without PE signature", "medium")

    if data[:4] == b"\x7fELF":
        cls = {1: "32-bit", 2: "64-bit"}.get(data[4] if len(data) > 4 else 0, "?")
        endian = {1: "little-endian", 2: "big-endian"}.get(data[5] if len(data) > 5 else 0, "?")
        etype = {1: "relocatable", 2: "executable", 3: "shared object", 4: "core"}.get(
            struct.unpack_from("<H", data, 16)[0] if len(data) >= 18 else 0, "?"
        )
        return Format("ELF", f"{cls} {endian} {etype}", "high")

    head = data[:4]
    if head in MACHO_MAGICS:
        name, detail = MACHO_MAGICS[head]
        return Format(name, detail, "high")

    # 0xCAFEBABE is shared by Java class files and Mach-O fat binaries.
    if head == b"\xca\xfe\xba\xbe" and len(data) >= 8:
        nfat = struct.unpack_from(">I", data, 4)[0]
        if 1 <= nfat <= 16:
            return Format("Mach-O", f"universal binary, {nfat} archs", "high")
        major = struct.unpack_from(">H", data, 6)[0]
        return Format("Java class", f"major version {major - 44}", "high")

    if head[:4] == b"PK\x03\x04":
        return _zip_kind(data)
    if head[:4] == b"PK\x05\x06":
        return Format("ZIP", "empty archive", "high")

    if data[:5] == b"%PDF-":
        return Format("PDF", data[5:8].decode("latin-1", "replace"), "high")
    if head == b"\xd0\xcf\x11\xe0":
        return Format("OLE2", "legacy office / msi container", "high")
    if head[:3] == b"Rar":
        return Format("RAR", "archive", "high")
    if head == b"7z\xbc\xaf\x27\x1c":
        return Format("7z", "archive", "high")
    if head[:2] == b"\x1f\x8b":
        return Format("gzip", "compressed", "high")
    if head[:3] == b"BZh":
        return Format("bzip2", "compressed", "high")
    if head == b"\xfd7zXZ\x00":
        return Format("xz", "compressed", "high")
    if head == b"\x89PNG":
        return Format("PNG", "image", "high")
    if head[:3] == b"\xff\xd8\xff":
        return Format("JPEG", "image", "high")
    if head[:4] == b"GIF8":
        return Format("GIF", "image", "high")
    if head[:4] == b"dex\n":
        return Format("DEX", "android dalvik bytecode", "high")
    if head[:4] == b"\x03\x00\x08\x00":
        return Format("DEX", "android odex guess", "low")

    # Source / script sniffing based on the first printable line.
    head_text = data[:512].decode("latin-1", "replace").lstrip()
    if head_text.startswith("#!"):
        line = head_text.splitlines()[0]
        return Format("script", line[:80], "high")
    for opener, name in (
        ("<?xml", "XML"),
        ("<?php", "PHP"),
        ("<html", "HTML"),
        ("<!DOCTYPE html", "HTML"),
        ("{\\rtf", "RTF"),
        ("function ", "JavaScript?"),
    ):
        if head_text.lower().startswith(opener.lower()):
            return Format(name, "", "medium")

    if path.lower().endswith((".py", ".js", ".ts", ".go", ".rs", ".c", ".cpp", ".java")):
        return Format("source", path.rsplit(".", 1)[-1], "low")

    printable = sum(1 for b in data[:512] if 0x20 <= b < 0x7F or b in (9, 10, 13))
    if data and printable / min(len(data), 512) > 0.9:
        return Format("text", "printable ASCII", "medium")

    return Format("unknown", "no known signature", "low")
