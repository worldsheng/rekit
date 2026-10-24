"""Self test: builds synthetic files in memory, then asserts every module.

Run:  python tests/selftest.py
Exit code 0 means every check passed.
"""

from __future__ import annotations

import io
import os
import struct
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from rekit import entropy, formats, pe as pe_mod, strings as strings_mod, xor as xor_mod  # noqa: E402
from rekit.cli import main as cli_main  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}  {detail}")


def build_pe(with_imports: bool = True, upx: bool = False) -> bytes:
    """Hand-assemble a minimal but structurally valid PE32."""
    size = 0x600
    buf = bytearray(size)

    # --- DOS header ---
    buf[0:2] = b"MZ"
    struct.pack_into("<H", buf, 0x02, 0x90)       # e_cblp
    struct.pack_into("<H", buf, 0x04, 0x03)       # e_cp
    struct.pack_into("<I", buf, 0x3C, 0x40)       # e_lfanew

    # --- PE signature + COFF header ---
    buf[0x40:0x44] = b"PE\x00\x00"
    coff = 0x44
    struct.pack_into("<H", buf, coff + 0, 0x014C)   # i386
    struct.pack_into("<H", buf, coff + 2, 2)        # 2 sections
    struct.pack_into("<I", buf, coff + 4, 0x5F5E1000)
    struct.pack_into("<I", buf, coff + 8, 0)        # no symbols
    struct.pack_into("<I", buf, coff + 12, 0)
    struct.pack_into("<H", buf, coff + 16, 0xE0)    # optional header size
    struct.pack_into("<H", buf, coff + 18, 0x0102)  # executable, 32-bit

    # --- Optional header (PE32, 0xE0 bytes) ---
    opt = coff + 20
    struct.pack_into("<H", buf, opt + 0, 0x10B)      # magic
    buf[opt + 2] = 14                                # linker major
    buf[opt + 3] = 0                                 # linker minor
    struct.pack_into("<I", buf, opt + 16, 0x1000)    # AddressOfEntryPoint
    struct.pack_into("<I", buf, opt + 20, 0x1000)    # BaseOfCode
    struct.pack_into("<I", buf, opt + 24, 0x2000)    # BaseOfData
    struct.pack_into("<I", buf, opt + 28, 0x400000)  # ImageBase
    struct.pack_into("<I", buf, opt + 32, 0x1000)    # SectionAlignment
    struct.pack_into("<I", buf, opt + 36, 0x200)     # FileAlignment
    struct.pack_into("<H", buf, opt + 40, 6)         # MajorOperatingSystemVersion
    struct.pack_into("<H", buf, opt + 42, 0)         # MinorOperatingSystemVersion
    struct.pack_into("<H", buf, opt + 44, 0)         # MajorImageVersion
    struct.pack_into("<H", buf, opt + 46, 0)         # MinorImageVersion
    struct.pack_into("<H", buf, opt + 48, 6)         # MajorSubsystemVersion
    struct.pack_into("<H", buf, opt + 50, 0)         # MinorSubsystemVersion
    struct.pack_into("<I", buf, opt + 52, 0)         # Win32VersionValue
    struct.pack_into("<I", buf, opt + 56, 0x4000)    # SizeOfImage
    struct.pack_into("<I", buf, opt + 60, 0x200)     # SizeOfHeaders
    struct.pack_into("<I", buf, opt + 64, 0)         # CheckSum
    struct.pack_into("<H", buf, opt + 68, 3)         # Subsystem = WINDOWS_CUI
    struct.pack_into("<H", buf, opt + 70, 0)         # DllCharacteristics
    struct.pack_into("<I", buf, opt + 72, 0x100000)  # SizeOfStackReserve
    struct.pack_into("<I", buf, opt + 76, 0x1000)    # SizeOfStackCommit
    struct.pack_into("<I", buf, opt + 80, 0x100000)  # SizeOfHeapReserve
    struct.pack_into("<I", buf, opt + 84, 0x1000)    # SizeOfHeapCommit
    struct.pack_into("<I", buf, opt + 88, 0)         # LoaderFlags
    struct.pack_into("<I", buf, opt + 92, 16)        # NumberOfRvaAndSizes
    if with_imports:
        struct.pack_into("<II", buf, opt + 96 + 8, 0x2000, 40)  # import directory

    # --- Section headers ---
    sh = opt + 0xE0
    text_name = b"UPX1\x00\x00\x00\x00" if upx else b".text\x00\x00\x00"
    buf[sh:sh + 8] = text_name
    struct.pack_into("<IIII", buf, sh + 8, 0x1000, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", buf, sh + 36, 0x60000020)  # CODE|EXEC|READ

    idata_off = sh + 40
    buf[idata_off:idata_off + 8] = b"UPX0\x00\x00\x00\x00" if upx else b".idata\x00\x00"
    struct.pack_into("<IIII", buf, idata_off + 8, 0x1000, 0x2000, 0x200, 0x400)
    struct.pack_into("<I", buf, idata_off + 36, 0x40000040)  # IDATA|READ

    # --- Section bodies ---
    buf[0x200:0x210] = b"\x55\x8b\xec\x33\xc0\x5d\xc3" + b"\x00" * 9

    if with_imports:
        base = 0x400  # file offset == RVA 0x2000

        def w(off: int, fmt: str, *vals) -> None:
            struct.pack_into(fmt, buf, base + off, *vals)

        # descriptor 1
        w(0x000, "<IIIII", 0x2040, 0, 0, 0x2030, 0x2048)
        # descriptor 2 = null terminator (already zero)
        # dll name
        name = b"KERNEL32.dll\x00"
        buf[base + 0x30:base + 0x30 + len(name)] = name
        # INT + IAT, one entry each
        w(0x40, "<II", 0x2058, 0)
        w(0x48, "<II", 0x2058, 0)
        # hint/name
        buf[base + 0x58:base + 0x5A] = b"\x00\x00"
        buf[base + 0x5A:base + 0x5A + 12] = b"ExitProcess\x00"

    return bytes(buf)


def test_entropy() -> None:
    print("\n[entropy]")
    check("zeros -> 0 bits", entropy.shannon(b"\x00" * 4096) == 0.0)
    check("uniform bytes -> ~8 bits", 7.9 < entropy.shannon(bytes(range(256)) * 16) <= 8.0)
    check("rating picks packed", entropy.rating(7.5) == "packed/compressed")
    check("rating picks plain", entropy.rating(5.9) == "plain")


def test_strings() -> None:
    print("\n[strings]")
    blob = b"\x00\x00Hello World\x00" + "宽字符测试".encode("utf-16le") + b"\x00\x00"
    found = strings_mod.extract(blob, min_len=4)
    texts = [f.text for f in found]
    check("finds ascii string", "Hello World" in texts, str(texts))
    check("finds utf16 cjk", any("宽字符" in t for t in texts), str(texts))
    offsets_ok = all(0 <= f.offset < len(blob) for f in found)
    check("offsets in range", offsets_ok)

    ascii_only = strings_mod.extract(b"abcd\x00efgh", min_len=4, kinds=("ascii",))
    check("min_len filters", [f.text for f in ascii_only] == ["abcd", "efgh"],
          str([f.text for f in ascii_only]))


def test_formats() -> None:
    print("\n[formats]")
    check("pe detected", formats.identify(build_pe()).name == "PE")
    check("mz without pe", formats.identify(b"MZ" + b"\x00" * 100).name == "DOS/MZ")
    check("elf detected", formats.identify(b"\x7fELF\x02\x01\x01" + b"\x00" * 100).name == "ELF")
    check("pdf detected", formats.identify(b"%PDF-1.7\n...").name == "PDF")
    check("gzip detected", formats.identify(b"\x1f\x8b\x08\x00" + b"\x00" * 20).name == "gzip")
    check("unknown detected", formats.identify(b"\x01\x02\x03\x04\x05").name == "unknown")

    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest/>")
    check("apk detected", formats.identify(buf.getvalue()).name == "APK")


def test_pe() -> None:
    print("\n[pe]")
    data = build_pe(with_imports=True)
    info = pe_mod.parse(data)

    check("machine x86", info["machine"] == "x86", info["machine"])
    check("not pe32+", info["pe32plus"] is False)
    check("entry rva", info["entry_point_rva"] == 0x1000, hex(info["entry_point_rva"]))
    check("two sections", info["number_of_sections"] == 2)
    check("section name", info["sections"][0]["name"] == ".text", info["sections"][0]["name"])
    check("text is executable", "EXEC" in info["sections"][0]["flags"], str(info["sections"][0]["flags"]))
    check("subsystem cui", info["subsystem"] == "WINDOWS_CUI", info["subsystem"])
    check("imports parsed", info["imports"].get("KERNEL32.dll") == ["ExitProcess"],
          str(info["imports"]))
    check("timestamp converted", info["timestamp_iso"].startswith("2020-09"),
          info["timestamp_iso"])

    # An UPX-looking file must score much higher than the same file without it.
    upx_info = pe_mod.parse(build_pe(with_imports=True, upx=True))
    labels = [f["label"] for f in upx_info["findings"]]
    check("upx detected", "packer-section" in labels, str(labels))
    check("upx score higher", upx_info["packer_score"] > info["packer_score"],
          f"{upx_info['packer_score']} vs {info['packer_score']}")

    # A file with no imports at all should be flagged.
    no_imp = pe_mod.parse(build_pe(with_imports=False))
    check("missing imports flagged", "no-imports" in [f["label"] for f in no_imp["findings"]])

    # Garbage in, exception out, not a crash.
    try:
        pe_mod.parse(b"not a pe at all" * 20)
        check("rejects garbage", False)
    except pe_mod.PEError:
        check("rejects garbage", True)


def test_xor() -> None:
    print("\n[xor]")
    plaintext = b"This program cannot be run in DOS mode. http://example.com/api"
    key = 0x5A
    cipher = bytes(b ^ key for b in plaintext)
    cands = xor_mod.brute_single_byte(cipher)
    check("brute finds key", bool(cands) and cands[0].key == key,
          str([(c.key, c.score) for c in cands[:3]]))

    multi_plain = b"This program cannot be run. http://a.b/c?token=deadbeef"
    mkey = bytes.fromhex("deadbeef")
    mcipher = xor_mod.apply_key(multi_plain, mkey)
    cribbed = xor_mod.crib_attack(mcipher, b"This program")
    check("crib recovers multi-byte key",
          bool(cribbed) and cribbed[0].key == mkey,
          str([c.key.hex() if isinstance(c.key, bytes) else c.key for c in cribbed[:3]]))

    roundtrip = xor_mod.apply_key(xor_mod.apply_key(plaintext, mkey), mkey)
    check("apply_key roundtrip", roundtrip == plaintext)


def test_cli() -> None:
    print("\n[cli]")
    pe_bytes = build_pe(with_imports=True)
    xor_bytes = bytes(b ^ 0x33 for b in b"This program is fine. https://x.y/z")

    tmp = tempfile.mkdtemp(prefix="rekit-selftest-")
    pe_path = os.path.join(tmp, "sample.exe")
    xor_path = os.path.join(tmp, "blob.bin")
    with open(pe_path, "wb") as fh:
        fh.write(pe_bytes)
    with open(xor_path, "wb") as fh:
        fh.write(xor_bytes)

    def run(argv: list[str]) -> tuple[int, str]:
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            code = cli_main(argv)
        finally:
            sys.stdout = old
        return code, buf.getvalue()

    code, out = run(["info", pe_path])
    check("cli info exit 0", code == 0, str(code))
    check("cli info says PE", "PE" in out, out[:200])

    code, out = run(["pe", pe_path, "--imports"])
    check("cli pe exit 0", code == 0)
    check("cli pe lists import", "ExitProcess" in out, out[:300])
    check("cli pe shows sections", ".text" in out and ".idata" in out)

    code, out = run(["strings", pe_path, "--grep", "kernel"])
    check("cli strings grep", "KERNEL32.dll" in out, out[:200])

    code, out = run(["xor", xor_path])
    check("cli xor exit 0", code == 0)
    check("cli xor finds 0x33", "key=0x33" in out, out[:200])

    code, out = run(["scan", tmp])
    check("cli scan exit 0", code == 0)
    check("cli scan sees one pe", "sample.exe" in out, out[:300])

    code, out = run(["hash", pe_path])
    check("cli hash exit 0", code == 0 and "sha256" in out)

    code, out = run(["pe", xor_path])
    check("cli pe rejects non-pe", code == 2, str(code))


def main() -> int:
    print("rekit selftest")
    test_entropy()
    test_strings()
    test_formats()
    test_pe()
    test_xor()
    test_cli()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
