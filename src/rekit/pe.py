"""PE (Portable Executable) parser - pure Python, no pefile.

Scope: headers, sections, data directories, imports, exports, Rich header,
TLS callbacks, and a packer heuristics pass. That is the part of PE analysis
that actually decides "what am I looking at" in the first 30 seconds.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone

from .entropy import rating, shannon, SUSPICIOUS
from .util import cstr


class PEError(ValueError):
    pass


MACHINES = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
    0x0200: "IA64",
    0x01F0: "PowerPC",
    0x0EBC: "EFI bytecode",
}

SUBSYSTEMS = {
    1: "NATIVE",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI",
    5: "OS2_CUI",
    7: "POSIX_CUI",
    9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION",
    11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER",
    13: "EFI_ROM",
    14: "XBOX",
    16: "WINDOWS_BOOT_APPLICATION",
}

SECTION_FLAGS = {
    0x00000020: "CODE",
    0x00000040: "IDATA",
    0x00000080: "UDATA",
    0x02000000: "DISCARDABLE",
    0x04000000: "NOT_CACHED",
    0x08000000: "NOT_PAGED",
    0x10000000: "SHARED",
    0x20000000: "EXEC",
    0x40000000: "READ",
    0x80000000: "WRITE",
}

# Section names that give the packer away immediately.
PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", "upx!": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack", ".asdata": "ASPack",
    ".themida": "Themida", ".winlice": "Themida", ".boot": "Themida",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".enigma1": "Enigma", ".enigma2": "Enigma",
    "mpress1": "MPRESS", "mpress2": "MPRESS",
    ".petite": "Petite", "pec2": "PECompact", "pec1": "PECompact",
    ".y0da": "Y0da", ".y0da2": "Y0da",
    ".packed": "generic packer", ".rlpack": "RLPack",
    ".nsp0": "NsPack", ".nsp1": "NsPack", "nsp0": "NsPack",
    ".perplex": "Perplex", ".spack": "Simple Pack",
}

DIRECTORY_NAMES = [
    "export", "import", "resource", "exception", "security", "basereloc",
    "debug", "architecture", "globalptr", "tls", "loadconfig",
    "boundimport", "iat", "delayimport", "clr", "reserved",
]

# Exports/DLL names worth flagging when present.
SENSITIVE_IMPORTS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "CreateRemoteThreadEx", "NtCreateThreadEx", "QueueUserAPC",
    "SetThreadContext", "GetThreadContext", "OpenProcess",
    "AdjustTokenPrivileges", "LookupPrivilegeValueA", "LookupPrivilegeValueW",
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "OutputDebugStringA", "OutputDebugStringW",
    "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
    "Thread32First", "Module32First",
    "SetWindowsHookExA", "SetWindowsHookExW",
    "GetAsyncKeyState", "GetKeyboardState", "MapVirtualKeyA",
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContextA",
    "InternetOpenA", "InternetOpenW", "InternetReadFile", "URLDownloadToFileA",
    "WinHttpOpen", "WinHttpSendRequest", "HttpSendRequestA",
    "RegSetValueExA", "RegSetValueExW", "CreateServiceA", "CreateServiceW",
    "ShellExecuteA", "ShellExecuteW", "WinExec", "CreateProcessA", "CreateProcessW",
}


def _unpack(fmt: str, data: bytes, off: int, default=None):
    try:
        return struct.unpack_from(fmt, data, off)[0]
    except struct.error:
        return default


def rva_to_offset(sections: list[dict], rva: int) -> int | None:
    for sec in sections:
        start = sec["virtual_address"]
        span = max(sec["virtual_size"], sec["raw_size"])
        if start <= rva < start + span:
            delta = rva - start
            if delta < sec["raw_size"]:
                return sec["raw_ptr"] + delta
            return None
    return None


def _parse_sections(data: bytes, table_off: int, count: int) -> list[dict]:
    sections = []
    for i in range(count):
        off = table_off + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].rstrip(b"\x00")
        name_s = name.decode("latin-1", "replace")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
        chars = struct.unpack_from("<I", data, off + 36)[0]
        raw = data[rptr:rptr + rsize] if rsize and rptr < len(data) else b""
        flags = [label for bit, label in SECTION_FLAGS.items() if chars & bit]
        sections.append({
            "name": name_s,
            "virtual_address": vaddr,
            "virtual_size": vsize,
            "raw_size": rsize,
            "raw_ptr": rptr,
            "characteristics": chars,
            "flags": flags,
            "entropy": round(shannon(raw), 3) if raw else 0.0,
            "entropy_rating": rating(shannon(raw)) if raw else "empty",
        })
    return sections


def _parse_imports(data: bytes, sections: list[dict], dir_rva: int, is64: bool) -> dict[str, list[str]]:
    imports: dict[str, list[str]] = {}
    if not dir_rva:
        return imports
    off = rva_to_offset(sections, dir_rva)
    step = 8 if is64 else 4
    fmt = "<Q" if is64 else "<I"
    high_bit = 1 << 63 if is64 else 1 << 31
    guard = 0
    while off is not None and off + 20 <= len(data) and guard < 4096:
        guard += 1
        oft, _ts, _fc, name_rva, ft = struct.unpack_from("<IIIII", data, off)
        if not (oft or name_rva or ft):
            break
        dll_off = rva_to_offset(sections, name_rva)
        dll = cstr(data, dll_off) or f"<rva 0x{name_rva:x}>"
        thunk_rva = oft or ft
        thunk_off = rva_to_offset(sections, thunk_rva)
        names: list[str] = []
        tguard = 0
        while thunk_off is not None and thunk_off + step <= len(data) and tguard < 8192:
            tguard += 1
            val = struct.unpack_from(fmt, data, thunk_off)[0]
            if val == 0:
                break
            if val & high_bit:
                names.append(f"ord#{val & 0xFFFF}")
            else:
                import_rva = val & 0x7FFFFFFF
                ioff = rva_to_offset(sections, import_rva)
                if ioff is not None and ioff + 2 < len(data):
                    names.append(cstr(data, ioff + 2))
                else:
                    names.append(f"<bad rva 0x{import_rva:x}>")
            thunk_off += step
        imports[dll] = names
        off += 20
    return imports


def _parse_exports(data: bytes, sections: list[dict], dir_rva: int) -> tuple[str, list[str]]:
    names: list[str] = []
    dll_name = ""
    if not dir_rva:
        return dll_name, names
    off = rva_to_offset(sections, dir_rva)
    if off is None or off + 40 > len(data):
        return dll_name, names
    (_chars, _ts, _maj, _min, name_rva, _base, nfuncs, nnames,
     addr_funcs, addr_names, addr_ords) = struct.unpack_from("<IIHHIIIIIII", data, off)
    dll_name = cstr(data, rva_to_offset(sections, name_rva))
    names_off = rva_to_offset(sections, addr_names)
    if names_off is None:
        return dll_name, names
    for i in range(min(nnames, 4096)):
        entry = names_off + i * 4
        if entry + 4 > len(data):
            break
        nrva = struct.unpack_from("<I", data, entry)[0]
        nm = cstr(data, rva_to_offset(sections, nrva))
        if nm:
            names.append(nm)
    return dll_name, names


def _parse_tls(data: bytes, sections: list[dict], dir_rva: int, image_base: int, is64: bool) -> dict:
    info = {"present": False, "callbacks": []}
    if not dir_rva:
        return info
    off = rva_to_offset(sections, dir_rva)
    if off is None:
        return info
    info["present"] = True
    if is64:
        cb_va = _unpack("<Q", data, off + 24)
        size = 40
    else:
        cb_va = _unpack("<I", data, off + 12)
        size = 24
    info["callback_array_va"] = cb_va
    info["struct_size"] = size
    if cb_va:
        rva = cb_va - image_base
        cb_off = rva_to_offset(sections, rva)
        guard = 0
        step = 8 if is64 else 4
        fmt = "<Q" if is64 else "<I"
        while cb_off is not None and cb_off + step <= len(data) and guard < 64:
            guard += 1
            addr = struct.unpack_from(fmt, data, cb_off)[0]
            if addr == 0:
                break
            info["callbacks"].append(addr)
            cb_off += step
    return info


def _parse_rich(data: bytes, e_lfanew: int) -> dict | None:
    idx = data.find(b"Rich", 0x40, max(0x40, e_lfanew))
    if idx < 0:
        return None
    key = _unpack("<I", data, idx + 4)
    if key is None:
        return None
    # Walk backwards to find the encoded "DanS" marker.
    start = None
    probe = idx - 4
    limit = max(0, idx - 0x400)
    while probe >= limit:
        val = _unpack("<I", data, probe)
        if val is not None and (val ^ key) == 0x536E6144:  # 'DanS'
            start = probe
            break
        probe -= 4
    if start is None:
        return {"key": key, "offset": idx, "entries": [], "complete": False}
    entries = []
    pos = start + 16
    while pos + 8 <= idx:
        comp_id = _unpack("<I", data, pos)
        count = _unpack("<I", data, pos + 4)
        if comp_id is None or count is None:
            break
        comp_id ^= key
        count ^= key
        prod = (comp_id >> 16) & 0xFFFF
        build = comp_id & 0xFFFF
        entries.append({"product_id": prod, "build": build, "count": count})
        pos += 8
    return {"key": key, "offset": idx, "entries": entries, "complete": True}


def parse(data: bytes) -> dict:
    if len(data) < 0x40:
        raise PEError("file smaller than a DOS header")
    if data[:2] != b"MZ":
        raise PEError("missing MZ signature")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 0x18 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise PEError(f"no PE signature at 0x{e_lfanew:x}")

    coff_off = e_lfanew + 4
    (machine, nsections, timestamp, _symptr, _nsyms,
     size_opt, characteristics) = struct.unpack_from("<HHIIIHH", data, coff_off)
    opt_off = coff_off + 20
    magic = _unpack("<H", data, opt_off)
    if magic not in (0x10B, 0x20B):
        raise PEError(f"unexpected optional header magic 0x{magic:x}")
    is64 = magic == 0x20B

    entry = _unpack("<I", data, opt_off + 16) or 0
    # PE32+ drops BaseOfData, so ImageBase moves from +28 to +24.
    image_base = _unpack("<Q" if is64 else "<I", data, opt_off + (24 if is64 else 28)) or 0
    section_align = _unpack("<I", data, opt_off + 32) or 0
    file_align = _unpack("<I", data, opt_off + 36) or 0
    size_image = _unpack("<I", data, opt_off + 56) or 0
    size_headers = _unpack("<I", data, opt_off + 60) or 0
    subsystem = _unpack("<H", data, opt_off + 68) or 0
    dll_chars = _unpack("<H", data, opt_off + 70) or 0
    num_dirs = _unpack("<I", data, opt_off + (108 if is64 else 92)) or 0
    dirs_off = opt_off + (112 if is64 else 96)

    directories = []
    for i in range(min(num_dirs, 16)):
        rva = _unpack("<I", data, dirs_off + i * 8)
        size = _unpack("<I", data, dirs_off + i * 8 + 4)
        if rva is None:
            break
        directories.append({
            "index": i,
            "name": DIRECTORY_NAMES[i],
            "rva": rva,
            "size": size,
            "present": bool(rva),
        })

    sections = _parse_sections(data, opt_off + size_opt, nsections)

    def dir_rva(name: str) -> int:
        for d in directories:
            if d["name"] == name:
                return d["rva"]
        return 0

    imports = _parse_imports(data, sections, dir_rva("import"), is64)
    export_name, exports = _parse_exports(data, sections, dir_rva("export"))
    tls = _parse_tls(data, sections, dir_rva("tls"), image_base, is64)
    rich = _parse_rich(data, e_lfanew)

    ts_iso = ""
    if 0 < timestamp < 0x7FFFFFFF:
        try:
            ts_iso = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OverflowError, OSError, ValueError):
            ts_iso = "invalid"

    result = {
        "machine": MACHINES.get(machine, f"0x{machine:04x}"),
        "machine_raw": machine,
        "pe32plus": is64,
        "characteristics": characteristics,
        "is_dll": bool(characteristics & 0x2000),
        "is_driver": subsystem == 1,
        "timestamp": timestamp,
        "timestamp_iso": ts_iso,
        "entry_point_rva": entry,
        "image_base": image_base,
        "section_alignment": section_align,
        "file_alignment": file_align,
        "size_of_image": size_image,
        "size_of_headers": size_headers,
        "subsystem": SUBSYSTEMS.get(subsystem, f"0x{subsystem:x}"),
        "subsystem_raw": subsystem,
        "dll_characteristics": dll_chars,
        "number_of_sections": nsections,
        "sections": sections,
        "directories": directories,
        "imports": imports,
        "export_name": export_name,
        "exports": exports,
        "tls": tls,
        "rich_header": rich,
    }
    result["findings"] = analyse_findings(result, data)
    result["packer_score"] = sum(f["weight"] for f in result["findings"])
    return result


def analyse_findings(pe: dict, data: bytes) -> list[dict]:
    """Heuristics that answer one question: is this thing packed or hostile?"""
    findings: list[dict] = []

    def add(weight: int, label: str, detail: str = "") -> None:
        findings.append({"weight": weight, "label": label, "detail": detail})

    # Resource-only images (.mui, satellite DLLs) are ordinary PE files whose
    # whole payload is strings. They have no code, no imports, and would light
    # up every heuristic below - so classify them first and skip the noise.
    code_sections = [s for s in pe["sections"] if "CODE" in s["flags"]]
    has_rsrc = any(s["name"].startswith(".rsrc") for s in pe["sections"])
    resource_only = has_rsrc and not code_sections
    if resource_only:
        add(5, "resource-only-image", f"{len(pe['sections'])} section(s), no code section")

    # 1. Known packer section names
    for sec in pe["sections"]:
        key = sec["name"].strip().lower()
        if key in PACKER_SECTIONS:
            add(60, "packer-section", f"{sec['name']} -> {PACKER_SECTIONS[key]}")

    # 2. Entropy on executable sections (skip resource sections, they are
    #    compressed by design and always look packed)
    for sec in pe["sections"]:
        if "EXEC" not in sec["flags"]:
            continue
        if sec["name"].startswith(".rsrc"):
            continue
        if sec["entropy"] >= SUSPICIOUS and sec["raw_size"] > 512:
            add(35, "high-entropy-code", f"{sec['name']} entropy {sec['entropy']}")

    # 3. Very thin import table
    total_funcs = sum(len(v) for v in pe["imports"].values())
    if not resource_only:
        if pe["imports"] and total_funcs <= 10:
            add(30, "minimal-imports", f"{len(pe['imports'])} dlls / {total_funcs} funcs")
        if not pe["imports"]:
            add(40, "no-imports", "import directory empty - typical of shellcode stubs")

    # 4. Entry point must live in an executable section
    entry = pe["entry_point_rva"]
    in_exec = False
    for sec in pe["sections"]:
        start = sec["virtual_address"]
        end = start + max(sec["virtual_size"], sec["raw_size"])
        if start <= entry < end and "EXEC" in sec["flags"]:
            in_exec = True
            break
    if pe["sections"] and not in_exec and not resource_only:
        add(30, "entry-outside-code", f"entry RVA 0x{entry:x} not in any executable section")

    # 5. Sections whose raw data does not exist but which claim virtual size
    for sec in pe["sections"]:
        if sec["raw_size"] == 0 and sec["virtual_size"] > 0x1000:
            add(15, "uninitialized-section", f"{sec['name']} raw=0 vsize=0x{sec['virtual_size']:x}")

    # 6. Writable + executable section
    for sec in pe["sections"]:
        if "WRITE" in sec["flags"] and "EXEC" in sec["flags"]:
            add(25, "wx-section", f"{sec['name']} is writable+executable")

    # 7. Suspicious API surface
    hits = set()
    for funcs in pe["imports"].values():
        for fn in funcs:
            base = fn.split("@")[0]
            if base in SENSITIVE_IMPORTS:
                hits.add(base)
    for label, group in (
        ("injection-apis", {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                            "CreateRemoteThreadEx", "NtCreateThreadEx", "QueueUserAPC"}),
        ("anti-debug-apis", {"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                             "NtQueryInformationProcess", "OutputDebugStringA"}),
        ("keyboard-hooks", {"GetAsyncKeyState", "SetWindowsHookExA", "GetKeyboardState"}),
        ("network-apis", {"InternetOpenA", "InternetOpenW", "WinHttpOpen",
                          "URLDownloadToFileA", "WinHttpSendRequest"}),
        ("persistence-apis", {"CreateServiceA", "CreateServiceW", "RegSetValueExA"}),
    ):
        overlap = hits & group
        if overlap:
            add(10, label, ", ".join(sorted(overlap)[:6]))

    # 8. TLS callbacks - a classic anti-debug trick
    if pe["tls"]["callbacks"]:
        add(20, "tls-callbacks", f"{len(pe['tls']['callbacks'])} callback(s) run before entry")

    # 9. Section name anomalies
    for sec in pe["sections"]:
        if sec["name"] and not all(0x20 <= ord(c) < 0x7F for c in sec["name"]):
            add(10, "non-printable-section-name", repr(sec["name"]))
        if sec["name"].startswith(".") and len(sec["name"]) > 8:
            add(10, "long-section-name", sec["name"])

    # 10. Overlay data after the last section
    if pe["sections"]:
        last = max(pe["sections"], key=lambda s: s["raw_ptr"] + s["raw_size"])
        end = last["raw_ptr"] + last["raw_size"]
        overlay = len(data) - end
        if overlay > 0x400:
            add(5, "overlay", f"{overlay} bytes after last section")

    return findings
