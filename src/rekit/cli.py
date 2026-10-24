"""Command line front end. One subcommand per job."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from . import entropy, formats, pe as pe_mod, strings as strings_mod, xor as xor_mod
from .util import human_size, iter_files, read_file, sha256, md5


def _out(text: str = "") -> None:
    print(text)


def _rule(title: str) -> None:
    _out()
    _out(f"== {title} " + "=" * max(0, 66 - len(title)))


def cmd_info(args: argparse.Namespace) -> int:
    data = read_file(args.path)
    fmt = formats.identify(data, args.path)
    ent = entropy.shannon(data)

    if args.json:
        payload = {
            "path": os.path.abspath(args.path),
            "size": len(data),
            "sha256": sha256(data),
            "md5": md5(data),
            "format": fmt.name,
            "detail": fmt.detail,
            "confidence": fmt.confidence,
            "entropy": round(ent, 4),
            "entropy_rating": entropy.rating(ent),
        }
        _out(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    _rule("file")
    _out(f"path       {os.path.abspath(args.path)}")
    _out(f"size       {human_size(len(data))} ({len(data)} bytes)")
    _out(f"format     {fmt}")
    _out(f"confidence {fmt.confidence}")
    _out(f"sha256     {sha256(data)}")
    _out(f"md5        {md5(data)}")
    _out(f"entropy    {ent:.4f}  [{entropy.rating(ent)}]")

    regions = entropy.uniform_string_detector(data)
    if regions:
        _rule("high-entropy regions")
        for off, length, value in regions[:10]:
            _out(f"  offset 0x{off:08x}  len {length:>8}  entropy {value:.3f}")
    return 0


def cmd_strings(args: argparse.Namespace) -> int:
    data = read_file(args.path)
    kinds = tuple(k.strip() for k in args.kind.split(",") if k.strip())
    found = strings_mod.extract(data, min_len=args.min_len, kinds=kinds)
    if args.grep:
        needle = args.grep.lower()
        found = [f for f in found if needle in f.text.lower()]
    if args.limit:
        found = found[:args.limit]

    if args.json:
        _out(json.dumps([{"offset": f.offset, "kind": f.kind, "text": f.text} for f in found],
                        indent=2, ensure_ascii=False))
        return 0

    for f in found:
        _out(str(f))
    _out()
    _out(f"-- {len(found)} string(s)")
    return 0


def cmd_pe(args: argparse.Namespace) -> int:
    data = read_file(args.path)
    try:
        info = pe_mod.parse(data)
    except pe_mod.PEError as exc:
        _out(f"[!] not a PE: {exc}")
        return 2

    if args.json:
        _out(json.dumps(info, indent=2, ensure_ascii=False))
        return 0

    _rule("headers")
    _out(f"machine        {info['machine']}")
    _out(f"format         {'PE32+' if info['pe32plus'] else 'PE32'}")
    _out(f"kind           {'driver' if info['is_driver'] else ('dll' if info['is_dll'] else 'exe')}")
    _out(f"subsystem      {info['subsystem']}")
    _out(f"timestamp      {info['timestamp_iso'] or 'n/a'}")
    _out(f"entry RVA      0x{info['entry_point_rva']:08x}")
    _out(f"image base     0x{info['image_base']:x}")
    _out(f"sections       {info['number_of_sections']}")
    _out(f"packer score   {info['packer_score']}")

    _rule("sections")
    _out(f"{'name':<10}{'vaddr':>10}{'vsize':>10}{'raw':>10}{'entropy':>9}  flags")
    for sec in info["sections"]:
        _out(f"{sec['name']:<10}0x{sec['virtual_address']:08x}{sec['virtual_size']:>10}"
             f"{sec['raw_size']:>10}{sec['entropy']:>9.3f}  {','.join(sec['flags'])}")

    _rule("imports")
    if not info["imports"]:
        _out("(none)")
    for dll, funcs in info["imports"].items():
        _out(f"{dll}  ({len(funcs)})")
        if args.imports:
            for fn in funcs:
                _out(f"    {fn}")

    if info["exports"]:
        _rule(f"exports from {info['export_name'] or '?'}")
        for name in info["exports"][:args.export_limit]:
            _out(f"  {name}")
        if len(info["exports"]) > args.export_limit:
            _out(f"  ... {len(info['exports']) - args.export_limit} more")

    if info["tls"]["present"]:
        _rule("tls")
        _out(f"callback array VA 0x{info['tls'].get('callback_array_va', 0):x}")
        for cb in info["tls"]["callbacks"]:
            _out(f"  callback 0x{cb:x}")
        if not info["tls"]["callbacks"]:
            _out("  (no callbacks)")

    if info["rich_header"]:
        _rule("rich header")
        rh = info["rich_header"]
        _out(f"xor key 0x{rh['key']:08x}  entries {len(rh['entries'])}")
        for entry in rh["entries"][:12]:
            _out(f"  product {entry['product_id']:>5}  build {entry['build']:>6}  count {entry['count']}")

    if info["findings"]:
        _rule(f"findings  (packer score {info['packer_score']})")
        for f in sorted(info["findings"], key=lambda x: x["weight"], reverse=True):
            _out(f"  [{f['weight']:>3}] {f['label']:<26} {f['detail']}")
    else:
        _rule("findings")
        _out("  nothing suspicious")
    return 0


def cmd_xor(args: argparse.Namespace) -> int:
    data = read_file(args.path)

    if args.key:
        key = bytes.fromhex(args.key) if all(c in "0123456789abcdefABCDEF" for c in args.key) and len(args.key) % 2 == 0 else args.key.encode()
        dec = xor_mod.apply_key(data, key)
        out_path = args.out or (args.path + ".dec")
        with open(out_path, "wb") as fh:
            fh.write(dec)
        _out(f"[+] key {key.hex()} applied -> {out_path} ({len(dec)} bytes)")
        return 0

    if args.crib:
        crib = args.crib.encode("latin-1", "replace")
        cands = xor_mod.crib_attack(data, crib)
        _rule("crib attack")
        if not cands:
            _out("no candidate key found")
            return 1
        for c in cands:
            _out(str(c))
        return 0

    cands = xor_mod.brute_single_byte(data)
    _rule("single-byte xor candidates")
    if not cands:
        _out("no plaintext-looking result")
        return 1
    for c in cands:
        _out(str(c))
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    rows = []
    for path in iter_files(args.path):
        try:
            if os.path.getsize(path) > args.max_size * 1024 * 1024:
                continue
            with open(path, "rb") as fh:
                head = fh.read(0x1000)
        except OSError:
            continue
        if head[:2] != b"MZ":
            continue
        try:
            data = read_file(path) if os.path.getsize(path) <= args.max_size * 1024 * 1024 else head
            info = pe_mod.parse(data)
        except Exception:
            continue
        score = info["packer_score"]
        if score < args.min_score:
            continue
        rows.append({
            "path": path,
            "score": score,
            "machine": info["machine"],
            "subsystem": info["subsystem"],
            "sections": info["number_of_sections"],
            "imports": sum(len(v) for v in info["imports"].values()),
            "labels": [f["label"] for f in info["findings"]],
        })

    rows.sort(key=lambda r: r["score"], reverse=True)
    if args.json:
        _out(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0

    _rule(f"scan results  ({len(rows)} hit(s))")
    for r in rows:
        _out(f"{r['score']:>4}  {r['machine']:<6} {str(r['sections']):>2}s "
             f"{r['imports']:>4}i  {r['path']}")
        _out(f"      {', '.join(dict.fromkeys(r['labels']))}")
    return 0


def cmd_hash(args: argparse.Namespace) -> int:
    data = read_file(args.path)
    _out(f"sha256  {sha256(data)}")
    _out(f"md5     {md5(data)}")
    _out(f"size    {len(data)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rekit",
        description="Zero-dependency reverse engineering toolkit.",
    )
    p.add_argument("--version", action="version", version=f"rekit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("info", help="identify a file, size, hashes, entropy")
    s.add_argument("path")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_info)

    s = sub.add_parser("strings", help="extract ascii / utf16 / utf8 strings with offsets")
    s.add_argument("path")
    s.add_argument("-n", "--min-len", type=int, default=4)
    s.add_argument("--kind", default="ascii,utf16le,utf8")
    s.add_argument("--grep")
    s.add_argument("--limit", type=int, default=0)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_strings)

    s = sub.add_parser("pe", help="parse PE headers, sections, imports, punch a packer score")
    s.add_argument("path")
    s.add_argument("--imports", action="store_true", help="list every imported function")
    s.add_argument("--export-limit", type=int, default=50)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_pe)

    s = sub.add_parser("xor", help="recover xor keys (brute / known key / crib)")
    s.add_argument("path")
    s.add_argument("--key", help="hex or ascii repeating key to apply")
    s.add_argument("--crib", help="known plaintext fragment")
    s.add_argument("-o", "--out", help="output path for --key mode")
    s.set_defaults(func=cmd_xor)

    s = sub.add_parser("scan", help="walk a directory and score every PE found")
    s.add_argument("path")
    s.add_argument("--min-score", type=int, default=30)
    s.add_argument("--max-size", type=int, default=64, help="megabytes")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("hash", help="sha256 / md5 / size")
    s.add_argument("path")
    s.set_defaults(func=cmd_hash)
    return p


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError:
        _out(f"[!] no such file: {args.path}")
        return 2
    except PermissionError:
        _out(f"[!] permission denied: {args.path}")
        return 2
