"""XOR recovery: the single most common "encrypted" blob in malware and in
protocols people ask you to reverse.

Three modes:
  1. brute        - try all 255 single-byte keys, rank by printability
  2. key          - apply a known repeating key
  3. crib         - known plaintext attack, recovers an unknown repeating key
"""

from __future__ import annotations

from dataclasses import dataclass

from .util import printable_ratio

# Tokens that strongly suggest we found real plaintext.
TOKENS = [
    b"http://", b"https://", b"This program", b"Microsoft", b"kernel32",
    b"GetProcAddress", b"LoadLibrary", b"MZ\x90", b"PK\x03\x04", b"<?xml",
    b"{\"", b"function", b"SELECT ", b"<html", b"#!/", b"Error", b"password",
    b"token", b"\"key\"", b"Content-Type", b"\r\n",
]

TOKEN_WEIGHT = 0.08

# Words that survive an XOR decode only if we guessed the key right.
WORDS = [
    b" the ", b" and ", b" for ", b" you ", b" this ", b" that ", b" with ",
    b" from ", b" have ", b" not ", b" are ", b" can ", b" was ", b" out ",
    b"http", b"www.", b".com", b"error", b"file", b"program", b"cannot",
    b"mode", b"function", b"return", b"password", b"token", b"select",
    b"<html", b"<?xml", b"import", b"library",
]


@dataclass
class Candidate:
    key: int | bytes
    score: float
    preview: str

    def __str__(self) -> str:
        k = f"0x{self.key:02x}" if isinstance(self.key, int) else self.key.hex()
        return f"key={k}  score={self.score:.3f}  {self.preview}"


def apply_key(data: bytes, key: bytes) -> bytes:
    n = len(key)
    if n == 1:
        k = key[0]
        return bytes(b ^ k for b in data)
    return bytes(b ^ key[i % n] for i, b in enumerate(data))


def score_plaintext(data: bytes) -> float:
    """How much does this look like real plaintext?

    Printability alone is a weak signal: a wrong key still often yields
    printable garbage. Weighting English word hits and space density is what
    actually separates the correct key from the 254 wrong ones.
    """
    if not data:
        return 0.0
    ratio = printable_ratio(data)
    if ratio < 0.6:
        return ratio * 0.3
    low = data.lower()
    n = len(low)
    word_hits = sum(1 for w in WORDS if w in low)
    spaces = data.count(0x20) / n
    letters = sum(1 for b in low if 97 <= b <= 122) / n
    tokens = sum(1 for tok in TOKENS if tok in data)
    return min(
        1.0,
        ratio * 0.25
        + min(1.0, word_hits / 5) * 0.40
        + min(1.0, spaces / 0.10) * 0.15
        + min(1.0, letters / 0.70) * 0.10
        + min(1.0, tokens / 2) * 0.10,
    )


def brute_single_byte(data: bytes, sample: int = 8192, top: int = 8) -> list[Candidate]:
    chunk = data[:sample]
    results: list[Candidate] = []
    for key in range(1, 256):
        dec = bytes(b ^ key for b in chunk)
        s = score_plaintext(dec)
        if s < 0.62:
            continue
        preview = "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in dec[:60])
        results.append(Candidate(key, round(s, 4), preview))
    results.sort(key=lambda c: c.score, reverse=True)
    return results[:top]


def crib_attack(data: bytes, crib: bytes, min_key_len: int = 1, max_key_len: int = 32,
                sample: int = 65536) -> list[Candidate]:
    """Recover a repeating XOR key given a known plaintext fragment.

    Tries every offset for the crib; for each candidate key length the derived
    key bytes must agree, otherwise the offset/length pair is rejected.
    """
    if not crib:
        return []
    out: list[Candidate] = []
    view = data[:sample]
    for length in range(min_key_len, max_key_len + 1):
        for offset in range(0, min(len(view), 512)):
            if offset + len(crib) > len(view):
                break
            derived = bytes(view[offset + i] ^ crib[i] for i in range(len(crib)))
            key = bytearray(length)
            ok = True
            for i, b in enumerate(derived):
                slot = i % length
                if key[slot] == 0 and b != 0:
                    key[slot] = b
                elif key[slot] != b:
                    ok = False
                    break
            if not ok:
                continue
            full = bytes(key)
            dec = apply_key(view[:min(len(view), 4096)], full)
            s = score_plaintext(dec)
            if s >= 0.62:
                preview = "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in dec[:60])
                out.append(Candidate(full, round(s, 4), preview))
    # Deduplicate by key while keeping the best score.
    best: dict[bytes, Candidate] = {}
    for cand in out:
        assert isinstance(cand.key, bytes)
        if cand.key not in best or cand.score > best[cand.key].score:
            best[cand.key] = cand
    ranked = sorted(best.values(), key=lambda c: c.score, reverse=True)
    return ranked[:8]
