"""Read-only analysis tools for stored evidence.

Every function opens the evidence file read-only ("rb") and streams it in
chunks, so multi-gigabyte images are fine. Nothing here can modify the
original; investigators who need other tools export a verified working copy.
"""

import hashlib
import math
import re

import numpy as np

CHUNK = 1024 * 1024

# (offset, magic bytes, description). First match wins, so more specific first.
SIGNATURES = [
    (0, b"EVF\x09\x0d\x0a\xff\x00", "EnCase evidence file (E01)"),
    (0, b"SQLite format 3\x00", "SQLite database"),
    (0, b"%PDF-", "PDF document"),
    (0, b"\x89PNG\r\n\x1a\n", "PNG image"),
    (0, b"\xff\xd8\xff", "JPEG image"),
    (0, b"GIF87a", "GIF image"),
    (0, b"GIF89a", "GIF image"),
    (0, b"PK\x03\x04", "ZIP archive (also DOCX/XLSX/APK/JAR)"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 compound file (legacy Office, MSI)"),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (0, b"Rar!\x1a\x07", "RAR archive"),
    (0, b"\x1f\x8b", "gzip compressed data"),
    (0, b"BZh", "bzip2 compressed data"),
    (0, b"\xfd7zXZ\x00", "xz compressed data"),
    (0, b"\x7fELF", "ELF executable (Linux/Unix)"),
    (0, b"MZ", "DOS/Windows executable (PE)"),
    (0, b"\xd4\xc3\xb2\xa1", "pcap network capture"),
    (0, b"\xa1\xb2\xc3\xd4", "pcap network capture"),
    (0, b"\x0a\x0d\x0d\x0a", "pcapng network capture"),
    (0, b"regf", "Windows registry hive"),
    (0, b"ElfFile\x00", "Windows XML event log (EVTX)"),
    (0, b"RIFF", "RIFF container (WAV/AVI/WEBP)"),
    (3, b"NTFS    ", "NTFS volume boot record"),
    (3, b"MSDOS5.0", "FAT volume boot record"),
    (82, b"FAT32   ", "FAT32 volume boot record"),
    (257, b"ustar", "tar archive"),
    (1080, b"\x53\xef", "ext2/3/4 filesystem"),
    (0x8001, b"CD001", "ISO 9660 disc image"),
    (510, b"\x55\xaa", "Disk image with MBR partition table"),
]
_HEAD_BYTES = 0x8001 + 5


def identify(path):
    with open(path, "rb") as fh:
        head = fh.read(_HEAD_BYTES)
    for offset, magic, label in SIGNATURES:
        if head[offset : offset + len(magic)] == magic:
            return {"type": label, "magic_offset": offset, "magic_hex": magic.hex()}
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in head[:4096])
    if head and printable / min(len(head), 4096) > 0.95:
        return {"type": "Text (no binary signature)", "magic_offset": None, "magic_hex": None}
    return {"type": "Unknown binary data", "magic_offset": None, "magic_hex": None}


def profile(path):
    """MD5, SHA-1, SHA-256 and Shannon entropy in one pass.

    MD5/SHA-1 are provided only to match against hash sets (e.g. NSRL) that
    still use them; SHA-256 remains the integrity hash.
    """
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    counts = np.zeros(256, dtype=np.int64)
    size = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            size += len(chunk)
            counts += np.bincount(np.frombuffer(chunk, dtype=np.uint8), minlength=256)
    entropy = -sum((c / size) * math.log2(c / size) for c in counts.tolist() if c) if size else 0.0
    return {
        "size_bytes": size,
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "entropy_bits_per_byte": round(entropy, 4),
        "entropy_hint": _entropy_hint(entropy),
    }


def _entropy_hint(e):
    if e > 7.9:
        return "very high: likely encrypted or compressed"
    if e > 7.0:
        return "high: compressed media or packed data"
    if e < 1.0:
        return "very low: mostly empty or repetitive (e.g. zeroed space)"
    return "mixed content"


def hexdump(path, offset=0, length=512):
    length = max(16, min(int(length), 4096))
    offset = max(0, int(offset))
    with open(path, "rb") as fh:
        fh.seek(offset)
        data = fh.read(length)
    rows = []
    for i in range(0, len(data), 16):
        row = data[i : i + 16]
        rows.append(
            {
                "offset": offset + i,
                "hex": " ".join(f"{b:02x}" for b in row),
                "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in row),
            }
        )
    return {"offset": offset, "length": len(data), "rows": rows}


_STRING_PATTERNS = {
    "ascii": lambda n: re.compile(rb"[\x20-\x7e]{%d,}" % n),
    "utf16le": lambda n: re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % n),
}
_MAX_CARRY = 64 * 1024


def _printable(b):
    return 0x20 <= b <= 0x7E


def _trailing_run_start(buf, encoding):
    """Start of the printable run at the end of `buf` (capped at _MAX_CARRY),
    which may continue into the next chunk and so must be carried over."""
    floor = max(0, len(buf) - _MAX_CARRY)
    i = len(buf)
    if encoding == "ascii":
        while i > floor and _printable(buf[i - 1]):
            i -= 1
        return i
    if i > floor and _printable(buf[i - 1]):
        i -= 1  # first byte of a UTF-16 character whose zero byte is in the next chunk
    while i - 2 >= floor and buf[i - 1] == 0 and _printable(buf[i - 2]):
        i -= 2
    return i


def extract_strings(path, encoding="ascii", min_len=6, limit=500, start=0):
    """Printable strings with their byte offsets, like `strings -t d`.

    Stops after `limit` results; `next_offset` lets the caller continue.
    """
    if encoding not in _STRING_PATTERNS:
        raise ValueError("encoding must be ascii or utf16le")
    min_len = max(3, min(int(min_len), 64))
    limit = max(1, min(int(limit), 2000))
    pattern = _STRING_PATTERNS[encoding](min_len)
    codec = "ascii" if encoding == "ascii" else "utf-16-le"
    results = []
    carry, base = b"", max(0, int(start))  # base = file offset of carry[0]
    with open(path, "rb") as fh:
        fh.seek(base)
        while True:
            chunk = fh.read(CHUNK)
            buf = carry + chunk
            # Hold back a run touching the end of the buffer until we see the next chunk.
            cut = _trailing_run_start(buf, encoding) if chunk else len(buf)
            for m in pattern.finditer(buf, 0, cut):
                results.append({"offset": base + m.start(), "text": m.group().decode(codec, errors="replace")[:500]})
                if len(results) >= limit:
                    return {"strings": results, "next_offset": base + m.end()}
            if not chunk:
                return {"strings": results, "next_offset": None}
            carry, base = buf[cut:], base + cut


def search(path, keyword, max_hits=200, context=24):
    """Case-insensitive search for `keyword` as ASCII and as UTF-16LE text.

    Returns byte offsets with a little surrounding context.
    """
    if not keyword or len(keyword) > 256:
        raise ValueError("keyword must be 1-256 characters")
    max_hits = max(1, min(int(max_hits), 1000))
    needles = {
        "ascii": keyword.encode("utf-8"),
        "utf16le": keyword.encode("utf-16-le"),
    }
    patterns = {enc: re.compile(re.escape(n), re.IGNORECASE) for enc, n in needles.items()}
    overlap = max(len(n) for n in needles.values()) - 1
    hits = []
    seen = set()
    with open(path, "rb") as fh:
        base, tail = 0, b""
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            buf = tail + chunk
            buf_start = base - len(tail)
            for enc, pat in patterns.items():
                for m in pat.finditer(buf):
                    off = buf_start + m.start()
                    if (enc, off) in seen:
                        continue  # found again in the overlap region
                    seen.add((enc, off))
                    hits.append({"offset": off, "encoding": enc})
            if len(hits) >= max_hits:
                break
            base += len(chunk)
            tail = buf[-overlap:] if overlap else b""
        hits.sort(key=lambda h: h["offset"])
        hits = hits[:max_hits]
        for h in hits:
            start = max(0, h["offset"] - context)
            fh.seek(start)
            raw = fh.read(context * 2 + len(needles[h["encoding"]]))
            h["context"] = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
            h["context_offset"] = start
    return {"keyword": keyword, "hits": hits, "truncated": len(hits) >= max_hits}
