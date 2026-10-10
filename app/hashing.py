"""SHA-256 helpers for evidence files. Files are hashed in chunks so large
images never need to fit in memory."""

import hashlib
import os

CHUNK_SIZE = 1024 * 1024


def sha256_stream(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
        digest.update(chunk)
    return digest.hexdigest()


def sha256_file(path):
    with open(path, "rb") as fh:
        return sha256_stream(fh)


def store_and_hash(stream, dest_path):
    """Copy `stream` to `dest_path`, hashing the exact bytes written.

    Returns (sha256_hex, size_bytes). The stored copy is made read-only.
    """
    digest = hashlib.sha256()
    size = 0
    # "xb": refuse to overwrite an existing file.
    with open(dest_path, "xb") as out:
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(chunk)
            out.write(chunk)
            size += len(chunk)
        out.flush()
        os.fsync(out.fileno())
    os.chmod(dest_path, 0o440)
    return digest.hexdigest(), size
