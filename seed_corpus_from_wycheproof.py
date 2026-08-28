#!/usr/bin/env python3

import hashlib
import json
import os
import re
import sys
from pathlib import Path

# Super coarse parsing of any 8-length or above
# string that regex sees as hex
MIN_HEX_CHARS = 8
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# Test vectors filepath in Orion => hfuzz_workspace/<target>/input/ target name
ROUTES: list[tuple[str, tuple[str, ...]]] = [
    ("c2sp_wycheproof/mldsa_", ("dsa",)),
    ("c2sp_wycheproof/mlkem_", ("kem",)),
    ("c2sp_wycheproof/pbkdf2_", ("kdf",)),
    ("nist/ML-DSA/", ("dsa",)),
    ("nist/ML-KEM/", ("kem",)),
    ("hpke_wg/", ("hpke",)),
    ("rfc9180/", ("hpke",)),
    ("blake2-kat.json", ("hash", "mac")),
    ("blake3_test_vectors.json", ("hash", "xof")),
    ("google/wycheproof/wycheproof_chacha20_poly1305", ("aead",)),
    ("google/wycheproof/wycheproof_xchacha20_poly1305", ("aead",)),
    ("google/wycheproof/wycheproof_hkdf_", ("kdf",)),
    ("google/wycheproof/wycheproof_hmac_", ("mac",)),
    ("google/wycheproof/wycheproof_x25519", ("ecc",)),
    ("custom/python_cryptography_argon2", ("high_level_api",)),
    ("custom/python_cryptography_scrypt", ("high_level_api", "kdf")),
    ("pynacl/pynacl_raw_argon2i_hashes", ("high_level_api",)),
    ("pynacl/pynacl_secretstream_test_vectors", ("aead_stream",)),
]


def target_for(relpath: str) -> tuple[str, ...]:
    for prefix, targets in ROUTES:
        if relpath.startswith(prefix):
            return targets
    return ()


def iter_hex_blobs(node):
    if isinstance(node, str):
        if len(node) >= MIN_HEX_CHARS and len(node) % 2 == 0 and HEX_RE.match(node):
            yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from iter_hex_blobs(v)
    elif isinstance(node, list):
        for v in node:
            yield from iter_hex_blobs(v)


def write_seed(out_dir: Path, data: bytes) -> bool:
    if not data:
        return False
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"vecseed-{hashlib.sha256(data).hexdigest()[:16]}"
    if path.exists():
        return False
    path.write_bytes(data)
    return True


def main(testvector_dir: Path, hfuzz_workspace: Path):
    if not testvector_dir.is_dir():
        print(f"testvector_dir not found: {testvector_dir}\n", file=sys.stderr)
        sys.exit(1)

    written_per_target: dict[str, int] = {}
    skipped_files = 0

    # We just go through every single JSON file
    for json_path in sorted(testvector_dir.rglob("*.json")):
        relpath = str(json_path.relative_to(testvector_dir))
        targets = target_for(relpath)
        if not targets:
            continue
        try:
            doc = json.loads(json_path.read_text())
        except (json.JSONDecodeError, UnicodeDecodeError):
            skipped_files += 1
            continue

        blobs = {bytes.fromhex(h) for h in iter_hex_blobs(doc)}
        for target in targets:
            out_dir = hfuzz_workspace / target / "input"
            n = sum(write_seed(out_dir, blob) for blob in blobs)
            written_per_target[target] = written_per_target.get(target, 0) + n

    for target, n in sorted(written_per_target.items()):
        print(f"{target} {n}")
    if skipped_files:
        print(f"\n({skipped_files} failed to parse JSON and skipped)")


if __name__ == "__main__":
    testvector_dir = Path(sys.argv[1])
    workspace = (
        Path(sys.argv[2]) if len(sys.argv) > 2 else Path.cwd() / "hfuzz_workspace"
    )
    main(testvector_dir, workspace)
