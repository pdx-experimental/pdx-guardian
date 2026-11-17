#!/usr/bin/env python3
"""
Host Fleet Controller: Builds canonical 164-byte Signed Manifest (pdx_manifest.h ABI)
and simulated firmware payloads for Week 1 Thin Vertical Thread.
"""

import hashlib
import json
import os
import struct
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

PDX_MANIFEST_MAGIC = 0x58445050
PDX_MANIFEST_SCHEMA_V1 = 0x0001
TARGET_HW_REV = 0x0001000A

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "simulator" / "fixtures" / "week1"


def pack_payload(
    sequence_id: int,
    operation_id: str,
    artifact_version: int,
    min_accepted_version: int,
    requires_stationary: int,
    firmware_bytes: bytes,
    key_id: int = 1,
) -> bytes:
    op_bytes = operation_id.encode("ascii")[:32].ljust(32, b"\x00")
    sha256_digest = hashlib.sha256(firmware_bytes).digest()
    # Struct format: <IHHQ32sIII B3s I32s (exact 100 bytes)
    payload = struct.pack(
        "<IHHQ32sIIIB3sI32s",
        PDX_MANIFEST_MAGIC,
        PDX_MANIFEST_SCHEMA_V1,
        key_id,
        sequence_id,
        op_bytes,
        TARGET_HW_REV,
        artifact_version,
        min_accepted_version,
        requires_stationary,
        b"\x00\x00\x00",
        len(firmware_bytes),
        sha256_digest,
    )
    assert len(payload) == 100, f"Expected 100 bytes, got {len(payload)}"
    return payload


def main() -> None:
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    # Generate deterministic demo keypair for local test fixture (never used in production)
    seed = hashlib.sha256(b"PDX_GUARDIAN_WEEK1_TEST_SEED_ONLY").digest()
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key()
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_hex = pub_raw.hex()

    # 1. Valid update v11
    fw_v11 = b"PDX_ECU_SIM_FIRMWARE_V11_" + (b"\xAA\x55" * 512)
    payload_v11 = pack_payload(
        sequence_id=1,
        operation_id="op-week1-thin-thread-0001",
        artifact_version=11,
        min_accepted_version=10,
        requires_stationary=1,
        firmware_bytes=fw_v11,
    )
    sig_v11 = priv.sign(payload_v11)
    manifest_v11 = payload_v11 + sig_v11
    assert len(manifest_v11) == 164

    (FIXTURES_DIR / "fw_v11.bin").write_bytes(fw_v11)
    (FIXTURES_DIR / "manifest_v11.bin").write_bytes(manifest_v11)

    # 2. Tampered firmware (1 byte flipped) against valid manifest v12
    fw_v12_orig = b"PDX_ECU_SIM_FIRMWARE_V12_" + (b"\xBB\x44" * 512)
    payload_v12 = pack_payload(
        sequence_id=2,
        operation_id="op-week1-tamper-test-0002",
        artifact_version=12,
        min_accepted_version=10,
        requires_stationary=1,
        firmware_bytes=fw_v12_orig,
    )
    sig_v12 = priv.sign(payload_v12)
    manifest_v12 = payload_v12 + sig_v12

    fw_v12_tampered = bytearray(fw_v12_orig)
    fw_v12_tampered[100] ^= 0xFF

    (FIXTURES_DIR / "fw_v12_tampered.bin").write_bytes(bytes(fw_v12_tampered))
    (FIXTURES_DIR / "manifest_v12.bin").write_bytes(manifest_v12)

    meta = {
        "ed25519_pubkey_hex": pub_hex,
        "v11_sha256": hashlib.sha256(fw_v11).hexdigest(),
        "v12_orig_sha256": hashlib.sha256(fw_v12_orig).hexdigest(),
        "v12_tampered_sha256": hashlib.sha256(fw_v12_tampered).hexdigest(),
    }
    (FIXTURES_DIR / "fixtures_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"Generated Week 1 fixtures in {FIXTURES_DIR}")
    print(f"Test Public Key (hex): {pub_hex}")


if __name__ == "__main__":
    main()
