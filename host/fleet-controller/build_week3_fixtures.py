#!/usr/bin/env python3
"""
Host Fleet Controller: Builds canonical 164-byte Signed Manifests and firmware
payloads for Week 3 10-Fault E2E Suite (T01-T09; T10 is journal tamper).
"""

import hashlib
import json
import struct
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from build_signed_manifest import PDX_MANIFEST_MAGIC, PDX_MANIFEST_SCHEMA_V1, pack_payload

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "simulator" / "fixtures" / "week3"


def pack_payload_custom_hw(
    sequence_id: int,
    operation_id: str,
    target_hw_rev: int,
    artifact_version: int,
    min_accepted_version: int,
    requires_stationary: int,
    firmware_bytes: bytes,
    key_id: int = 1,
) -> bytes:
    op_bytes = operation_id.encode("ascii")[:32].ljust(32, b"\x00")
    sha256_digest = hashlib.sha256(firmware_bytes).digest()
    payload = struct.pack(
        "<IHHQ32sIIIB3sI32s",
        PDX_MANIFEST_MAGIC,
        PDX_MANIFEST_SCHEMA_V1,
        key_id,
        sequence_id,
        op_bytes,
        target_hw_rev,
        artifact_version,
        min_accepted_version,
        requires_stationary,
        b"\x00\x00\x00",
        len(firmware_bytes),
        sha256_digest,
    )
    assert len(payload) == 100
    return payload


def sign_manifest(priv: Ed25519PrivateKey, payload: bytes) -> bytes:
    manifest = payload + priv.sign(payload)
    assert len(manifest) == 164
    return manifest


def main() -> None:
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    seed = hashlib.sha256(b"PDX_GUARDIAN_WEEK1_TEST_SEED_ONLY").digest()
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub_hex = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()

    bad_seed = hashlib.sha256(b"PDX_GUARDIAN_UNAUTHORIZED_KEY_T03").digest()
    bad_priv = Ed25519PrivateKey.from_private_bytes(bad_seed)

    cases: list[dict[str, object]] = []

    def add_case(
        case_id: str,
        fw_name: str,
        mf_name: str,
        fw_bytes: bytes,
        manifest_bytes: bytes,
        operation_id: str,
        target_version: int,
    ) -> None:
        (FIXTURES_DIR / fw_name).write_bytes(fw_bytes)
        (FIXTURES_DIR / mf_name).write_bytes(manifest_bytes)
        cases.append({
            "case_id": case_id,
            "operation_id": operation_id,
            "target_version": target_version,
            "firmware_file": fw_name,
            "manifest_file": mf_name,
            "firmware_sha256": hashlib.sha256(fw_bytes).hexdigest(),
        })

    # T01: Normal update v10 -> v11 (ALLOW)
    fw_t01 = b"PDX_ECU_SIM_FIRMWARE_V11_" + (b"\xAA\x55" * 512)
    mf_t01 = sign_manifest(priv, pack_payload(1, "op-wk3-t01-valid-v11", 11, 10, 1, fw_t01))
    add_case("T01", "t01_fw_v11.bin", "t01_manifest_v11.bin", fw_t01, mf_t01, "op-wk3-t01-valid-v11", 11)

    # T02: Bit-flipped payload v12 (DENY_HASH)
    fw_t02_orig = b"PDX_ECU_SIM_FIRMWARE_V12_T02_" + (b"\xBB\x44" * 512)
    mf_t02 = sign_manifest(priv, pack_payload(2, "op-wk3-t02-tamper-v12", 12, 10, 1, fw_t02_orig))
    fw_t02_bad = bytearray(fw_t02_orig)
    fw_t02_bad[100] ^= 0xFF
    add_case("T02", "t02_fw_v12_tampered.bin", "t02_manifest_v12.bin", bytes(fw_t02_bad), mf_t02, "op-wk3-t02-tamper-v12", 12)

    # T03: Unauthorized Ed25519 signature v12 (DENY_SIGNATURE)
    fw_t03 = b"PDX_ECU_SIM_FIRMWARE_V12_T03_" + (b"\xCC\x33" * 512)
    mf_t03 = sign_manifest(bad_priv, pack_payload(3, "op-wk3-t03-badsig-v12", 12, 10, 1, fw_t03))
    add_case("T03", "t03_fw_v12.bin", "t03_manifest_v12_badsig.bin", fw_t03, mf_t03, "op-wk3-t03-badsig-v12", 12)

    # T04: Anti-rollback attack v9 while active=11 (DENY_ROLLBACK)
    fw_t04 = b"PDX_ECU_SIM_FIRMWARE_V09_T04_" + (b"\xDD\x22" * 512)
    mf_t04 = sign_manifest(priv, pack_payload(4, "op-wk3-t04-rollback-v09", 9, 9, 1, fw_t04))
    add_case("T04", "t04_fw_v09.bin", "t04_manifest_v09.bin", fw_t04, mf_t04, "op-wk3-t04-rollback-v09", 9)

    # T05: Non-stationary vehicle (speed=45, requires_stationary=1 -> DENY_NOT_STATIONARY)
    fw_t05 = b"PDX_ECU_SIM_FIRMWARE_V12_T05_" + (b"\xEE\x11" * 512)
    mf_t05 = sign_manifest(priv, pack_payload(5, "op-wk3-t05-speed-v12", 12, 10, 1, fw_t05))
    add_case("T05", "t05_fw_v12.bin", "t05_manifest_v12.bin", fw_t05, mf_t05, "op-wk3-t05-speed-v12", 12)

    # T06: Hardware revision mismatch (0x0002000B != 0x0001000A -> DENY_HW_REV)
    fw_t06 = b"PDX_ECU_SIM_FIRMWARE_V12_T06_" + (b"\x55\xAA" * 512)
    mf_t06 = sign_manifest(priv, pack_payload_custom_hw(5, "op-wk3-t06-hwrev-v12", 0x0002000B, 12, 10, 1, fw_t06))
    add_case("T06", "t06_fw_v12.bin", "t06_manifest_v12_hwrev.bin", fw_t06, mf_t06, "op-wk3-t06-hwrev-v12", 12)

    # T07 (A/B/C): Crash during staging (tmp, after-rename, after-version)
    fw_t07 = b"PDX_ECU_SIM_FIRMWARE_V12_T07_" + (b"\x99\x66" * 512)
    mf_t07 = sign_manifest(priv, pack_payload(6, "op-wk3-t07-crash-v12", 12, 10, 1, fw_t07))
    add_case("T07", "t07_fw_v12.bin", "t07_manifest_v12.bin", fw_t07, mf_t07, "op-wk3-t07-crash-v12", 12)

    fw_t07b = b"PDX_ECU_SIM_FIRMWARE_V12_T07B_" + (b"\x88\x77" * 512)
    mf_t07b = sign_manifest(priv, pack_payload(7, "op-wk3-t07b-rename-v12", 12, 10, 1, fw_t07b))
    add_case("T07B", "t07b_fw_v12.bin", "t07b_manifest_v12.bin", fw_t07b, mf_t07b, "op-wk3-t07b-rename-v12", 12)

    fw_t07c = b"PDX_ECU_SIM_FIRMWARE_V12_T07C_" + (b"\x77\x88" * 512)
    mf_t07c = sign_manifest(priv, pack_payload(8, "op-wk3-t07c-ver-v12", 12, 10, 1, fw_t07c))
    add_case("T07C", "t07c_fw_v12.bin", "t07c_manifest_v12.bin", fw_t07c, mf_t07c, "op-wk3-t07c-ver-v12", 12)

    # T08: Cross-restart replay attack (v13 > v12, but seq=8 <= last_sequence_id=8 -> DENY_ROLLBACK)
    fw_t08 = b"PDX_ECU_SIM_FIRMWARE_V13_T08_" + (b"\x66\x99" * 512)
    mf_t08 = sign_manifest(priv, pack_payload(8, "op-wk3-t08-replay-v13", 13, 10, 1, fw_t08))
    add_case("T08", "t08_fw_v13.bin", "t08_manifest_v13_replay.bin", fw_t08, mf_t08, "op-wk3-t08-replay-v13", 13)

    # T09 & T09B: Persistence I/O error -> UNKNOWN_OUTCOME + uncertain lock on next request
    fw_t09 = b"PDX_ECU_SIM_FIRMWARE_V13_T09_" + (b"\x44\xBB" * 512)
    mf_t09 = sign_manifest(priv, pack_payload(9, "op-wk3-t09-ioerr-v13", 13, 10, 1, fw_t09))
    add_case("T09", "t09_fw_v13.bin", "t09_manifest_v13.bin", fw_t09, mf_t09, "op-wk3-t09-ioerr-v13", 13)

    fw_t09b = b"PDX_ECU_SIM_FIRMWARE_V14_T09B_" + (b"\x33\xCC" * 512)
    mf_t09b = sign_manifest(priv, pack_payload(10, "op-wk3-t09b-locked-v14", 14, 10, 1, fw_t09b))
    add_case("T09B", "t09b_fw_v14.bin", "t09b_manifest_v14.bin", fw_t09b, mf_t09b, "op-wk3-t09b-locked-v14", 14)

    meta = {"public_key_hex": pub_hex, "cases": cases}
    (FIXTURES_DIR / "fixtures_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"Generated {len(cases)} Week 3 fixtures in {FIXTURES_DIR}")


if __name__ == "__main__":
    main()
