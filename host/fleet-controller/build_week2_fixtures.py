#!/usr/bin/env python3
"""
Host Fleet Controller: Builds canonical 164-byte Signed Manifests and firmware
payloads for Week 2 E2E test suite (T01-T05, T07).
"""

import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from build_signed_manifest import pack_payload

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "simulator" / "fixtures" / "week2"


def sign_manifest(priv: Ed25519PrivateKey, payload: bytes) -> bytes:
    manifest = payload + priv.sign(payload)
    assert len(manifest) == 164
    return manifest


def main() -> None:
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    # Same deterministic demo keypair whose public key is embedded in guardian_gate
    seed = hashlib.sha256(b"PDX_GUARDIAN_WEEK1_TEST_SEED_ONLY").digest()
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub_hex = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()

    # Unauthorized keypair for T03
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
    mf_t01 = sign_manifest(
        priv,
        pack_payload(
            sequence_id=1,
            operation_id="op-wk2-t01-valid-v11",
            artifact_version=11,
            min_accepted_version=10,
            requires_stationary=1,
            firmware_bytes=fw_t01,
        ),
    )
    add_case("T01", "t01_fw_v11.bin", "t01_manifest_v11.bin", fw_t01, mf_t01, "op-wk2-t01-valid-v11", 11)

    # T02: Bit-flipped payload v12 (DENY_HASH)
    fw_t02_orig = b"PDX_ECU_SIM_FIRMWARE_V12_T02_" + (b"\xBB\x44" * 512)
    mf_t02 = sign_manifest(
        priv,
        pack_payload(
            sequence_id=2,
            operation_id="op-wk2-t02-tamper-v12",
            artifact_version=12,
            min_accepted_version=10,
            requires_stationary=1,
            firmware_bytes=fw_t02_orig,
        ),
    )
    fw_t02_bad = bytearray(fw_t02_orig)
    fw_t02_bad[100] ^= 0xFF
    add_case("T02", "t02_fw_v12_tampered.bin", "t02_manifest_v12.bin", bytes(fw_t02_bad), mf_t02, "op-wk2-t02-tamper-v12", 12)

    # T03: Unauthorized Ed25519 signature v12 (DENY_SIGNATURE)
    fw_t03 = b"PDX_ECU_SIM_FIRMWARE_V12_T03_" + (b"\xCC\x33" * 512)
    mf_t03 = sign_manifest(
        bad_priv,
        pack_payload(
            sequence_id=3,
            operation_id="op-wk2-t03-badsig-v12",
            artifact_version=12,
            min_accepted_version=10,
            requires_stationary=1,
            firmware_bytes=fw_t03,
        ),
    )
    add_case("T03", "t03_fw_v12.bin", "t03_manifest_v12_badsig.bin", fw_t03, mf_t03, "op-wk2-t03-badsig-v12", 12)

    # T04: Anti-rollback attack v9 while active=11 (DENY_ROLLBACK)
    fw_t04 = b"PDX_ECU_SIM_FIRMWARE_V09_T04_" + (b"\xDD\x22" * 512)
    mf_t04 = sign_manifest(
        priv,
        pack_payload(
            sequence_id=4,
            operation_id="op-wk2-t04-rollback-v09",
            artifact_version=9,
            min_accepted_version=9,
            requires_stationary=1,
            firmware_bytes=fw_t04,
        ),
    )
    add_case("T04", "t04_fw_v09.bin", "t04_manifest_v09.bin", fw_t04, mf_t04, "op-wk2-t04-rollback-v09", 9)

    # T05: Valid v12 with requires_stationary=1, tested at speed 45 (DENY_NOT_STATIONARY)
    fw_t05 = b"PDX_ECU_SIM_FIRMWARE_V12_T05_" + (b"\xEE\x11" * 512)
    mf_t05 = sign_manifest(
        priv,
        pack_payload(
            sequence_id=5,
            operation_id="op-wk2-t05-speed-v12",
            artifact_version=12,
            min_accepted_version=10,
            requires_stationary=1,
            firmware_bytes=fw_t05,
        ),
    )
    add_case("T05", "t05_fw_v12.bin", "t05_manifest_v12.bin", fw_t05, mf_t05, "op-wk2-t05-speed-v12", 12)

    # T07: Valid v12 for SIGKILL crash mid-staging (crash-point=tmp)
    fw_t07 = b"PDX_ECU_SIM_FIRMWARE_V12_T07_" + (b"\x99\x66" * 512)
    mf_t07 = sign_manifest(
        priv,
        pack_payload(
            sequence_id=6,
            operation_id="op-wk2-t07-crash-v12",
            artifact_version=12,
            min_accepted_version=10,
            requires_stationary=1,
            firmware_bytes=fw_t07,
        ),
    )
    add_case("T07", "t07_fw_v12.bin", "t07_manifest_v12.bin", fw_t07, mf_t07, "op-wk2-t07-crash-v12", 12)

    # T07B: Valid v12 for SIGKILL crash after-rename (before version persist)
    fw_t07b = b"PDX_ECU_SIM_FIRMWARE_V12_T07B_" + (b"\x88\x77" * 512)
    mf_t07b = sign_manifest(
        priv,
        pack_payload(
            sequence_id=7,
            operation_id="op-wk2-t07b-rename-v12",
            artifact_version=12,
            min_accepted_version=10,
            requires_stationary=1,
            firmware_bytes=fw_t07b,
        ),
    )
    add_case("T07B", "t07b_fw_v12.bin", "t07b_manifest_v12.bin", fw_t07b, mf_t07b, "op-wk2-t07b-rename-v12", 12)

    # T07C: Valid v12 for SIGKILL crash after-version (before ACTIVATED journal append)
    fw_t07c = b"PDX_ECU_SIM_FIRMWARE_V12_T07C_" + (b"\x77\x88" * 512)
    mf_t07c = sign_manifest(
        priv,
        pack_payload(
            sequence_id=8,
            operation_id="op-wk2-t07c-ver-v12",
            artifact_version=12,
            min_accepted_version=10,
            requires_stationary=1,
            firmware_bytes=fw_t07c,
        ),
    )
    add_case("T07C", "t07c_fw_v12.bin", "t07c_manifest_v12.bin", fw_t07c, mf_t07c, "op-wk2-t07c-ver-v12", 12)

    meta = {"public_key_hex": pub_hex, "cases": cases}
    (FIXTURES_DIR / "fixtures_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"Generated {len(cases)} Week 2 fixtures in {FIXTURES_DIR}")


if __name__ == "__main__":
    main()
