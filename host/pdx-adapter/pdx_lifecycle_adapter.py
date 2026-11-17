#!/usr/bin/env python3
"""
PDX Lifecycle Adapter (Pinned to pdx-artifact-engine==0.3.0a12)
Maps real QNX /dev/pdxguardian receipts strictly to a12 External Operation Lifecycle
and exports a12 Provenance Bundle without fabricating unimplemented Engine features.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pdx_artifact_core as pdx_core


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_digest_str(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def map_qnx_receipt_to_pdx(
    qnx_receipt: dict[str, Any],
    manifest_bytes: bytes,
    firmware_bytes: bytes,
    output_dir: Path,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    op_id = qnx_receipt["operation_id"]
    decision = qnx_receipt["decision"]
    ts = utc_now_iso()

    req_digest = sha256_digest_str(manifest_bytes)
    in_digest = sha256_digest_str(firmware_bytes)
    out_digest = sha256_digest_str(json.dumps(qnx_receipt, sort_keys=True).encode("utf-8"))

    # 1. Create External Operation (submitted)
    op = pdx_core.create_external_operation(
        operation_id=op_id,
        provider="qnx-guardian-resmgr-v1",
        execution_mode="synchronous",
        request_id=f"req-{op_id}",
        idempotency_key=f"idem-{op_id}",
        request_digest=req_digest,
        input_digest=in_digest,
        submitted_at=ts,
        status="submitted",
    )

    # 2. Transition to pending (dispatched to /dev/pdxguardian)
    op = pdx_core.transition_external_operation(
        op,
        status="pending",
        updated_at=utc_now_iso(),
    )

    # 3. Map QNX deterministic gate outcome strictly to a12 contract
    if decision == "ALLOW" and qnx_receipt.get("slot_status") in (
        "STAGED_AND_ACTIVATED_SLOT_A",
        "STAGED_AND_ACTIVATED_SLOT_B",
    ):
        receipt_fw_sha = qnx_receipt.get("payload_sha256", "")
        if receipt_fw_sha != in_digest:
            raise ValueError(
                f"Receipt payload_sha256 mismatch for {op_id}: "
                f"receipt={receipt_fw_sha!r} != firmware={in_digest!r}"
            )
        slot_status = qnx_receipt["slot_status"]
        slot_dir = "slot_a" if slot_status.endswith("SLOT_A") else "slot_b"
        slot_slug = "slot-a" if slot_dir == "slot_a" else "slot-b"
        op = pdx_core.transition_external_operation(
            op,
            status="completed",
            updated_at=utc_now_iso(),
            output_digest=out_digest,
            artifacts=[
                {
                    "artifact_id": f"{slot_slug}-v{qnx_receipt.get('active_version')}",
                    "sha256": in_digest,
                    "size_bytes": len(firmware_bytes),
                    "media_type": "application/octet-stream",
                    "created_at": utc_now_iso(),
                    "uri": f"artifact://qnx-guardian/slots/{slot_dir}/firmware.bin",
                }
            ],
        )
    elif decision.startswith("DENY_"):
        op = pdx_core.transition_external_operation(
            op,
            status="failed",
            updated_at=utc_now_iso(),
            output_digest=out_digest,
            error={
                "code": decision,
                "message": f"QNX Guardian Gate rejected update: {decision}",
                "retryable": False,
            },
        )
    else:
        op = pdx_core.transition_external_operation(
            op,
            status="unknown_outcome",
            updated_at=utc_now_iso(),
            reconcile_required=True,
            error={
                "code": "UNKNOWN_OUTCOME",
                "message": "Target state uncertain; local journal reconciliation required.",
                "retryable": False,
            },
        )

    # 4. Validate External Operation against a12 schema
    op_errors = pdx_core.validate_external_operation(op)
    if op_errors:
        raise ValueError(f"Invalid external operation: {op_errors}")

    # 5. Export Provenance Bundle (a12)
    prov = pdx_core.create_provenance_bundle(
        bundle_id=f"prov-{op_id}",
        source_run_id=op_id,
        generated_at=utc_now_iso(),
        entities=[
            {
                "id": f"manifest-{op_id}",
                "type": "signed_manifest_v1",
                "digest": req_digest,
            },
            {
                "id": f"receipt-{op_id}",
                "type": "qnx_gate_receipt",
                "digest": out_digest,
            },
        ],
        activities=[
            {
                "id": f"gate-eval-{op_id}",
                "type": "qnx_resmgr_evaluation",
            }
        ],
        agents=[
            {
                "id": "qnx-guardian-gate",
                "type": "qnx_8_native_resmgr",
            }
        ],
        relations=[
            {
                "type": "used",
                "subject_id": f"gate-eval-{op_id}",
                "object_id": f"manifest-{op_id}",
            },
            {
                "type": "wasGeneratedBy",
                "subject_id": f"receipt-{op_id}",
                "object_id": f"gate-eval-{op_id}",
            },
        ],
    )
    prov_errors = pdx_core.validate_provenance_bundle(prov)
    if prov_errors:
        raise ValueError(f"Invalid provenance bundle: {prov_errors}")

    (output_dir / f"{op_id}_external_op.json").write_text(json.dumps(op, indent=2), encoding="utf-8")
    (output_dir / f"{op_id}_provenance.json").write_text(json.dumps(prov, indent=2), encoding="utf-8")
    return {"external_operation": op, "provenance": prov}


def reconcile_unknown_operation(
    op: dict[str, Any],
    post_crash_status: dict[str, Any],
    output_dir: Path,
    firmware_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Reconcile an unknown_outcome operation using QNX --status journal recovery evidence."""
    op_id = op["operation_id"]
    if post_crash_status.get("chain_valid") is not True:
        raise ValueError(f"Post-crash status chain_valid must be True for {op_id}")
    if post_crash_status.get("reconcile_performed") is not True:
        raise ValueError(f"Post-crash status reconcile_performed must be True for {op_id}")
    if post_crash_status.get("reconciled_op_id") != op_id:
        raise ValueError(
            f"Post-crash status reconciled_op_id mismatch: "
            f"{post_crash_status.get('reconciled_op_id')!r} != {op_id!r}"
        )
    rec_state = post_crash_status.get("reconciled_state")
    if rec_state not in ("RECONCILED_ABORTED", "RECONCILED_ACTIVATED"):
        raise ValueError(f"Post-crash status missing or invalid reconciled_state for {op_id}: {rec_state!r}")

    out_digest = sha256_digest_str(json.dumps(post_crash_status, sort_keys=True).encode("utf-8"))

    if rec_state == "RECONCILED_ACTIVATED":
        active_slot = post_crash_status.get("active_slot")
        if active_slot not in ("SLOT_A", "SLOT_B"):
            raise ValueError(f"RECONCILED_ACTIVATED requires valid active_slot, got: {active_slot!r}")
        slot_dir = "slot_a" if active_slot == "SLOT_A" else "slot_b"
        slot_slug = "slot-a" if active_slot == "SLOT_A" else "slot-b"
        fw_sha = sha256_digest_str(firmware_bytes) if firmware_bytes else ""
        reconciled = pdx_core.transition_external_operation(
            op,
            status="completed",
            updated_at=utc_now_iso(),
            output_digest=out_digest,
            reconcile_required=False,
            artifacts=[
                {
                    "artifact_id": f"{slot_slug}-v{post_crash_status.get('active_version')}",
                    "sha256": fw_sha,
                    "size_bytes": len(firmware_bytes or b""),
                    "media_type": "application/octet-stream",
                    "created_at": utc_now_iso(),
                    "uri": f"artifact://qnx-guardian/slots/{slot_dir}/firmware.bin",
                }
            ],
        )
    else:
        reconciled = pdx_core.transition_external_operation(
            op,
            status="failed",
            updated_at=utc_now_iso(),
            output_digest=out_digest,
            reconcile_required=False,
            error={
                "code": rec_state,
                "message": (
                    f"QNX journal auto-reconciled incomplete BEGIN_STAGE; "
                    f"active_version={post_crash_status.get('active_version')}, "
                    f"state={rec_state}"
                ),
                "retryable": False,
            },
        )
    rec_errors = pdx_core.validate_external_operation(reconciled)
    if rec_errors:
        raise ValueError(f"Invalid reconciled external operation: {rec_errors}")
    (output_dir / f"{op_id}_external_op_reconciled.json").write_text(
        json.dumps(reconciled, indent=2), encoding="utf-8"
    )
    return reconciled
