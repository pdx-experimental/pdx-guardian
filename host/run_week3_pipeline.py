#!/usr/bin/env python3
"""
Host Pipeline Runner for Week 3 10-Fault Suite (T01-T10):
Takes captured QNX /dev/pdxguardian receipts & post-crash statuses from
evidence/week3/qnx_week3_results.json, enforces completeness of all 10 fault
scenarios, independently recomputes expected firmware SHA-256 from fixture bytes,
runs PDX 0.3.0a12 lifecycle adapter, and runs ProDocuX 0.3.0rc11 verification +
PDF rendering (evidence/week3/guardian_report.pdf).
"""

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "host" / "pdx-adapter"))
sys.path.insert(0, str(ROOT_DIR / "host" / "report-adapter"))

from pdx_lifecycle_adapter import map_qnx_receipt_to_pdx, reconcile_unknown_operation
from generate_report import generate_guardian_pdf

EXPECTED_RECEIPT_OPS = {
    "op-wk3-t01-valid-v11": ("ALLOW", "completed", "artifact://qnx-guardian/slots/slot_b/firmware.bin"),
    "op-wk3-t02-tamper-v12": ("DENY_HASH", "failed", None),
    "op-wk3-t03-badsig-v12": ("DENY_SIGNATURE", "failed", None),
    "op-wk3-t04-rollback-v09": ("DENY_ROLLBACK", "failed", None),
    "op-wk3-t05-speed-v12": ("DENY_NOT_STATIONARY", "failed", None),
    "op-wk3-t06-hwrev-v12": ("DENY_HW_REV", "failed", None),
    "op-wk3-t08-replay-v13": ("DENY_ROLLBACK", "failed", None),
    "op-wk3-t09-ioerr-v13": ("UNKNOWN_OUTCOME", "unknown_outcome", None),
    "op-wk3-t09b-locked-v14": ("UNKNOWN_OUTCOME", "unknown_outcome", None),
}

EXPECTED_CRASH_OPS = {
    "op-wk3-t07-crash-v12": ("SIGKILL(tmp) -> RECONCILED_ABORTED", "failed", None, "op-wk3-t01-valid-v11"),
    "op-wk3-t07b-rename-v12": ("SIGKILL(after-rename) -> RECONCILED_ABORTED", "failed", None, "op-wk3-t01-valid-v11"),
    "op-wk3-t07c-ver-v12": (
        "SIGKILL(after-version) -> RECONCILED_ACTIVATED",
        "completed",
        "artifact://qnx-guardian/slots/slot_a/firmware.bin",
        "op-wk3-t07c-ver-v12",
    ),
    "op-wk3-t09-ioerr-v13": ("PERSIST_ERR -> RECONCILED_ABORTED", "failed", None, "op-wk3-t07c-ver-v12"),
}


def run_week3_pipeline(
    results: dict[str, Any],
    fixtures_dir: Path,
    evidence_dir: Path,
) -> dict[str, Any]:
    if results.get("t10_tamper_fail_closed") is not True:
        raise ValueError("Missing mandatory T10 tampered-journal fail-closed evidence")

    meta = json.loads((fixtures_dir / "fixtures_meta.json").read_text(encoding="utf-8"))
    case_by_op = {c["operation_id"]: c for c in meta["cases"]}

    seen_receipts: set[str] = set()
    records: list[dict[str, Any]] = []

    for qnx_receipt in results.get("receipts", []):
        op_id = qnx_receipt.get("operation_id", "")
        if op_id in seen_receipts:
            raise ValueError(f"Duplicate receipt operation_id: {op_id}")
        if op_id not in EXPECTED_RECEIPT_OPS:
            raise ValueError(f"Unexpected receipt operation_id: {op_id}")
        seen_receipts.add(op_id)

        c = case_by_op[op_id]
        m_bytes = (fixtures_dir / c["manifest_file"]).read_bytes()
        fw_bytes = (fixtures_dir / c["firmware_file"]).read_bytes()

        pdx_out = map_qnx_receipt_to_pdx(qnx_receipt, m_bytes, fw_bytes, evidence_dir)
        exp_qnx, exp_pdx, exp_uri = EXPECTED_RECEIPT_OPS[op_id]
        receipt_for_report = dict(qnx_receipt)
        rec: dict[str, Any] = {
            "qnx_receipt": receipt_for_report,
            "pdx": pdx_out,
            "expected_qnx_decision": exp_qnx,
            "expected_pdx_status": exp_pdx,
        }
        if exp_pdx == "completed":
            receipt_for_report["active_fw_sha256"] = qnx_receipt.get("payload_sha256")
            receipt_for_report["expected_fw_sha256"] = hashlib.sha256(fw_bytes).hexdigest()
            rec["require_fw_sha"] = True
        if exp_uri is not None:
            rec["expected_artifact_uri"] = exp_uri

        # Skip adding raw T09 UNKNOWN_OUTCOME here because T09_REC below provides its reconciled record
        if op_id != "op-wk3-t09-ioerr-v13":
            records.append(rec)
        print(
            f"[PDX Adapter] {op_id} -> QNX={qnx_receipt['decision']} "
            f"-> PDX={pdx_out['external_operation']['status']}"
        )

    if seen_receipts != set(EXPECTED_RECEIPT_OPS.keys()):
        missing = sorted(set(EXPECTED_RECEIPT_OPS.keys()) - seen_receipts)
        raise ValueError(f"Missing required receipt operations: {missing}")

    seen_crashes: set[str] = set()
    for rec_item in results.get("crash_recoveries", []):
        op_id = rec_item.get("operation_id", "")
        if op_id in seen_crashes:
            raise ValueError(f"Duplicate crash_recovery operation_id: {op_id}")
        if op_id not in EXPECTED_CRASH_OPS:
            raise ValueError(f"Unexpected crash_recovery operation_id: {op_id}")
        seen_crashes.add(op_id)

        crash_point = rec_item["crash_point"]
        status_obj = rec_item["status"]
        c = case_by_op[op_id]
        m_bytes = (fixtures_dir / c["manifest_file"]).read_bytes()
        fw_bytes = (fixtures_dir / c["firmware_file"]).read_bytes()

        exp_qnx, exp_pdx, exp_uri, expected_fw_op = EXPECTED_CRASH_OPS[op_id]
        expected_fw_case = case_by_op[expected_fw_op]
        expected_fw_bytes = (fixtures_dir / expected_fw_case["firmware_file"]).read_bytes()
        host_expected_fw_sha256 = hashlib.sha256(expected_fw_bytes).hexdigest()

        derived_receipt = {
            "operation_id": op_id,
            "decision": "UNKNOWN_OUTCOME",
            "active_version": status_obj.get("active_version", 11),
            "target_version": c["target_version"],
            "slot_status": f"CRASH_{crash_point.upper()}",
            "payload_sha256": hashlib.sha256(fw_bytes).hexdigest(),
            "derived_observation": True,
            "active_fw_sha256": rec_item.get("active_fw_sha256"),
            "expected_fw_sha256": host_expected_fw_sha256,
        }
        pdx_out = map_qnx_receipt_to_pdx(derived_receipt, m_bytes, fw_bytes, evidence_dir)
        initial_status = pdx_out["external_operation"]["status"]
        reconciled_op = reconcile_unknown_operation(
            pdx_out["external_operation"], status_obj, evidence_dir, firmware_bytes=fw_bytes
        )
        pdx_out["external_operation"] = reconciled_op
        rec_state = status_obj["reconciled_state"]
        slot_lbl = status_obj["active_slot"]
        prefix = "PERSIST_ERR" if crash_point == "persist-error" else f"SIGKILL({crash_point})"
        report_receipt = {
            **derived_receipt,
            "decision": f"{prefix} -> {rec_state}",
            "slot_status": slot_lbl,
        }
        rec = {
            "qnx_receipt": report_receipt,
            "pdx": pdx_out,
            "expected_qnx_decision": exp_qnx,
            "expected_pdx_status": exp_pdx,
            "require_fw_sha": True,
        }
        if exp_uri is not None:
            rec["expected_artifact_uri"] = exp_uri
        records.append(rec)
        print(
            f"[PDX Adapter] {op_id} -> QNX={prefix}/{rec_state} "
            f"-> PDX={initial_status} -> {reconciled_op['status']}"
        )

    if seen_crashes != set(EXPECTED_CRASH_OPS.keys()):
        missing = sorted(set(EXPECTED_CRASH_OPS.keys()) - seen_crashes)
        raise ValueError(f"Missing required crash_recovery operations: {missing}")

    report_pdf = evidence_dir / "guardian_report.pdf"
    verif = generate_guardian_pdf(
        records,
        report_pdf,
        report_title="PDX-Guardian Week 3: 10-Fault Suite & PDX Lifecycle Audit",
        extra_summary={
            "T10 Tampered Journal Fail-Closed": str(results.get("t10_tamper_fail_closed")),
            "Journal Entries Verified": str(len(results.get("journal_chain", []))),
            "Independent Hash Chain": str(results.get("independent_hash_chain_verified", False)),
            "Serial Transcript": str(results.get("serial_transcript_file", "")),
        },
    )
    print(f"[ProDocuX Verifier] status={verif['status']} canonical_sha256={verif['canonical_request_sha256']}")
    print(f"[ProDocuX Renderer] Generated PDF report: {report_pdf}")
    return verif


def main() -> int:
    fixtures_dir = ROOT_DIR / "simulator" / "fixtures" / "week3"
    evidence_dir = ROOT_DIR / "evidence" / "week3"
    results_file = evidence_dir / "qnx_week3_results.json"

    if not results_file.exists():
        print(f"Missing {results_file}", file=sys.stderr)
        return 1

    results = json.loads(results_file.read_text(encoding="utf-8"))
    run_week3_pipeline(results, fixtures_dir, evidence_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
