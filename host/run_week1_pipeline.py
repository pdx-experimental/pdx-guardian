#!/usr/bin/env python3
"""
Host Pipeline Runner for Week 1 Thin Vertical Thread:
Takes captured QNX /dev/pdxguardian receipts, runs PDX 0.3.0a12 lifecycle adapter,
and exports ProDocuX 0.3.0rc11 PDF audit report.
"""

import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "host" / "pdx-adapter"))
sys.path.insert(0, str(ROOT_DIR / "host" / "report-adapter"))

from pdx_lifecycle_adapter import map_qnx_receipt_to_pdx
from generate_report import generate_guardian_pdf


def main() -> int:
    fixtures_dir = ROOT_DIR / "simulator" / "fixtures" / "week1"
    evidence_dir = ROOT_DIR / "evidence" / "week1"
    receipts_file = evidence_dir / "qnx_receipts.jsonl"

    if not receipts_file.exists():
        print(f"Missing {receipts_file}", file=sys.stderr)
        return 1

    records = []
    lines = [ln.strip() for ln in receipts_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
    mapping = [
        ("manifest_v11.bin", "fw_v11.bin"),
        ("manifest_v12.bin", "fw_v12_tampered.bin"),
    ]

    expected_w1 = {
        "op-week1-thin-thread-0001": ("ALLOW", "completed", "artifact://qnx-guardian/slots/slot_b/firmware.bin"),
        "op-week1-tamper-test-0002": ("DENY_HASH", "failed", None),
    }

    for idx, line in enumerate(lines):
        qnx_receipt = json.loads(line)
        m_name, fw_name = mapping[idx] if idx < len(mapping) else ("manifest_v11.bin", "fw_v11.bin")
        m_bytes = (fixtures_dir / m_name).read_bytes()
        fw_bytes = (fixtures_dir / fw_name).read_bytes()

        pdx_out = map_qnx_receipt_to_pdx(qnx_receipt, m_bytes, fw_bytes, evidence_dir)
        exp_qnx, exp_pdx, exp_uri = expected_w1[qnx_receipt["operation_id"]]
        rec = {
            "qnx_receipt": qnx_receipt,
            "pdx": pdx_out,
            "expected_qnx_decision": exp_qnx,
            "expected_pdx_status": exp_pdx,
        }
        if exp_uri is not None:
            rec["expected_artifact_uri"] = exp_uri
        records.append(rec)
        print(f"[PDX Adapter] {qnx_receipt['operation_id']} -> PDX status: {pdx_out['external_operation']['status']}")

    report_pdf = evidence_dir / "guardian_report.pdf"
    generate_guardian_pdf(records, report_pdf)
    print(f"[ProDocuX Reporter] Generated PDF report: {report_pdf}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
