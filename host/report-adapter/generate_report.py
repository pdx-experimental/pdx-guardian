#!/usr/bin/env python3
"""
ProDocuX Evidence Verifier & Report Generator (Pinned to prodocux==0.3.0rc11)
1. Runs prodocux_kernel.verification.verify_evidence_bundle on QNX + PDX records.
2. Validates prodocux_content_blocks_v1 and deterministically renders the PDF
   audit report via prodocux_kernel.rendering.write_content_blocks(..., "pdf").
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import prodocux_kernel
from prodocux_kernel.rendering import validate_content_blocks, write_content_blocks
from prodocux_kernel.verification import verify_evidence_bundle
from prodocux_kernel.verification.evidence_models import (
    EvidenceBundleRequestV1,
    EvidenceCheck,
    EvidenceDocument,
    EvidenceItem,
    EvidenceRuleSet,
    ExtractionIdentity,
    PdfPageLocator,
    SourceReferenceV1,
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_and_build_prodocux_bundle(
    evidence_records: list[dict[str, Any]],
    report_title: str,
) -> dict[str, Any]:
    """Verify QNX + PDX evidence records using prodocux_kernel.verification."""
    documents: list[EvidenceDocument] = []
    evidence_items: list[EvidenceItem] = []
    checks: list[EvidenceCheck] = []

    for idx, rec in enumerate(evidence_records, start=1):
        qnx = rec["qnx_receipt"]
        ext_op = rec["pdx"]["external_operation"]
        op_id = str(qnx.get("operation_id", f"op-{idx}"))
        doc_id = f"doc-{idx}-{op_id}"
        raw_bytes = json.dumps(rec, sort_keys=True).encode("utf-8")
        doc_sha = _sha256_bytes(raw_bytes)

        documents.append(
            EvidenceDocument(
                document_id=doc_id,
                source_sha256=doc_sha,
                media_type="application/json",
            )
        )

        src_ref = SourceReferenceV1(
            schema_version="prodocux_source_reference_v1",
            source_sha256=doc_sha,
            media_type="application/json",
            locator=PdfPageLocator(kind="pdf_page", page=1),
            snippet=f"{op_id}: qnx={qnx.get('decision')} pdx={ext_op.get('status')}",
            extraction=ExtractionIdentity(
                method="host_supplied",
                extractor_id="pdx-guardian-host-adapter",
                extractor_version=prodocux_kernel.__version__,
            ),
            truncated=False,
        )

        ev_op = EvidenceItem(
            evidence_id=f"ev-{idx}-op",
            document_id=doc_id,
            field_name="operation_id",
            value_type="string",
            value=op_id,
            confidence=1.0,
            source_reference=src_ref,
        )
        ev_dec = EvidenceItem(
            evidence_id=f"ev-{idx}-decision",
            document_id=doc_id,
            field_name="qnx_decision",
            value_type="string",
            value=str(qnx.get("decision", "")),
            confidence=1.0,
            source_reference=src_ref,
        )
        ev_pdx = EvidenceItem(
            evidence_id=f"ev-{idx}-pdx-status",
            document_id=doc_id,
            field_name="pdx_status",
            value_type="string",
            value=str(ext_op.get("status", "")),
            confidence=1.0,
            source_reference=src_ref,
        )
        ev_ver = EvidenceItem(
            evidence_id=f"ev-{idx}-active-ver",
            document_id=doc_id,
            field_name="active_version",
            value_type="integer",
            value=int(qnx.get("active_version", 0)),
            confidence=1.0,
            source_reference=src_ref,
        )
        evidence_items.extend([ev_op, ev_dec, ev_pdx, ev_ver])

        checks.append(
            EvidenceCheck(
                check_id=f"chk-{idx}-presence",
                kind="presence",
                evidence_ids=[ev_op.evidence_id, ev_dec.evidence_id, ev_pdx.evidence_id],
                minimum_confidence=1.0,
            )
        )
        checks.append(
            EvidenceCheck(
                check_id=f"chk-{idx}-version-floor",
                kind="numeric_range",
                evidence_ids=[ev_ver.evidence_id],
                minimum=10.0,
                minimum_inclusive=True,
            )
        )

        expected_qnx = rec.get("expected_qnx_decision")
        expected_pdx = rec.get("expected_pdx_status")
        if not expected_qnx or not expected_pdx:
            raise ValueError(f"Record {op_id} missing mandatory expected_qnx_decision or expected_pdx_status")

        checks.append(
            EvidenceCheck(
                check_id=f"chk-{idx}-qnx-decision-match",
                kind="equality",
                evidence_ids=[ev_dec.evidence_id],
                expected=str(expected_qnx),
            )
        )
        checks.append(
            EvidenceCheck(
                check_id=f"chk-{idx}-pdx-status-match",
                kind="equality",
                evidence_ids=[ev_pdx.evidence_id],
                expected=str(expected_pdx),
            )
        )

        require_fw_sha = bool(rec.get("require_fw_sha") or qnx.get("derived_observation"))
        if require_fw_sha:
            active_fw_sha = qnx.get("active_fw_sha256")
            expected_fw_sha = qnx.get("expected_fw_sha256")
            if not active_fw_sha or not expected_fw_sha:
                raise ValueError(
                    f"Record {op_id} requires active_fw_sha256 and expected_fw_sha256, got "
                    f"active={active_fw_sha!r}, expected={expected_fw_sha!r}"
                )
            ev_fw = EvidenceItem(
                evidence_id=f"ev-{idx}-active-fw-sha",
                document_id=doc_id,
                field_name="active_fw_sha256",
                value_type="string",
                value=str(active_fw_sha),
                confidence=1.0,
                source_reference=src_ref,
            )
            evidence_items.append(ev_fw)
            checks.append(
                EvidenceCheck(
                    check_id=f"chk-{idx}-active-fw-sha-match",
                    kind="equality",
                    evidence_ids=[ev_fw.evidence_id],
                    expected=str(expected_fw_sha),
                )
            )

        expected_uri = rec.get("expected_artifact_uri")
        if expected_uri is not None:
            artifacts = ext_op.get("artifacts") or []
            actual_uri = str(artifacts[0].get("uri", "")) if artifacts else ""
            ev_uri = EvidenceItem(
                evidence_id=f"ev-{idx}-artifact-uri",
                document_id=doc_id,
                field_name="artifact_uri",
                value_type="string",
                value=actual_uri,
                confidence=1.0,
                source_reference=src_ref,
            )
            evidence_items.append(ev_uri)
            checks.append(
                EvidenceCheck(
                    check_id=f"chk-{idx}-artifact-uri-match",
                    kind="equality",
                    evidence_ids=[ev_uri.evidence_id],
                    expected=str(expected_uri),
                )
            )

    rule_set_bytes = json.dumps(
        {"rule_set": "pdx-guardian-ota-gate-v1", "title": report_title},
        sort_keys=True,
    ).encode("utf-8")

    req = EvidenceBundleRequestV1(
        schema_version="prodocux_evidence_bundle_request_v1",
        request_id=f"req-{_sha256_bytes(report_title.encode('utf-8'))[:16]}",
        rule_set=EvidenceRuleSet(
            id="pdx-guardian-ota-gate",
            version="1.0.0",
            sha256=_sha256_bytes(rule_set_bytes),
        ),
        documents=documents,
        evidence=evidence_items,
        checks=checks,
    )
    result = verify_evidence_bundle(req)
    return result if isinstance(result, dict) else result.model_dump(mode="json")


def generate_guardian_pdf(
    evidence_records: list[dict[str, Any]],
    output_pdf: Path,
    report_title: str = "PDX-Guardian: Vehicle OTA & Crash Recovery Audit Report",
    extra_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    output_pdf.parent.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    verification_result = verify_and_build_prodocux_bundle(evidence_records, report_title)
    if verification_result["status"] != "pass":
        raise RuntimeError(
            f"ProDocuX evidence verification failed: {json.dumps(verification_result)}"
        )

    verification_path = output_pdf.with_name("prodocux_evidence_verification.json")
    verification_path.write_text(
        json.dumps(verification_result, indent=2), encoding="utf-8"
    )

    kv_pairs = [
        {"label": "Generated At", "value": generated_at},
        {"label": "ProDocuX Kernel", "value": f"prodocux_kernel {prodocux_kernel.__version__}"},
        {"label": "Verification Status", "value": verification_result["status"].upper()},
        {"label": "Canonical Request SHA-256", "value": verification_result["canonical_request_sha256"]},
        {"label": "Checks Executed", "value": str(len(verification_result["results"]))},
        {"label": "Target Hardware", "value": "QNX 8.0 x86_64 QEMU (fs-qnx6)"},
    ]
    if extra_summary:
        for k, v in extra_summary.items():
            kv_pairs.append({"label": str(k), "value": str(v)})

    rows: list[list[str]] = [
        ["Operation ID", "QNX Decision", "Slot / Active Ver", "PDX Status", "Derived", "Payload SHA-256 (16B)"]
    ]
    for rec in evidence_records:
        qnx = rec["qnx_receipt"]
        ext_op = rec["pdx"]["external_operation"]
        rows.append([
            str(qnx.get("operation_id", "")),
            str(qnx.get("decision", "")),
            f"{qnx.get('slot_status', '')} (v{qnx.get('active_version', '')})",
            str(ext_op.get("status", "")),
            "yes" if qnx.get("derived_observation") else "no",
            str(qnx.get("payload_sha256", ""))[:16],
        ])

    content_blocks: dict[str, Any] = {
        "schema_version": "prodocux_content_blocks_v1",
        "document": {"title": report_title},
        "blocks": [
            {"id": "blk-heading", "type": "heading", "level": 1, "text": report_title},
            {"id": "blk-summary", "type": "key_values", "pairs": kv_pairs},
            {"id": "blk-tbl-heading", "type": "heading", "level": 2, "text": "Verified QNX Gate & PDX Lifecycle Evidence"},
            {
                "id": "blk-table",
                "type": "table",
                "table": {"rows": rows},
            },
        ],
    }
    validate_content_blocks(content_blocks)
    pdf_bytes = write_content_blocks(content_blocks, "pdf")
    output_pdf.write_bytes(pdf_bytes)
    return verification_result
