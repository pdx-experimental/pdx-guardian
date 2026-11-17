#!/usr/bin/env python3
"""
Week 4 Host Pipeline:
Independently reads raw per-sample CSVs (evidence/week4/samples/*.csv),
recomputes wakeup overruns, ECU deadline misses, p50/p99/p99.9/max, cross-checks
against QNX guest counts in qnx_week4_jitter.json, verifies against pre-frozen
thresholds via ProDocuX rc11, and renders evidence/week4/jitter_report.pdf.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

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


def recompute_from_csv(csv_path: Path, period_us: float = 10000.0) -> tuple[dict, str]:
    raw = csv_path.read_bytes()
    csv_sha = _sha256_bytes(raw)
    lines = raw.decode("utf-8").strip().splitlines()
    if len(lines) < 2 or lines[0].strip() != "sample_idx,signed_wakeup_us,work_span_us":
        raise ValueError(f"Malformed CSV header in {csv_path}")

    signed_vals: list[float] = []
    work_spans: list[float] = []
    for idx, line in enumerate(lines[1:]):
        parts = line.split(",")
        if len(parts) != 3 or int(parts[0]) != idx:
            raise ValueError(f"Malformed CSV row {idx} in {csv_path}: {line}")
        signed_vals.append(float(parts[1]))
        work_spans.append(float(parts[2]))

    abs_sorted = sorted(abs(v) for v in signed_vals)
    n = len(abs_sorted)
    return (
        {
            "csv_samples": n,
            "csv_wakeup_overruns": sum(1 for v in signed_vals if v > period_us),
            "csv_ecu_deadline_misses": sum(1 for w in work_spans if w > period_us),
            "csv_p50_us": round(abs_sorted[int((n - 1) * 0.50)], 3),
            "csv_p95_us": round(abs_sorted[int((n - 1) * 0.95)], 3),
            "csv_p99_us": round(abs_sorted[int((n - 1) * 0.99)], 3),
            "csv_p999_us": round(abs_sorted[int((n - 1) * 0.999)], 3),
            "csv_max_abs_us": round(abs_sorted[-1], 3),
        },
        csv_sha,
    )


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    evidence_dir = repo_root / "evidence" / "week4"
    jitter_path = evidence_dir / "qnx_week4_jitter.json"
    if not jitter_path.exists():
        raise FileNotFoundError(f"Missing {jitter_path}. Run scripts/run_week4_e2e.py first.")

    raw_bytes = jitter_path.read_bytes()
    doc_sha = _sha256_bytes(raw_bytes)
    payload = json.loads(raw_bytes.decode("utf-8"))
    runs = payload["runs"]
    if len(runs) != 9:
        raise ValueError(f"Expected 9 runs in {jitter_path}, got {len(runs)}")

    doc_id = "doc-wk4-jitter-3arm"
    documents = [
        EvidenceDocument(
            document_id=doc_id,
            source_sha256=doc_sha,
            media_type="application/json",
        )
    ]

    # Independently recompute every run from raw CSVs and cross-check with guest counts
    by_scenario: dict[str, list[dict]] = {"idle": [], "same-vcpu": [], "separated-vcpu": []}
    csv_doc_map: dict[str, tuple[str, str]] = {}
    recomputed_runs: list[tuple[dict, dict]] = []

    for r in runs:
        if not r.get("config_valid"):
            raise ValueError(f"Run marked config_valid=false: R{r['round']} {r['scenario']}")
        tag = f"r{r['round']}_{r['scenario']}"
        csv_rel = r.get("csv_file", f"samples/{tag}.csv")
        csv_path = evidence_dir / csv_rel
        if not csv_path.exists():
            raise FileNotFoundError(f"Missing raw sample CSV {csv_path}")

        csv_stats, csv_sha = recompute_from_csv(csv_path, float(r.get("period_us", 10000)))
        if csv_stats["csv_samples"] != r["completed_samples"]:
            raise ValueError(f"{tag}: CSV samples {csv_stats['csv_samples']} != guest {r['completed_samples']}")
        if csv_stats["csv_wakeup_overruns"] != r["wakeup_overruns"]:
            raise ValueError(f"{tag}: CSV wakeup_overruns {csv_stats['csv_wakeup_overruns']} != guest {r['wakeup_overruns']}")
        if csv_stats["csv_ecu_deadline_misses"] != r["ecu_deadline_misses"]:
            raise ValueError(f"{tag}: CSV ecu_deadline_misses {csv_stats['csv_ecu_deadline_misses']} != guest {r['ecu_deadline_misses']}")

        csv_doc_id = f"doc-csv-{tag}"
        documents.append(
            EvidenceDocument(
                document_id=csv_doc_id,
                source_sha256=csv_sha,
                media_type="text/csv",
            )
        )
        csv_doc_map[tag] = (csv_doc_id, csv_sha)
        recomputed_runs.append((r, csv_stats))
        by_scenario[r["scenario"]].append({"guest": r, "csv": csv_stats, "tag": tag})

    recomputed_summary: dict[str, dict] = {}
    evidence_items: list[EvidenceItem] = []
    checks: list[EvidenceCheck] = []

    for sc_name in ("idle", "same-vcpu", "separated-vcpu"):
        entries = by_scenario[sc_name]
        if len(entries) != 3:
            raise ValueError(f"Expected 3 rounds for {sc_name}, got {len(entries)}")

        sc = {
            "total_samples": sum(e["csv"]["csv_samples"] for e in entries),
            "wakeup_overruns_total": sum(e["csv"]["csv_wakeup_overruns"] for e in entries),
            "ecu_deadline_misses_total": sum(e["csv"]["csv_ecu_deadline_misses"] for e in entries),
            "p50_us_median": sorted(e["csv"]["csv_p50_us"] for e in entries)[1],
            "p99_us_median": sorted(e["csv"]["csv_p99_us"] for e in entries)[1],
            "p999_us_median": sorted(e["csv"]["csv_p999_us"] for e in entries)[1],
            "max_abs_us_worst": max(e["csv"]["csv_max_abs_us"] for e in entries),
        }
        recomputed_summary[sc_name] = sc

        rep_tag = entries[1]["tag"]
        rep_doc_id, rep_sha = csv_doc_map[rep_tag]
        src_ref = SourceReferenceV1(
            schema_version="prodocux_source_reference_v1",
            source_sha256=rep_sha,
            media_type="text/csv",
            locator=PdfPageLocator(kind="pdf_page", page=1),
            snippet=(
                f"{sc_name} (CSV-recomputed across 3 rounds): samples={sc['total_samples']} "
                f"wakeup_overruns={sc['wakeup_overruns_total']} ecu_misses={sc['ecu_deadline_misses_total']} "
                f"p50_med={sc['p50_us_median']}us p99_med={sc['p99_us_median']}us "
                f"p999_med={sc['p999_us_median']}us worst_max={sc['max_abs_us_worst']}us"
            ),
            extraction=ExtractionIdentity(
                method="host_supplied",
                extractor_id="pdx-guardian-csv-recomputer",
                extractor_version=prodocux_kernel.__version__,
            ),
            truncated=False,
        )

        ev_samples = EvidenceItem(
            evidence_id=f"ev-{sc_name}-samples",
            document_id=rep_doc_id,
            field_name=f"{sc_name}.csv_total_samples",
            value_type="number",
            value=int(sc["total_samples"]),
            confidence=1.0,
            source_reference=src_ref,
        )
        ev_overruns = EvidenceItem(
            evidence_id=f"ev-{sc_name}-overruns",
            document_id=rep_doc_id,
            field_name=f"{sc_name}.csv_wakeup_overruns_total",
            value_type="number",
            value=int(sc["wakeup_overruns_total"]),
            confidence=1.0,
            source_reference=src_ref,
        )
        ev_ecu_misses = EvidenceItem(
            evidence_id=f"ev-{sc_name}-ecu-misses",
            document_id=rep_doc_id,
            field_name=f"{sc_name}.csv_ecu_deadline_misses_total",
            value_type="number",
            value=int(sc["ecu_deadline_misses_total"]),
            confidence=1.0,
            source_reference=src_ref,
        )
        ev_p50 = EvidenceItem(
            evidence_id=f"ev-{sc_name}-p50",
            document_id=rep_doc_id,
            field_name=f"{sc_name}.csv_p50_us_median",
            value_type="number",
            value=float(sc["p50_us_median"]),
            confidence=1.0,
            source_reference=src_ref,
        )
        ev_p99 = EvidenceItem(
            evidence_id=f"ev-{sc_name}-p99",
            document_id=rep_doc_id,
            field_name=f"{sc_name}.csv_p99_us_median",
            value_type="number",
            value=float(sc["p99_us_median"]),
            confidence=1.0,
            source_reference=src_ref,
        )
        ev_max = EvidenceItem(
            evidence_id=f"ev-{sc_name}-max",
            document_id=rep_doc_id,
            field_name=f"{sc_name}.csv_max_abs_us_worst",
            value_type="number",
            value=float(sc["max_abs_us_worst"]),
            confidence=1.0,
            source_reference=src_ref,
        )
        evidence_items.extend([ev_samples, ev_overruns, ev_ecu_misses, ev_p50, ev_p99, ev_max])

        checks.extend([
            EvidenceCheck(
                check_id=f"chk-{sc_name}-samples",
                kind="numeric_range",
                evidence_ids=[ev_samples.evidence_id],
                minimum=30000.0,
                minimum_inclusive=True,
            ),
            EvidenceCheck(
                check_id=f"chk-{sc_name}-wakeup-overruns",
                kind="numeric_range",
                evidence_ids=[ev_overruns.evidence_id],
                minimum=0.0,
                minimum_inclusive=True,
                maximum=0.0,
                maximum_inclusive=True,
            ),
            EvidenceCheck(
                check_id=f"chk-{sc_name}-ecu-misses",
                kind="numeric_range",
                evidence_ids=[ev_ecu_misses.evidence_id],
                minimum=0.0,
                minimum_inclusive=True,
                maximum=0.0,
                maximum_inclusive=True,
            ),
            EvidenceCheck(
                check_id=f"chk-{sc_name}-p50-threshold",
                kind="numeric_range",
                evidence_ids=[ev_p50.evidence_id],
                minimum=0.0,
                minimum_inclusive=True,
                maximum=50.0,
                maximum_inclusive=True,
            ),
            EvidenceCheck(
                check_id=f"chk-{sc_name}-p99-threshold",
                kind="numeric_range",
                evidence_ids=[ev_p99.evidence_id],
                minimum=0.0,
                minimum_inclusive=True,
                maximum=250.0,
                maximum_inclusive=True,
            ),
            EvidenceCheck(
                check_id=f"chk-{sc_name}-max-threshold",
                kind="numeric_range",
                evidence_ids=[ev_max.evidence_id],
                minimum=0.0,
                minimum_inclusive=True,
                maximum=1500.0,
                maximum_inclusive=True,
            ),
        ])

    report_title = "PDX-Guardian Week 4: 3-Arm Interleaved Jitter Benchmark Report"
    rule_set_bytes = json.dumps(
        {"rule_set": "pdx-guardian-jitter-gate-v3-csv-verified", "title": report_title},
        sort_keys=True,
    ).encode("utf-8")

    req = EvidenceBundleRequestV1(
        schema_version="prodocux_evidence_bundle_request_v1",
        request_id=f"req-{_sha256_bytes(report_title.encode('utf-8'))[:16]}",
        rule_set=EvidenceRuleSet(
            id="pdx-guardian-jitter-gate",
            version="3.0.0",
            sha256=_sha256_bytes(rule_set_bytes),
        ),
        documents=documents,
        evidence=evidence_items,
        checks=checks,
    )
    res_obj = verify_evidence_bundle(req)
    verification_result = res_obj if isinstance(res_obj, dict) else res_obj.model_dump(mode="json")

    ver_path = evidence_dir / "prodocux_jitter_verification.json"
    ver_path.write_text(json.dumps(verification_result, indent=2), encoding="utf-8")

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    kv_pairs = [
        {"label": "Generated At", "value": generated_at},
        {"label": "ProDocuX Kernel", "value": f"prodocux_kernel {prodocux_kernel.__version__}"},
        {"label": "Verification Status", "value": verification_result["status"].upper()},
        {"label": "Canonical Request SHA-256", "value": verification_result["canonical_request_sha256"]},
        {"label": "Environment", "value": payload["environment"]},
        {"label": "Evidence Source", "value": "9 raw per-sample CSVs (90,000 samples, Host-recomputed & guest-cross-checked)"},
        {"label": "Disclaimer", "value": payload["disclaimer"]},
    ]

    summary_rows = [
        ["Scenario (3 rounds)", "Total Samples", "Wakeup Overruns", "ECU Misses", "p50 Med (us)", "p99 Med (us)", "p99.9 Med (us)", "Worst Max (us)"]
    ]
    for sc_name in ("idle", "same-vcpu", "separated-vcpu"):
        sc = recomputed_summary[sc_name]
        summary_rows.append([
            sc_name,
            str(sc["total_samples"]),
            str(sc["wakeup_overruns_total"]),
            str(sc["ecu_deadline_misses_total"]),
            f"{sc['p50_us_median']:.3f}",
            f"{sc['p99_us_median']:.3f}",
            f"{sc['p999_us_median']:.3f}",
            f"{sc['max_abs_us_worst']:.3f}",
        ])

    run_rows = [
        ["Round / Scenario", "Valid", "CSV Samples", "Wakeup / ECU Miss", "p50 (us)", "p99 (us)", "p99.9 (us)", "Max (us)", "SHA-256 / fsync OK"]
    ]
    for r, hr in recomputed_runs:
        run_rows.append([
            f"R{r['round']} {r['scenario']}",
            str(r["config_valid"]),
            str(hr["csv_samples"]),
            f"{hr['csv_wakeup_overruns']} / {hr['csv_ecu_deadline_misses']}",
            f"{hr['csv_p50_us']:.3f}",
            f"{hr['csv_p99_us']:.3f}",
            f"{hr['csv_p999_us']:.3f}",
            f"{hr['csv_max_abs_us']:.3f}",
            f"{r['worker_sha256_iterations']} / {r['worker_io_fsync_ok']}",
        ])

    content_blocks = {
        "schema_version": "prodocux_content_blocks_v1",
        "document": {"title": report_title},
        "blocks": [
            {"id": "blk-heading", "type": "heading", "level": 1, "text": report_title},
            {"id": "blk-summary", "type": "key_values", "pairs": kv_pairs},
            {"id": "blk-tbl-heading", "type": "heading", "level": 2, "text": "3-Arm Scenario Summary (Host-Recomputed from Raw CSVs)"},
            {"id": "blk-table-summary", "type": "table", "table": {"rows": summary_rows}},
            {"id": "blk-runs-heading", "type": "heading", "level": 2, "text": "Per-Run CSV-Verified Measurements"},
            {"id": "blk-table-runs", "type": "table", "table": {"rows": run_rows}},
        ],
    }
    validate_content_blocks(content_blocks)
    pdf_bytes = write_content_blocks(content_blocks, "pdf")
    pdf_path = evidence_dir / "jitter_report.pdf"
    pdf_path.write_bytes(pdf_bytes)

    print(f"[ProDocuX Verifier] status={verification_result['status']} canonical_sha256={verification_result['canonical_request_sha256']}")
    print(f"[ProDocuX Renderer] Generated PDF report: {pdf_path}")
    return 0 if verification_result["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
