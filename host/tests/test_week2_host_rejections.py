#!/usr/bin/env python3
"""
Negative & A/B Slot Unit Tests for Week 2 Host Pipeline, PDX Adapter, and ProDocuX Verifier.
Verifies:
1. Normal ALLOW on SLOT_A maps to completed + slot-a artifact URI.
2. Missing case in results is rejected (fail closed).
3. Missing active_fw_sha256 on crash recovery is rejected (fail closed).
4. Wrong slot (SLOT_B instead of SLOT_A on T07C) is rejected by ProDocuX gate.
5. Decision flip (T02 DENY_HASH -> ALLOW) is rejected by ProDocuX gate.
"""

import copy
import json
import sys
import tempfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT_DIR / "host"))
sys.path.insert(0, str(ROOT_DIR / "host" / "pdx-adapter"))

from pdx_lifecycle_adapter import map_qnx_receipt_to_pdx
from run_week2_pipeline import run_week2_pipeline


def expect_raises(exc_type: type[Exception], fn, label: str) -> None:
    try:
        fn()
    except exc_type as exc:
        print(f"[PASS] {label}: raised {exc_type.__name__}: {exc}")
        return
    raise AssertionError(f"[FAIL] {label}: did NOT raise {exc_type.__name__}")


def main() -> int:
    fixtures_dir = ROOT_DIR / "simulator" / "fixtures" / "week2"
    results_path = ROOT_DIR / "evidence" / "week2" / "qnx_week2_results.json"
    base_results = json.loads(results_path.read_text(encoding="utf-8"))

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)

        # 1. Normal ALLOW on SLOT_A
        fw_bytes = (fixtures_dir / "t01_fw_v11.bin").read_bytes()
        m_bytes = (fixtures_dir / "t01_manifest_v11.bin").read_bytes()
        slot_a_receipt = {
            "operation_id": "op-test-slot-a-v11",
            "decision": "ALLOW",
            "slot_status": "STAGED_AND_ACTIVATED_SLOT_A",
            "active_version": 11,
            "target_version": 11,
            "payload_sha256": "7bc00a28181d18b9a1f049035995657e71ba4ac73338bd9110183f2e8a2557a0",
        }
        pdx_a = map_qnx_receipt_to_pdx(slot_a_receipt, m_bytes, fw_bytes, tmp_dir / "t1")
        op_a = pdx_a["external_operation"]
        assert op_a["status"] == "completed", op_a
        assert op_a["artifacts"][0]["artifact_id"] == "slot-a-v11", op_a["artifacts"]
        assert op_a["artifacts"][0]["uri"] == "artifact://qnx-guardian/slots/slot_a/firmware.bin", op_a["artifacts"]
        print("[PASS] Normal ALLOW on SLOT_A -> completed + slots/slot_a/firmware.bin")

        # 2. Missing case (remove T05)
        res_missing = copy.deepcopy(base_results)
        res_missing["receipts"] = [r for r in res_missing["receipts"] if r["operation_id"] != "op-wk2-t05-speed-v12"]
        expect_raises(
            ValueError,
            lambda: run_week2_pipeline(res_missing, fixtures_dir, tmp_dir / "t2"),
            "Missing case T05",
        )

        # 3. Missing active_fw_sha256 on crash recovery T07
        res_no_sha = copy.deepcopy(base_results)
        res_no_sha["crash_recoveries"][0].pop("active_fw_sha256", None)
        expect_raises(
            ValueError,
            lambda: run_week2_pipeline(res_no_sha, fixtures_dir, tmp_dir / "t3"),
            "Missing active_fw_sha256 on T07",
        )

        # 4. Wrong slot on T07C (SLOT_B instead of SLOT_A)
        res_wrong_slot = copy.deepcopy(base_results)
        res_wrong_slot["crash_recoveries"][2]["status"]["active_slot"] = "SLOT_B"
        expect_raises(
            RuntimeError,
            lambda: run_week2_pipeline(res_wrong_slot, fixtures_dir, tmp_dir / "t4"),
            "Wrong slot SLOT_B on T07C",
        )

        # 5. Decision flip on T03 (DENY_SIGNATURE -> ALLOW) caught by ProDocuX verifier
        res_flip = copy.deepcopy(base_results)
        for r in res_flip["receipts"]:
            if r["operation_id"] == "op-wk2-t03-badsig-v12":
                r["decision"] = "ALLOW"
                r["slot_status"] = "STAGED_AND_ACTIVATED_SLOT_A"
        expect_raises(
            RuntimeError,
            lambda: run_week2_pipeline(res_flip, fixtures_dir, tmp_dir / "t5"),
            "Decision flip T03 DENY_SIGNATURE -> ALLOW",
        )

        # 6. Missing reconciled_state on T07
        res_no_state = copy.deepcopy(base_results)
        res_no_state["crash_recoveries"][0]["status"].pop("reconciled_state", None)
        expect_raises(
            ValueError,
            lambda: run_week2_pipeline(res_no_state, fixtures_dir, tmp_dir / "t6"),
            "Missing reconciled_state on T07",
        )

        # 7. Contradictory recovery evidence (chain_valid=False, reconcile_performed=False, wrong op_id)
        res_bad_rec = copy.deepcopy(base_results)
        res_bad_rec["crash_recoveries"][0]["status"]["chain_valid"] = False
        res_bad_rec["crash_recoveries"][0]["status"]["reconcile_performed"] = False
        res_bad_rec["crash_recoveries"][0]["status"]["reconciled_op_id"] = "op-wrong"
        expect_raises(
            ValueError,
            lambda: run_week2_pipeline(res_bad_rec, fixtures_dir, tmp_dir / "t7"),
            "Contradictory recovery evidence on T07",
        )

        # 8. Tampered payload_sha256 on T01 ALLOW receipt
        res_bad_sha = copy.deepcopy(base_results)
        for r in res_bad_sha["receipts"]:
            if r["operation_id"] == "op-wk2-t01-valid-v11":
                r["payload_sha256"] = "0" * 64
        expect_raises(
            ValueError,
            lambda: run_week2_pipeline(res_bad_sha, fixtures_dir, tmp_dir / "t8"),
            "Tampered payload_sha256 on T01 ALLOW receipt",
        )

    print("ALL 8 HOST REJECTION & A/B SLOT TESTS PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
