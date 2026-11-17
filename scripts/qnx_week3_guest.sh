#!/bin/sh
PUBKEY="$1"
if [ -z "$PUBKEY" ]; then
    echo "Missing pubkey"
    exit 1
fi

curl -sS http://10.0.2.2:18080/qnx/guardian-gate/guardian_gate.elf -o guardian_gate.elf &&
curl -sS http://10.0.2.2:18080/qnx/guardian-gate/gate_submit.elf -o gate_submit.elf &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t01_manifest_v11.bin -o t01_m.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t01_fw_v11.bin -o t01_fw.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t02_manifest_v12.bin -o t02_m.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t02_fw_v12_tampered.bin -o t02_fw.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t03_manifest_v12_badsig.bin -o t03_m.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t03_fw_v12.bin -o t03_fw.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t04_manifest_v09.bin -o t04_m.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t04_fw_v09.bin -o t04_fw.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t05_manifest_v12.bin -o t05_m.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t05_fw_v12.bin -o t05_fw.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t06_manifest_v12_hwrev.bin -o t06_m.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t06_fw_v12.bin -o t06_fw.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t07_manifest_v12.bin -o t07_m.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t07_fw_v12.bin -o t07_fw.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t07b_manifest_v12.bin -o t07b_m.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t07b_fw_v12.bin -o t07b_fw.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t07c_manifest_v12.bin -o t07c_m.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t07c_fw_v12.bin -o t07c_fw.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t08_manifest_v13_replay.bin -o t08_m.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t08_fw_v13.bin -o t08_fw.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t09_manifest_v13.bin -o t09_m.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t09_fw_v13.bin -o t09_fw.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t09b_manifest_v14.bin -o t09b_m.bin &&
curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t09b_fw_v14.bin -o t09b_fw.bin || exit 1

chmod +x guardian_gate.elf gate_submit.elf

echo "=== PHASE 1: T01-T04 + T06 (speed=0) ==="
./guardian_gate.elf --pubkey "$PUBKEY" --version 10 --speed 0 &
GATE_PID=$!
waitfor /dev/pdxguardian 15
./gate_submit.elf t01_m.bin t01_fw.bin
./gate_submit.elf t02_m.bin t02_fw.bin
./gate_submit.elf t03_m.bin t03_fw.bin
./gate_submit.elf t04_m.bin t04_fw.bin
./gate_submit.elf t06_m.bin t06_fw.bin
kill $GATE_PID 2>/dev/null
wait $GATE_PID 2>/dev/null
sleep 1

echo "=== PHASE 2: T05 (speed=45) ==="
./guardian_gate.elf --pubkey "$PUBKEY" --version 10 --speed 45 &
GATE_PID=$!
waitfor /dev/pdxguardian 15
./gate_submit.elf t05_m.bin t05_fw.bin
kill $GATE_PID 2>/dev/null
wait $GATE_PID 2>/dev/null
sleep 1

echo "=== PHASE 3A: T07 (crash-point=tmp) ==="
./guardian_gate.elf --pubkey "$PUBKEY" --version 10 --speed 0 --crash-point tmp &
GATE_PID=$!
waitfor /dev/pdxguardian 15
./gate_submit.elf t07_m.bin t07_fw.bin
echo "T07A_EXIT=$?"
wait $GATE_PID 2>/dev/null
sleep 1

./guardian_gate.elf --pubkey "$PUBKEY" --version 10 --speed 0 &
GATE_PID=$!
waitfor /dev/pdxguardian 15
./gate_submit.elf --status
echo "ACTIVE_FW_SHA256=T07A:$(openssl dgst -sha256 /data/pdx_guardian/slots/slot_b/firmware.bin | awk '{print $NF}')"
kill $GATE_PID 2>/dev/null
wait $GATE_PID 2>/dev/null
sleep 1

echo "=== PHASE 3B: T07B (crash-point=after-rename) ==="
./guardian_gate.elf --pubkey "$PUBKEY" --version 10 --speed 0 --crash-point after-rename &
GATE_PID=$!
waitfor /dev/pdxguardian 15
./gate_submit.elf t07b_m.bin t07b_fw.bin
echo "T07B_EXIT=$?"
wait $GATE_PID 2>/dev/null
sleep 1

./guardian_gate.elf --pubkey "$PUBKEY" --version 10 --speed 0 &
GATE_PID=$!
waitfor /dev/pdxguardian 15
./gate_submit.elf --status
echo "ACTIVE_FW_SHA256=T07B:$(openssl dgst -sha256 /data/pdx_guardian/slots/slot_b/firmware.bin | awk '{print $NF}')"
kill $GATE_PID 2>/dev/null
wait $GATE_PID 2>/dev/null
sleep 1

echo "=== PHASE 3C: T07C (crash-point=after-version) + PHASE 4: T08 (cross-restart replay) ==="
./guardian_gate.elf --pubkey "$PUBKEY" --version 10 --speed 0 --crash-point after-version &
GATE_PID=$!
waitfor /dev/pdxguardian 15
./gate_submit.elf t07c_m.bin t07c_fw.bin
echo "T07C_EXIT=$?"
wait $GATE_PID 2>/dev/null
sleep 1

./guardian_gate.elf --pubkey "$PUBKEY" --version 10 --speed 0 &
GATE_PID=$!
waitfor /dev/pdxguardian 15
./gate_submit.elf --status
echo "ACTIVE_FW_SHA256=T07C:$(openssl dgst -sha256 /data/pdx_guardian/slots/slot_a/firmware.bin | awk '{print $NF}')"
./gate_submit.elf t08_m.bin t08_fw.bin
kill $GATE_PID 2>/dev/null
wait $GATE_PID 2>/dev/null
sleep 1

echo "=== PHASE 5: T09/T09B (persist-error + uncertain lock + recovery) ==="
./guardian_gate.elf --pubkey "$PUBKEY" --version 10 --speed 0 --simulate-persist-error &
GATE_PID=$!
waitfor /dev/pdxguardian 15
./gate_submit.elf t09_m.bin t09_fw.bin
./gate_submit.elf t09b_m.bin t09b_fw.bin
./gate_submit.elf --status
kill $GATE_PID 2>/dev/null
wait $GATE_PID 2>/dev/null
sleep 1

./guardian_gate.elf --pubkey "$PUBKEY" --version 10 --speed 0 &
GATE_PID=$!
waitfor /dev/pdxguardian 15
./gate_submit.elf --status
echo "ACTIVE_FW_SHA256=T09_RECOVERED:$(openssl dgst -sha256 /data/pdx_guardian/slots/slot_a/firmware.bin | awk '{print $NF}')"
echo "JOURNAL_BEGIN"
cat /data/pdx_guardian/journal/journal_chain.log
echo "JOURNAL_END"
kill $GATE_PID 2>/dev/null
wait $GATE_PID 2>/dev/null
sleep 1

echo "=== PHASE 6: T10 (tampered journal fail-closed startup) ==="
echo "seq=99 prev=0000000000000000000000000000000000000000000000000000000000000000 op=tamper state=ALLOW ver=99 slot=SLOT_B hash=0000000000000000000000000000000000000000000000000000000000000000" >> /data/pdx_guardian/journal/journal_chain.log
./guardian_gate.elf --pubkey "$PUBKEY" --version 10 --speed 0
echo "T10_TAMPER_EXIT=$?"
printf 'WK3_E2E_%s_OK\n' 'DONE'
