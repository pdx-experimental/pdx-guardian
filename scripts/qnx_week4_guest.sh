#!/bin/sh
set -e

WORK=/data/var/tmp/wk4_jitter
rm -rf "$WORK"
mkdir -p "$WORK"
cd "$WORK"

HOST_URL="http://10.0.2.2:18080"
echo "=== [Week 4] Downloading jitter_bench.elf ==="
curl -sf "$HOST_URL/qnx/ecu-simulator/jitter_bench.elf" -o jitter_bench.elf
chmod +x jitter_bench.elf

run_case() {
    round="$1"
    scenario="$2"
    tag="r${round}_${scenario}"
    echo "=== [Week 4] Round ${round} Scenario: ${scenario} ==="
    ./jitter_bench.elf \
        --scenario "$scenario" \
        --round "$round" \
        --warmup 1000 \
        --samples 10000 \
        --period-us 10000 \
        --work-dir "$WORK" \
        --out-json "$WORK/${tag}.json" \
        --samples-csv "$WORK/${tag}.csv"
    curl -sf -X POST --data-binary @"$WORK/${tag}.csv" "$HOST_URL/upload/${tag}.csv" >/dev/null
}

# 3 interleaved rounds across (idle, same-vcpu, separated-vcpu)
run_case 1 idle
run_case 1 same-vcpu
run_case 1 separated-vcpu

run_case 2 same-vcpu
run_case 2 separated-vcpu
run_case 2 idle

run_case 3 separated-vcpu
run_case 3 idle
run_case 3 same-vcpu

echo "WK4_JITTER_DONE_OK"
