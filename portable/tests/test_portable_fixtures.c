#include "pdx_gate_policy.h"
#include "pdx_manifest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t TRUSTED_PUBKEY[32] = {
    0x7d, 0x1f, 0x0d, 0x1f, 0x11, 0x33, 0xb0, 0x5f,
    0x65, 0xe0, 0x75, 0xaa, 0x4a, 0x68, 0x7d, 0x8b,
    0xcc, 0xc3, 0x1e, 0xfd, 0x52, 0x1d, 0xb6, 0xfc,
    0xc7, 0x2e, 0x34, 0xbe, 0xa7, 0xb3, 0xf8, 0xfa
};

static int read_file_bytes(const char *path, uint8_t **out_buf, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return -1; }
    rewind(fp);
    uint8_t *buf = (uint8_t *)malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return -1; }
    size_t n = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    if (n != (size_t)sz) { free(buf); return -1; }
    *out_buf = buf;
    *out_len = n;
    return 0;
}

static pdx_gate_decision_t eval_fixture(
    const char *manifest_path,
    const char *fw_path,
    const pdx_vehicle_state_t *state
) {
    uint8_t *m_buf = NULL, *fw_buf = NULL;
    size_t m_len = 0, fw_len = 0;
    if (read_file_bytes(manifest_path, &m_buf, &m_len) != 0 ||
        read_file_bytes(fw_path, &fw_buf, &fw_len) != 0) {
        free(m_buf);
        free(fw_buf);
        fprintf(stderr, "Failed to read fixture: %s / %s\n", manifest_path, fw_path);
        exit(2);
    }
    if (m_len != sizeof(pdx_signed_manifest_t)) {
        free(m_buf);
        free(fw_buf);
        fprintf(stderr, "Unexpected manifest size: %zu\n", m_len);
        exit(2);
    }
    const pdx_signed_manifest_t *manifest = (const pdx_signed_manifest_t *)m_buf;
    pdx_gate_decision_t d = pdx_evaluate_manifest_policy(&manifest->payload, state);
    if (d == PDX_DECISION_ALLOW) {
        d = pdx_verify_crypto_openssl(manifest, TRUSTED_PUBKEY, fw_buf, fw_len);
    }
    free(m_buf);
    free(fw_buf);
    return d;
}

static void assert_case(
    const char *name,
    const char *manifest_path,
    const char *fw_path,
    const pdx_vehicle_state_t *state,
    pdx_gate_decision_t expected
) {
    pdx_gate_decision_t actual = eval_fixture(manifest_path, fw_path, state);
    if (actual != expected) {
        fprintf(stderr, "[FAIL] %s: expected=%s got=%s\n",
                name, pdx_decision_to_str(expected), pdx_decision_to_str(actual));
        exit(1);
    }
    printf("[PASS] %s -> %s\n", name, pdx_decision_to_str(actual));
}

int main(void) {
    pdx_vehicle_state_t state = {
        .current_hw_revision = 0x0001000AU,
        .current_active_version = 10U,
        .vehicle_speed_kmh = 0U,
        .last_sequence_id = 0ULL
    };

    assert_case("T01 valid v11",
                "simulator/fixtures/week3/t01_manifest_v11.bin",
                "simulator/fixtures/week3/t01_fw_v11.bin",
                &state, PDX_DECISION_ALLOW);

    state.current_active_version = 11U;
    state.last_sequence_id = 1ULL;

    assert_case("T02 tampered payload",
                "simulator/fixtures/week3/t02_manifest_v12.bin",
                "simulator/fixtures/week3/t02_fw_v12_tampered.bin",
                &state, PDX_DECISION_DENY_HASH);

    assert_case("T03 bad signature",
                "simulator/fixtures/week3/t03_manifest_v12_badsig.bin",
                "simulator/fixtures/week3/t03_fw_v12.bin",
                &state, PDX_DECISION_DENY_SIGNATURE);

    assert_case("T04 rollback v09",
                "simulator/fixtures/week3/t04_manifest_v09.bin",
                "simulator/fixtures/week3/t04_fw_v09.bin",
                &state, PDX_DECISION_DENY_ROLLBACK);

    assert_case("T06 hw_revision mismatch",
                "simulator/fixtures/week3/t06_manifest_v12_hwrev.bin",
                "simulator/fixtures/week3/t06_fw_v12.bin",
                &state, PDX_DECISION_DENY_HW_REV);

    state.vehicle_speed_kmh = 50U;
    assert_case("T05 non-stationary",
                "simulator/fixtures/week3/t05_manifest_v12.bin",
                "simulator/fixtures/week3/t05_fw_v12.bin",
                &state, PDX_DECISION_DENY_NOT_STATIONARY);

    state.vehicle_speed_kmh = 0U;
    state.current_active_version = 12U;
    state.last_sequence_id = 8ULL;
    assert_case("T08 sequence replay",
                "simulator/fixtures/week3/t08_manifest_v13_replay.bin",
                "simulator/fixtures/week3/t08_fw_v13.bin",
                &state, PDX_DECISION_DENY_ROLLBACK);

    printf("ALL 7 PORTABLE C FIXTURE TESTS PASSED.\n");
    return 0;
}
