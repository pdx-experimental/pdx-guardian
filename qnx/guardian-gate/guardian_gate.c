/**
 * @file guardian_gate.c
 * @brief QNX 8.0 Native Resource Manager (/dev/pdxguardian) - Week 2
 *
 * Integrates:
 * - Portable Policy + OpenSSL 3 Ed25519 / SHA-256 verification
 * - Hash-Chained Journal & Monotonic Version Anchor (fs-qnx6)
 * - Crash Recovery Reconciliation (BEGIN_STAGE -> RECONCILED_ABORTED)
 * - Optional --simulate-crash flag to trigger SIGKILL mid-staging (T07)
 */

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/iofunc.h>
#include <sys/resmgr.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pdx_gate_policy.h"
#include "pdx_journal.h"
#include "pdx_manifest.h"

#define DEVICE_PATH       "/dev/pdxguardian"
#define SLOT_A_DIR        "/data/pdx_guardian/slots/slot_a"
#define SLOT_A_TMP        "/data/pdx_guardian/slots/slot_a/firmware.bin.tmp"
#define SLOT_A_BIN        "/data/pdx_guardian/slots/slot_a/firmware.bin"
#define SLOT_B_DIR        "/data/pdx_guardian/slots/slot_b"
#define SLOT_B_TMP        "/data/pdx_guardian/slots/slot_b/firmware.bin.tmp"
#define SLOT_B_BIN        "/data/pdx_guardian/slots/slot_b/firmware.bin"

#define MAX_RX_BUFFER     (4 * 1024 * 1024U)
#define MAX_RECEIPT_LEN   2048

static uint8_t g_trusted_pubkey[32];
static pdx_vehicle_state_t g_vehicle_state = {
    .current_hw_revision = 0x0001000AU,
    .current_active_version = 10U,
    .vehicle_speed_kmh = 0U,
    .last_sequence_id = 0ULL
};
static pdx_journal_ctx_t g_journal;
static int g_gate_uncertain_locked = 0;

typedef enum {
    CRASH_NONE = 0,
    CRASH_TMP = 1,
    CRASH_AFTER_RENAME = 2,
    CRASH_AFTER_VERSION = 3
} crash_point_t;

static crash_point_t g_crash_point = CRASH_NONE;
static int g_simulate_persist_error = 0;

typedef struct {
    iofunc_ocb_t hdr;
    uint8_t *rx_buf;
    size_t rx_len;
    size_t rx_cap;
    char receipt_json[MAX_RECEIPT_LEN];
    size_t receipt_len;
    size_t read_offset;
} guardian_ocb_t;

static void format_status_json(guardian_ocb_t *ocb) {
    snprintf(ocb->receipt_json, MAX_RECEIPT_LEN,
             "{\"status_query\":true,\"active_version\":%u,\"active_slot\":\"%s\","
             "\"last_sequence_id\":%llu,\"journal_seq\":%llu,"
             "\"chain_valid\":%s,\"reconcile_performed\":%s,\"reconciled_op_id\":\"%s\","
             "\"reconciled_state\":\"%s\",\"uncertain_locked\":%s,\"last_hash\":\"%s\"}\n",
             g_vehicle_state.current_active_version,
             g_journal.active_slot,
             (unsigned long long)g_vehicle_state.last_sequence_id,
             (unsigned long long)g_journal.last_seq,
             g_journal.chain_valid ? "true" : "false",
             g_journal.reconcile_performed ? "true" : "false",
             g_journal.reconciled_op_id,
             g_journal.reconciled_state,
             g_gate_uncertain_locked ? "true" : "false",
             g_journal.last_hash);
    ocb->receipt_len = strlen(ocb->receipt_json);
    ocb->read_offset = 0;
}

static void process_update_request(guardian_ocb_t *ocb) {
    if (!g_journal.chain_valid) {
        snprintf(ocb->receipt_json, MAX_RECEIPT_LEN,
                 "{\"operation_id\":\"unknown\",\"decision\":\"DENY_INTERNAL_ERR\","
                 "\"slot_status\":\"BLOCKED_JOURNAL_TAMPERED\",\"active_version\":%u,"
                 "\"target_version\":0,\"journal_seq\":%llu,\"payload_sha256\":\"\"}\n",
                 g_vehicle_state.current_active_version,
                 (unsigned long long)g_journal.last_seq);
        ocb->receipt_len = strlen(ocb->receipt_json);
        ocb->read_offset = 0;
        return;
    }

    if (ocb->rx_len < sizeof(pdx_signed_manifest_t)) {
        snprintf(ocb->receipt_json, MAX_RECEIPT_LEN,
                 "{\"operation_id\":\"unknown\",\"decision\":\"DENY_SIZE_LIMIT\","
                 "\"slot_status\":\"UNCHANGED_SLOT_A\",\"active_version\":%u}\n",
                 g_vehicle_state.current_active_version);
        ocb->receipt_len = strlen(ocb->receipt_json);
        ocb->read_offset = 0;
        return;
    }

    const pdx_signed_manifest_t *manifest = (const pdx_signed_manifest_t *)ocb->rx_buf;
    const uint8_t *fw_data = ocb->rx_buf + sizeof(pdx_signed_manifest_t);
    size_t fw_len = ocb->rx_len - sizeof(pdx_signed_manifest_t);

    char op_id_str[PDX_OPERATION_ID_MAX_LEN + 1];
    memcpy(op_id_str, manifest->payload.operation_id, PDX_OPERATION_ID_MAX_LEN);
    op_id_str[PDX_OPERATION_ID_MAX_LEN] = '\0';

    /* 1. Policy Evaluation */
    pdx_gate_decision_t decision = pdx_evaluate_manifest_policy(&manifest->payload, &g_vehicle_state);

    /* 2. OpenSSL 3 Ed25519 + SHA-256 Verification */
    if (decision == PDX_DECISION_ALLOW) {
        decision = pdx_verify_crypto_openssl(manifest, g_trusted_pubkey, fw_data, fw_len);
    }

    const char *active_slot = g_journal.active_slot;
    int stage_to_b = (strcmp(active_slot, "SLOT_A") == 0);
    const char *target_slot = stage_to_b ? "SLOT_B" : "SLOT_A";
    const char *target_dir  = stage_to_b ? SLOT_B_DIR : SLOT_A_DIR;
    const char *target_tmp  = stage_to_b ? SLOT_B_TMP : SLOT_A_TMP;
    const char *target_bin  = stage_to_b ? SLOT_B_BIN : SLOT_A_BIN;

    const char *slot_status = stage_to_b ? "UNCHANGED_SLOT_A" : "UNCHANGED_SLOT_B";
    const char *decision_str = NULL;

    if (g_gate_uncertain_locked) {
        decision_str = "UNKNOWN_OUTCOME";
        slot_status = "UNCERTAIN_PERSISTENCE_LOCKED";
    } else if (decision == PDX_DECISION_ALLOW) {
        if (pdx_journal_append(&g_journal, op_id_str, "BEGIN_STAGE", manifest->payload.artifact_version, target_slot) != 0) {
            g_gate_uncertain_locked = 1;
            decision_str = "UNKNOWN_OUTCOME";
            slot_status = "UNCERTAIN_JOURNAL_LOCKED";
        } else if (g_crash_point == CRASH_TMP) {
            int fd = open(target_tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) {
                write(fd, fw_data, fw_len / 2);
                fsync(fd);
                close(fd);
            }
            printf("[guardian_gate] Simulating worker SIGKILL at crash-point=tmp (%s) for op=%s!\n", target_slot, op_id_str);
            fflush(stdout);
            raise(SIGKILL);
        } else if (g_simulate_persist_error ||
                   pdx_atomic_write_bytes(target_dir, target_tmp, target_bin, fw_data, (uint64_t)fw_len) != 0) {
            g_gate_uncertain_locked = 1;
            decision_str = "UNKNOWN_OUTCOME";
            slot_status = "UNCERTAIN_STAGE_WRITE_LOCKED";
        } else if (g_crash_point == CRASH_AFTER_RENAME) {
            printf("[guardian_gate] Simulating worker SIGKILL at crash-point=after-rename (%s) for op=%s!\n", target_slot, op_id_str);
            fflush(stdout);
            raise(SIGKILL);
        } else if (pdx_persist_anchor(manifest->payload.artifact_version, target_slot, manifest->payload.sequence_id) != 0) {
            g_gate_uncertain_locked = 1;
            decision_str = "UNKNOWN_OUTCOME";
            slot_status = "UNCERTAIN_ANCHOR_WRITE_LOCKED";
        } else if (g_crash_point == CRASH_AFTER_VERSION) {
            printf("[guardian_gate] Simulating worker SIGKILL at crash-point=after-version (%s) for op=%s!\n", target_slot, op_id_str);
            fflush(stdout);
            raise(SIGKILL);
        } else {
            g_vehicle_state.current_active_version = manifest->payload.artifact_version;
            g_vehicle_state.last_sequence_id = manifest->payload.sequence_id;
            g_journal.active_version = manifest->payload.artifact_version;
            snprintf(g_journal.active_slot, sizeof(g_journal.active_slot), "%s", target_slot);
            g_journal.last_sequence_id = manifest->payload.sequence_id;
            if (pdx_journal_append(&g_journal, op_id_str, "ACTIVATED", manifest->payload.artifact_version, target_slot) != 0) {
                g_gate_uncertain_locked = 1;
                decision_str = "UNKNOWN_OUTCOME";
                slot_status = "UNCERTAIN_ACTIVATE_LOG_LOCKED";
            } else {
                decision_str = pdx_decision_to_str(decision);
                slot_status = stage_to_b ? "STAGED_AND_ACTIVATED_SLOT_B" : "STAGED_AND_ACTIVATED_SLOT_A";
            }
        }
    } else {
        if (pdx_journal_append(&g_journal, op_id_str, pdx_decision_to_str(decision),
                               manifest->payload.artifact_version, active_slot) != 0) {
            g_gate_uncertain_locked = 1;
            decision_str = "UNKNOWN_OUTCOME";
            slot_status = "UNCERTAIN_DENY_LOG_LOCKED";
        } else {
            decision_str = pdx_decision_to_str(decision);
        }
    }

    char hex_sha[65];
    for (int i = 0; i < 32; i++) {
        snprintf(&hex_sha[i * 2], 3, "%02x", manifest->payload.payload_sha256[i]);
    }
    hex_sha[64] = '\0';

    snprintf(ocb->receipt_json, MAX_RECEIPT_LEN,
             "{\"operation_id\":\"%s\",\"decision\":\"%s\",\"slot_status\":\"%s\","
             "\"active_version\":%u,\"target_version\":%u,\"journal_seq\":%llu,"
             "\"journal_hash\":\"%s\",\"payload_sha256\":\"%s\"}\n",
             op_id_str, decision_str, slot_status,
             g_vehicle_state.current_active_version,
             manifest->payload.artifact_version,
             (unsigned long long)g_journal.last_seq,
             g_journal.last_hash,
             hex_sha);
    ocb->receipt_len = strlen(ocb->receipt_json);
    ocb->read_offset = 0;
}

static IOFUNC_OCB_T *guardian_ocb_calloc(resmgr_context_t *ctp, IOFUNC_ATTR_T *attr) {
    (void)ctp;
    (void)attr;
    guardian_ocb_t *ocb = calloc(1, sizeof(guardian_ocb_t));
    if (ocb != NULL) {
        ocb->rx_cap = 65536;
        ocb->rx_buf = malloc(ocb->rx_cap);
    }
    return (IOFUNC_OCB_T *)ocb;
}

static void guardian_ocb_free(IOFUNC_OCB_T *hdr) {
    guardian_ocb_t *ocb = (guardian_ocb_t *)hdr;
    if (ocb != NULL) {
        free(ocb->rx_buf);
        free(ocb);
    }
}

static int guardian_io_write(resmgr_context_t *ctp, io_write_t *msg, RESMGR_OCB_T *hdr) {
    guardian_ocb_t *ocb = (guardian_ocb_t *)hdr;
    int status = iofunc_write_verify(ctp, msg, &ocb->hdr, NULL);
    if (status != EOK) return status;

    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) {
        return ENOSYS;
    }

    size_t nbytes = msg->i.nbytes;
    if (nbytes == 0) {
        _IO_SET_WRITE_NBYTES(ctp, 0);
        return EOK;
    }

    if (ocb->rx_len + nbytes > MAX_RX_BUFFER) {
        return EMSGSIZE;
    }

    if (ocb->rx_len + nbytes > ocb->rx_cap) {
        size_t new_cap = ocb->rx_cap * 2;
        while (new_cap < ocb->rx_len + nbytes) new_cap *= 2;
        uint8_t *new_buf = realloc(ocb->rx_buf, new_cap);
        if (new_buf == NULL) return ENOMEM;
        ocb->rx_buf = new_buf;
        ocb->rx_cap = new_cap;
    }

    ssize_t nread = resmgr_msgget(ctp, ocb->rx_buf + ocb->rx_len, nbytes, sizeof(msg->i));
    if (nread < 0) return errno;

    ocb->rx_len += (size_t)nread;

    if (ocb->rx_len >= sizeof(pdx_signed_manifest_t)) {
        const pdx_signed_manifest_t *m = (const pdx_signed_manifest_t *)ocb->rx_buf;
        size_t expected_total = sizeof(pdx_signed_manifest_t) + m->payload.payload_size_bytes;
        if (m->payload.magic != PDX_MANIFEST_MAGIC ||
            m->payload.payload_size_bytes > PDX_MAX_PAYLOAD_SIZE_BYTES ||
            ocb->rx_len >= expected_total) {
            process_update_request(ocb);
        }
    }

    _IO_SET_WRITE_NBYTES(ctp, nread);
    return EOK;
}

static int guardian_io_read(resmgr_context_t *ctp, io_read_t *msg, RESMGR_OCB_T *hdr) {
    guardian_ocb_t *ocb = (guardian_ocb_t *)hdr;
    int status = iofunc_read_verify(ctp, msg, &ocb->hdr, NULL);
    if (status != EOK) return status;

    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) {
        return ENOSYS;
    }

    if (ocb->receipt_len == 0) {
        if (ocb->rx_len == 0) {
            format_status_json(ocb);
        } else {
            process_update_request(ocb);
        }
    }

    size_t avail = (ocb->read_offset < ocb->receipt_len) ? (ocb->receipt_len - ocb->read_offset) : 0;
    size_t nbytes = (msg->i.nbytes < avail) ? msg->i.nbytes : avail;

    if (nbytes > 0) {
        MsgReply(ctp->rcvid, nbytes, ocb->receipt_json + ocb->read_offset, nbytes);
        ocb->read_offset += nbytes;
    } else {
        MsgReply(ctp->rcvid, 0, NULL, 0);
    }

    return _RESMGR_NOREPLY;
}

static int parse_hex_pubkey(const char *hex, uint8_t out[32]) {
    if (strlen(hex) != 64) return -1;
    for (int i = 0; i < 32; i++) {
        unsigned int val = 0;
        if (sscanf(&hex[i * 2], "%2x", &val) != 1) return -1;
        out[i] = (uint8_t)val;
    }
    return 0;
}

int main(int argc, char **argv) {
    uint32_t default_ver = 10U;
    memset(g_trusted_pubkey, 0, sizeof(g_trusted_pubkey));

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--pubkey") == 0 && i + 1 < argc) {
            if (parse_hex_pubkey(argv[++i], g_trusted_pubkey) != 0) {
                fprintf(stderr, "Invalid --pubkey hex (expected 64 hex chars)\n");
                return EXIT_FAILURE;
            }
        } else if (strcmp(argv[i], "--speed") == 0 && i + 1 < argc) {
            g_vehicle_state.vehicle_speed_kmh = (uint32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--version") == 0 && i + 1 < argc) {
            default_ver = (uint32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--crash-during-stage") == 0) {
            g_crash_point = CRASH_TMP;
        } else if (strcmp(argv[i], "--simulate-persist-error") == 0) {
            g_simulate_persist_error = 1;
        } else if (strcmp(argv[i], "--crash-point") == 0 && i + 1 < argc) {
            const char *cp = argv[++i];
            if (strcmp(cp, "tmp") == 0) g_crash_point = CRASH_TMP;
            else if (strcmp(cp, "after-rename") == 0) g_crash_point = CRASH_AFTER_RENAME;
            else if (strcmp(cp, "after-version") == 0) g_crash_point = CRASH_AFTER_VERSION;
            else {
                fprintf(stderr, "Unknown --crash-point: %s\n", cp);
                return EXIT_FAILURE;
            }
        }
    }

    if (pdx_journal_init(&g_journal, default_ver) != 0) {
        fprintf(stderr, "FATAL: pdx_journal_init failed closed (corrupt journal or missing version anchor)\n");
        return EXIT_FAILURE;
    }
    g_vehicle_state.current_active_version = g_journal.active_version;
    g_vehicle_state.last_sequence_id = g_journal.last_sequence_id;

    dispatch_t *dpp = dispatch_create();
    if (dpp == NULL) {
        perror("dispatch_create");
        return EXIT_FAILURE;
    }

    resmgr_attr_t resmgr_attr;
    memset(&resmgr_attr, 0, sizeof(resmgr_attr));
    resmgr_attr.nparts_max = 1;
    resmgr_attr.msg_max_size = 65536;

    static iofunc_funcs_t ocb_funcs = {
        .nfuncs = _IOFUNC_NFUNCS,
        .ocb_calloc = guardian_ocb_calloc,
        .ocb_free = guardian_ocb_free
    };
    static iofunc_mount_t mount_attr = { .funcs = &ocb_funcs };

    iofunc_attr_t attr;
    iofunc_attr_init(&attr, S_IFCHR | 0666, NULL, NULL);
    attr.mount = &mount_attr;

    resmgr_connect_funcs_t connect_funcs;
    resmgr_io_funcs_t io_funcs;
    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &connect_funcs,
                     _RESMGR_IO_NFUNCS, &io_funcs);
    io_funcs.read = guardian_io_read;
    io_funcs.write = guardian_io_write;

    int id = resmgr_attach(dpp, &resmgr_attr, DEVICE_PATH, _FTYPE_ANY, 0,
                           &connect_funcs, &io_funcs, &attr);
    if (id == -1) {
        perror("resmgr_attach");
        return EXIT_FAILURE;
    }

    printf("[guardian_gate] Attached %s (active_ver=%u, speed=%u, seq=%llu, chain_valid=%d, reconciled=%d)\n",
           DEVICE_PATH,
           g_vehicle_state.current_active_version,
           g_vehicle_state.vehicle_speed_kmh,
           (unsigned long long)g_journal.last_seq,
           g_journal.chain_valid,
           g_journal.reconcile_performed);
    fflush(stdout);

    dispatch_context_t *ctp = dispatch_context_alloc(dpp);
    if (ctp == NULL) {
        perror("dispatch_context_alloc");
        return EXIT_FAILURE;
    }

    while (1) {
        if ((ctp = dispatch_block(ctp)) == NULL) {
            perror("dispatch_block");
            return EXIT_FAILURE;
        }
        dispatch_handler(ctp);
    }

    return EXIT_SUCCESS;
}
