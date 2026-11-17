#include "pdx_journal.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BASE_DIR          "/data/pdx_guardian"
#define JOURNAL_DIR       "/data/pdx_guardian/journal"
#define JOURNAL_FILE      "/data/pdx_guardian/journal/journal_chain.log"
#define ANCHOR_TMP        "/data/pdx_guardian/state_version.dat.tmp"
#define ANCHOR_FILE       "/data/pdx_guardian/state_version.dat"
#define SLOT_A_TMP        "/data/pdx_guardian/slots/slot_a/firmware.bin.tmp"
#define SLOT_A_FILE       "/data/pdx_guardian/slots/slot_a/firmware.bin"
#define SLOT_B_TMP        "/data/pdx_guardian/slots/slot_b/firmware.bin.tmp"
#define SLOT_B_FILE       "/data/pdx_guardian/slots/slot_b/firmware.bin"

#define GENESIS_HASH "0000000000000000000000000000000000000000000000000000000000000000"

static int compute_entry_hash(
    uint64_t seq,
    const char *prev_hash,
    const char *op_id,
    const char *state_str,
    uint32_t target_version,
    const char *slot_str,
    char out_hex[PDX_JOURNAL_HASH_HEX]
) {
    char buf[512];
    int n = snprintf(buf, sizeof(buf), "%llu|%s|%s|%s|%u|%s",
                     (unsigned long long)seq, prev_hash, op_id, state_str, target_version, slot_str);
    if (n <= 0 || (size_t)n >= sizeof(buf)) {
        return -1;
    }

    uint8_t digest[32];
    unsigned int dlen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
    int ok = (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
              EVP_DigestUpdate(ctx, buf, (size_t)n) == 1 &&
              EVP_DigestFinal_ex(ctx, digest, &dlen) == 1);
    EVP_MD_CTX_free(ctx);
    if (!ok || dlen != 32) {
        return -1;
    }
    for (unsigned int i = 0; i < 32; i++) {
        snprintf(&out_hex[i * 2], 3, "%02x", digest[i]);
    }
    out_hex[64] = '\0';
    return 0;
}

static int fsync_dir_strict(const char *dir_path) {
    int dir_fd = open(dir_path, O_RDONLY);
    if (dir_fd < 0) {
        return -1;
    }
    int rc = fsync(dir_fd);
    int close_rc = close(dir_fd);
    return (rc == 0 && close_rc == 0) ? 0 : -1;
}

int pdx_atomic_write_bytes(const char *dir_path, const char *tmp_path, const char *dst_path,
                           const void *data, uint64_t len) {
    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;

    const uint8_t *ptr = (const uint8_t *)data;
    uint64_t written = 0;
    while (written < len) {
        ssize_t n = write(fd, ptr + written, (size_t)(len - written));
        if (n <= 0) {
            close(fd);
            return -1;
        }
        written += (uint64_t)n;
    }

    if (fsync(fd) != 0) {
        close(fd);
        return -1;
    }
    if (close(fd) != 0) {
        return -1;
    }
    if (rename(tmp_path, dst_path) != 0) {
        return -1;
    }
    if (fsync_dir_strict(dir_path) != 0) {
        return -1;
    }
    return 0;
}

int pdx_persist_anchor(uint32_t active_version, const char *active_slot, uint64_t last_sequence_id) {
    if (active_slot == NULL ||
        (strcmp(active_slot, "SLOT_A") != 0 && strcmp(active_slot, "SLOT_B") != 0)) {
        return -1;
    }
    char anchor_str[64];
    int len = snprintf(anchor_str, sizeof(anchor_str), "%u %s %llu\n",
                       active_version, active_slot, (unsigned long long)last_sequence_id);
    if (len <= 0 || (size_t)len >= sizeof(anchor_str)) {
        return -1;
    }
    return pdx_atomic_write_bytes(BASE_DIR, ANCHOR_TMP, ANCHOR_FILE, anchor_str, (uint64_t)len);
}

static int load_anchor(
    uint32_t default_version,
    uint32_t *out_version,
    char out_slot[16],
    uint64_t *out_seq_id
) {
    FILE *fp = fopen(ANCHOR_FILE, "r");
    if (fp == NULL) {
        if (errno != ENOENT) {
            return -1;
        }
        if (access(JOURNAL_FILE, F_OK) == 0) {
            return -1;
        }
        if (pdx_persist_anchor(default_version, "SLOT_A", 0ULL) != 0) {
            return -1;
        }
        *out_version = default_version;
        snprintf(out_slot, 16, "%s", "SLOT_A");
        *out_seq_id = 0ULL;
        return 0;
    }

    unsigned int v = 0;
    char slot[16] = {0};
    unsigned long long seq_id = 0;
    int scanned = fscanf(fp, "%u %15s %llu", &v, slot, &seq_id);
    fclose(fp);
    if (scanned != 3 || v == 0 ||
        (strcmp(slot, "SLOT_A") != 0 && strcmp(slot, "SLOT_B") != 0)) {
        return -1;
    }
    *out_version = (uint32_t)v;
    snprintf(out_slot, 16, "%s", slot);
    *out_seq_id = (uint64_t)seq_id;
    return 0;
}

static void cleanup_uncommitted_slot(const char *staging_slot, const char *active_slot) {
    /* Never delete the currently committed active slot firmware */
    if (strcmp(staging_slot, active_slot) == 0) {
        return;
    }
    if (strcmp(staging_slot, "SLOT_A") == 0) {
        unlink(SLOT_A_TMP);
        unlink(SLOT_A_FILE);
    } else if (strcmp(staging_slot, "SLOT_B") == 0) {
        unlink(SLOT_B_TMP);
        unlink(SLOT_B_FILE);
    }
}

int pdx_journal_init(pdx_journal_ctx_t *ctx, uint32_t default_version) {
    if (ctx == NULL || default_version == 0) {
        return -1;
    }
    memset(ctx, 0, sizeof(*ctx));
    mkdir(BASE_DIR, 0755);
    mkdir("/data/pdx_guardian/slots", 0755);
    mkdir("/data/pdx_guardian/slots/slot_a", 0755);
    mkdir("/data/pdx_guardian/slots/slot_b", 0755);
    mkdir(JOURNAL_DIR, 0755);

    if (load_anchor(default_version, &ctx->active_version, ctx->active_slot, &ctx->last_sequence_id) != 0) {
        ctx->chain_valid = 0;
        return -1;
    }
    memcpy(ctx->last_hash, GENESIS_HASH, PDX_JOURNAL_HASH_HEX);
    ctx->chain_valid = 1;

    FILE *fp = fopen(JOURNAL_FILE, "r");
    if (fp == NULL) {
        if (errno == ENOENT) {
            return 0;
        }
        ctx->chain_valid = 0;
        return -1;
    }

    char line[1024];
    char last_op[PDX_JOURNAL_MAX_OP_ID] = {0};
    char last_state[32] = {0};
    char last_slot[16] = {0};
    uint32_t last_ver = 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        uint64_t seq = 0;
        char prev_h[PDX_JOURNAL_HASH_HEX] = {0};
        char op_id[PDX_JOURNAL_MAX_OP_ID] = {0};
        char state[32] = {0};
        unsigned int tver = 0;
        char slot[16] = {0};
        char entry_h[PDX_JOURNAL_HASH_HEX] = {0};

        int parsed = sscanf(
            line,
            "seq=%llu prev=%64s op=%32s state=%31s ver=%u slot=%15s hash=%64s",
            (unsigned long long *)&seq, prev_h, op_id, state, &tver, slot, entry_h
        );
        if (parsed != 7) {
            ctx->chain_valid = 0;
            break;
        }

        if (seq != ctx->last_seq + 1 || strcmp(prev_h, ctx->last_hash) != 0) {
            ctx->chain_valid = 0;
            break;
        }

        char expected_h[PDX_JOURNAL_HASH_HEX];
        if (compute_entry_hash(seq, prev_h, op_id, state, (uint32_t)tver, slot, expected_h) != 0 ||
            strcmp(expected_h, entry_h) != 0) {
            ctx->chain_valid = 0;
            break;
        }

        ctx->last_seq = seq;
        memcpy(ctx->last_hash, entry_h, PDX_JOURNAL_HASH_HEX);
        snprintf(last_op, sizeof(last_op), "%s", op_id);
        snprintf(last_state, sizeof(last_state), "%s", state);
        snprintf(last_slot, sizeof(last_slot), "%s", slot);
        last_ver = (uint32_t)tver;
    }
    fclose(fp);

    if (!ctx->chain_valid) {
        return -1;
    }

    /* Reconcile incomplete staging if process crashed after BEGIN_STAGE */
    if (ctx->last_seq > 0 && strcmp(last_state, "BEGIN_STAGE") == 0) {
        if (ctx->active_version >= last_ver && strcmp(ctx->active_slot, last_slot) == 0) {
            /* Anchor already committed: activation succeeded prior to crash */
            if (pdx_journal_append(ctx, last_op, "RECONCILED_ACTIVATED", last_ver, ctx->active_slot) != 0) {
                return -1;
            }
            snprintf(ctx->reconciled_state, sizeof(ctx->reconciled_state), "%s", "RECONCILED_ACTIVATED");
        } else {
            /* Anchor not committed: remove uncommitted staging artifact only, preserve active_slot */
            cleanup_uncommitted_slot(last_slot, ctx->active_slot);
            if (pdx_journal_append(ctx, last_op, "RECONCILED_ABORTED", last_ver, ctx->active_slot) != 0) {
                return -1;
            }
            snprintf(ctx->reconciled_state, sizeof(ctx->reconciled_state), "%s", "RECONCILED_ABORTED");
        }
        ctx->reconcile_performed = 1;
        snprintf(ctx->reconciled_op_id, sizeof(ctx->reconciled_op_id), "%s", last_op);
    }

    return 0;
}

int pdx_journal_append(
    pdx_journal_ctx_t *ctx,
    const char *op_id,
    const char *state_str,
    uint32_t target_version,
    const char *slot_str
) {
    if (ctx == NULL || op_id == NULL || state_str == NULL || slot_str == NULL) {
        return -1;
    }
    uint64_t next_seq = ctx->last_seq + 1;
    char new_hash[PDX_JOURNAL_HASH_HEX];
    if (compute_entry_hash(next_seq, ctx->last_hash, op_id, state_str, target_version, slot_str, new_hash) != 0) {
        return -1;
    }

    FILE *fp = fopen(JOURNAL_FILE, "a");
    if (fp == NULL) return -1;

    int rc = fprintf(fp, "seq=%llu prev=%s op=%s state=%s ver=%u slot=%s hash=%s\n",
                     (unsigned long long)next_seq,
                     ctx->last_hash,
                     op_id,
                     state_str,
                     target_version,
                     slot_str,
                     new_hash);
    if (rc < 0 || fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0 || fsync_dir_strict(JOURNAL_DIR) != 0) {
        return -1;
    }

    ctx->last_seq = next_seq;
    memcpy(ctx->last_hash, new_hash, PDX_JOURNAL_HASH_HEX);
    return 0;
}
