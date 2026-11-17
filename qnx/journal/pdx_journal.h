/**
 * @file pdx_journal.h
 * @brief Persistent Hash-Chained Journal & Atomic A/B Anchor for QNX 8.0 (fs-qnx6)
 */

#ifndef PDX_JOURNAL_H
#define PDX_JOURNAL_H

#include <stdint.h>

#define PDX_JOURNAL_MAX_OP_ID 33
#define PDX_JOURNAL_HASH_HEX  65

typedef struct {
    uint64_t last_seq;
    char last_hash[PDX_JOURNAL_HASH_HEX];
    uint32_t active_version;
    char active_slot[16];
    uint64_t last_sequence_id;
    int chain_valid;
    int reconcile_performed;
    char reconciled_op_id[PDX_JOURNAL_MAX_OP_ID];
    char reconciled_state[32];
} pdx_journal_ctx_t;

/**
 * @brief Initialize journal context, load atomic anchor (version, active_slot,
 * last_sequence_id), verify existing hash chain, and reconcile any incomplete
 * BEGIN_STAGE entry without touching the committed active slot firmware.
 */
int pdx_journal_init(pdx_journal_ctx_t *ctx, uint32_t default_version);

/**
 * @brief Append a hash-chained entry and fsync file + directory to fs-qnx6.
 */
int pdx_journal_append(
    pdx_journal_ctx_t *ctx,
    const char *op_id,
    const char *state_str,
    uint32_t target_version,
    const char *slot_str
);

/**
 * @brief Atomically persist (active_version, active_slot, last_sequence_id)
 * using tmp -> fsync -> rename -> dir fsync.
 */
int pdx_persist_anchor(uint32_t active_version, const char *active_slot, uint64_t last_sequence_id);

/**
 * @brief Atomically write bytes using tmp -> fsync -> rename -> dir fsync.
 */
int pdx_atomic_write_bytes(
    const char *dir_path,
    const char *tmp_path,
    const char *dst_path,
    const void *data,
    uint64_t len
);

#endif /* PDX_JOURNAL_H */
