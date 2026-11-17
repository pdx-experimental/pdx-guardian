/**
 * @file pdx_gate_policy.h
 * @brief Portable Policy & Decision Contracts for PDX Guardian
 */

#ifndef PDX_GATE_POLICY_H
#define PDX_GATE_POLICY_H

#include "pdx_manifest.h"
#include <stddef.h>
#include <stdint.h>

typedef enum {
    PDX_DECISION_ALLOW = 0,
    PDX_DECISION_DENY_MAGIC = 1,
    PDX_DECISION_DENY_SCHEMA = 2,
    PDX_DECISION_DENY_SIGNATURE = 3,
    PDX_DECISION_DENY_HASH = 4,
    PDX_DECISION_DENY_ROLLBACK = 5,
    PDX_DECISION_DENY_HW_REV = 6,
    PDX_DECISION_DENY_NOT_STATIONARY = 7,
    PDX_DECISION_DENY_SIZE_LIMIT = 8,
    PDX_DECISION_DENY_INTERNAL_ERR = 9
} pdx_gate_decision_t;

typedef struct {
    uint32_t current_hw_revision;
    uint32_t current_active_version;
    uint32_t vehicle_speed_kmh;
    uint64_t last_sequence_id;
} pdx_vehicle_state_t;

typedef struct {
    pdx_gate_decision_t decision;
    char operation_id[PDX_OPERATION_ID_MAX_LEN + 1];
    uint32_t target_version;
    uint64_t sequence_id;
    uint8_t payload_sha256[PDX_PAYLOAD_SHA256_LEN];
} pdx_gate_result_t;

/**
 * @brief Validate manifest structural fields and vehicle policy (without crypto).
 */
pdx_gate_decision_t pdx_evaluate_manifest_policy(
    const pdx_manifest_payload_t *payload,
    const pdx_vehicle_state_t *state
);

/**
 * @brief Verify Ed25519 signature over 100-byte payload and SHA-256 over firmware bytes.
 * Implemented using OpenSSL 3 EVP APIs.
 */
pdx_gate_decision_t pdx_verify_crypto_openssl(
    const pdx_signed_manifest_t *manifest,
    const uint8_t *ed25519_pubkey_32,
    const uint8_t *firmware_data,
    size_t firmware_len
);

const char *pdx_decision_to_str(pdx_gate_decision_t decision);

#endif /* PDX_GATE_POLICY_H */
