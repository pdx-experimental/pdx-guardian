#include "pdx_gate_policy.h"
#include <string.h>

pdx_gate_decision_t pdx_evaluate_manifest_policy(
    const pdx_manifest_payload_t *payload,
    const pdx_vehicle_state_t *state
) {
    if (payload == NULL || state == NULL) {
        return PDX_DECISION_DENY_INTERNAL_ERR;
    }

    if (payload->magic != PDX_MANIFEST_MAGIC) {
        return PDX_DECISION_DENY_MAGIC;
    }

    if (payload->schema_version != PDX_MANIFEST_SCHEMA_V1) {
        return PDX_DECISION_DENY_SCHEMA;
    }

    if (payload->key_id != PDX_TRUSTED_KEY_ID) {
        return PDX_DECISION_DENY_SIGNATURE;
    }

    if (payload->reserved_flags[0] != 0 || payload->reserved_flags[1] != 0 || payload->reserved_flags[2] != 0) {
        return PDX_DECISION_DENY_SCHEMA;
    }

    if (payload->sequence_id <= state->last_sequence_id) {
        return PDX_DECISION_DENY_ROLLBACK;
    }

    if (payload->payload_size_bytes == 0 || payload->payload_size_bytes > PDX_MAX_PAYLOAD_SIZE_BYTES) {
        return PDX_DECISION_DENY_SIZE_LIMIT;
    }

    if (payload->target_hw_revision != state->current_hw_revision) {
        return PDX_DECISION_DENY_HW_REV;
    }

    /* Anti-rollback: new artifact_version must be strictly greater than active version */
    if (payload->artifact_version <= state->current_active_version) {
        return PDX_DECISION_DENY_ROLLBACK;
    }

    if (state->current_active_version < payload->min_accepted_version) {
        return PDX_DECISION_DENY_ROLLBACK;
    }

    if (payload->requires_stationary != 0 && state->vehicle_speed_kmh > 0) {
        return PDX_DECISION_DENY_NOT_STATIONARY;
    }

    return PDX_DECISION_ALLOW;
}

const char *pdx_decision_to_str(pdx_gate_decision_t decision) {
    switch (decision) {
        case PDX_DECISION_ALLOW:               return "ALLOW";
        case PDX_DECISION_DENY_MAGIC:          return "DENY_MAGIC";
        case PDX_DECISION_DENY_SCHEMA:         return "DENY_SCHEMA";
        case PDX_DECISION_DENY_SIGNATURE:      return "DENY_SIGNATURE";
        case PDX_DECISION_DENY_HASH:           return "DENY_HASH";
        case PDX_DECISION_DENY_ROLLBACK:       return "DENY_ROLLBACK";
        case PDX_DECISION_DENY_HW_REV:         return "DENY_HW_REV";
        case PDX_DECISION_DENY_NOT_STATIONARY: return "DENY_NOT_STATIONARY";
        case PDX_DECISION_DENY_SIZE_LIMIT:     return "DENY_SIZE_LIMIT";
        default:                               return "DENY_INTERNAL_ERR";
    }
}
