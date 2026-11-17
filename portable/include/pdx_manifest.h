/**
 * @file pdx_manifest.h
 * @brief PDX Guardian Manifest Binary ABI Specification (Gate 0 Frozen)
 * 
 * Exact 100-byte payload covered by 64-byte Ed25519 signature (164 bytes total).
 * Endianness: Little-Endian (LE)
 */

#ifndef PDX_MANIFEST_H
#define PDX_MANIFEST_H

#include <stdint.h>

#define PDX_MANIFEST_MAGIC          0x58445050U /* "PPDX" in ASCII Little-Endian */
#define PDX_MANIFEST_SCHEMA_V1      0x0001U
#define PDX_TRUSTED_KEY_ID          1U
#define PDX_OPERATION_ID_MAX_LEN    32
#define PDX_PAYLOAD_SHA256_LEN      32
#define PDX_SIGNATURE_LEN           64
#define PDX_MAX_PAYLOAD_SIZE_BYTES  (4 * 1024 * 1024U) /* 4 MB limit (matches Resource Manager buffer) */

#pragma pack(push, 1)

/**
 * @brief Canonical fixed binary structure for Update Manifest Payload.
 * Exact size: 100 Bytes.
 */
typedef struct {
    uint32_t magic;                 /**< 0x58445050 ("PPDX" in LE) */
    uint16_t schema_version;        /**< 0x0001 (Schema Version 1) */
    uint16_t key_id;                /**< Trusted signer key index */
    uint64_t sequence_id;           /**< Monotonically increasing sequence */
    char     operation_id[PDX_OPERATION_ID_MAX_LEN]; /**< Fixed null-terminated/padded UUID */
    uint32_t target_hw_revision;    /**< Target hardware revision filter */
    uint32_t artifact_version;      /**< Target artifact version (anti-rollback check) */
    uint32_t min_accepted_version;  /**< Minimum compatible version */
    uint8_t  requires_stationary;   /**< 0: unrestricted, 1: vehicle speed must be 0 */
    uint8_t  reserved_flags[3];     /**< Reserved padding, must be 0x00 */
    uint32_t payload_size_bytes;    /**< Binary payload size in bytes */
    uint8_t  payload_sha256[PDX_PAYLOAD_SHA256_LEN]; /**< SHA-256 hash of update artifact */
} pdx_manifest_payload_t;

/**
 * @brief Complete Signed Manifest envelope.
 * Exact size: 164 Bytes (100 Bytes Payload + 64 Bytes Signature).
 */
typedef struct {
    pdx_manifest_payload_t payload; /**< Data covered by Ed25519 signature */
    uint8_t signature[PDX_SIGNATURE_LEN]; /**< Ed25519 digital signature */
} pdx_signed_manifest_t;

#pragma pack(pop)

#endif /* PDX_MANIFEST_H */
