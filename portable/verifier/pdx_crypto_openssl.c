#include "pdx_gate_policy.h"
#include <openssl/evp.h>
#include <string.h>

pdx_gate_decision_t pdx_verify_crypto_openssl(
    const pdx_signed_manifest_t *manifest,
    const uint8_t *ed25519_pubkey_32,
    const uint8_t *firmware_data,
    size_t firmware_len
) {
    if (manifest == NULL || ed25519_pubkey_32 == NULL || firmware_data == NULL) {
        return PDX_DECISION_DENY_INTERNAL_ERR;
    }

    if (firmware_len != (size_t)manifest->payload.payload_size_bytes) {
        return PDX_DECISION_DENY_HASH;
    }

    /* 1. Verify Ed25519 Signature over exact 96-byte payload */
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, ed25519_pubkey_32, 32);
    if (pkey == NULL) {
        return PDX_DECISION_DENY_INTERNAL_ERR;
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        EVP_PKEY_free(pkey);
        return PDX_DECISION_DENY_INTERNAL_ERR;
    }

    int sig_ok = 0;
    if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) == 1) {
        if (EVP_DigestVerify(
                md_ctx,
                manifest->signature,
                PDX_SIGNATURE_LEN,
                (const uint8_t *)&manifest->payload,
                sizeof(pdx_manifest_payload_t)) == 1) {
            sig_ok = 1;
        }
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    if (!sig_ok) {
        return PDX_DECISION_DENY_SIGNATURE;
    }

    /* 2. Verify SHA-256 Digest of Firmware Payload */
    uint8_t digest[PDX_PAYLOAD_SHA256_LEN];
    unsigned int digest_len = 0;
    EVP_MD_CTX *hash_ctx = EVP_MD_CTX_new();
    if (hash_ctx == NULL) {
        return PDX_DECISION_DENY_INTERNAL_ERR;
    }

    int hash_ok = 0;
    if (EVP_DigestInit_ex(hash_ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(hash_ctx, firmware_data, firmware_len) == 1 &&
        EVP_DigestFinal_ex(hash_ctx, digest, &digest_len) == 1) {
        if (digest_len == PDX_PAYLOAD_SHA256_LEN &&
            memcmp(digest, manifest->payload.payload_sha256, PDX_PAYLOAD_SHA256_LEN) == 0) {
            hash_ok = 1;
        }
    }

    EVP_MD_CTX_free(hash_ctx);

    return hash_ok ? PDX_DECISION_ALLOW : PDX_DECISION_DENY_HASH;
}
