#include "kdf.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <string>

static std::vector<uint8_t> hkdf_derive(
    const std::vector<uint8_t>& shared_secret,
    const std::string& info
) {
    constexpr size_t KEY_SIZE = 32;

    std::vector<uint8_t> derived_key(KEY_SIZE);

    // Fetch the HKDF implementation from OpenSSL.
    EVP_KDF* kdf = EVP_KDF_fetch(
        nullptr,
        "HKDF",
        nullptr
    );

    if (kdf == nullptr) {
        return {};
    }

    // Create a context for HKDF.
    EVP_KDF_CTX* context = EVP_KDF_CTX_new(kdf);

    if (context == nullptr) {
        EVP_KDF_free(kdf);
        return {};
    }

    // Tell HKDF to use SHA-256.
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST,
            const_cast<char*>("SHA256"),
            0
        ),

        // Shared secret = HKDF input key material.
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY,
            const_cast<uint8_t*>(shared_secret.data()),
            shared_secret.size()
        ),

        // Context/purpose label.
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO,
            const_cast<char*>(info.data()),
            info.size()
        ),

        OSSL_PARAM_construct_end()
    };

    // Perform HKDF.
    if (EVP_KDF_derive(
            context,
            derived_key.data(),
            derived_key.size(),
            params
        ) <= 0) {

        EVP_KDF_CTX_free(context);
        EVP_KDF_free(kdf);

        return {};
    }

    EVP_KDF_CTX_free(context);
    EVP_KDF_free(kdf);

    return derived_key;
}

DerivedKeys derive_keys(
    const std::vector<uint8_t>& shared_secret
) {
    DerivedKeys keys;

    keys.encryption_key =
        hkdf_derive(
            shared_secret,
            "NetworkingChat encryption"
        );

    keys.mac_key =
        hkdf_derive(
            shared_secret,
            "NetworkingChat MAC"
        );

    return keys;
}