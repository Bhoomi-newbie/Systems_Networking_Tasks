#include "kdf.h"
#include <openssl/evp.h> //OpenSSL's high-level cryptographic API
#include <openssl/kdf.h> //KDF functionality
#include <openssl/core_names.h> //HKDF parameters and names such as SHA-256
#include <openssl/params.h>  //used to pass parameters to OpenSSL
#include <string>

//helper function to perform key derivation using HKDF
static std::vector<uint8_t> hkdf_derive(const std::vector<uint8_t>& shared_secret, const std::string& info) {
    constexpr size_t KEY_SIZE = 32;
    std::vector<uint8_t> derived_key(KEY_SIZE);

    // Fetch the HKDF implementation from OpenSSL.
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr,"HKDF",nullptr);
    if (kdf == nullptr) {
        return {};
    }

    // Create a context for HKDF.
    EVP_KDF_CTX* context = EVP_KDF_CTX_new(kdf); //An OpenSSL context is an object that holds the state/configuration needed to perform one particular cryptographic operation
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

//Separately deriving encryption and mac keys using the helper function
DerivedKeys derive_keys(const std::vector<uint8_t>& shared_secret) {
    DerivedKeys keys;

    keys.encryption_key =
        hkdf_derive(
            shared_secret,
            "encryption_key"
        );

    keys.mac_key =
        hkdf_derive(
            shared_secret,
            "MAC_key"
        );

    return keys;
}