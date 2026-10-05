#include "hmac.h"

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>


//to generaate the mac tag
std::vector<uint8_t> hmac_sha256(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& data
) {
    EVP_MAC* mac = EVP_MAC_fetch(nullptr,"HMAC",nullptr);
    if (mac == nullptr) {
        return {};
    }

    EVP_MAC_CTX* context = EVP_MAC_CTX_new(mac);
    if (context == nullptr) {
        EVP_MAC_free(mac);
        return {};
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_MAC_PARAM_DIGEST,
            const_cast<char*>("SHA256"),
            0
        ),
        OSSL_PARAM_construct_end()
    };

    if (EVP_MAC_init(
            context,
            key.data(),
            key.size(),
            params
        ) <= 0) {

        EVP_MAC_CTX_free(context);
        EVP_MAC_free(mac);
        return {};
    }

    if (EVP_MAC_update(
            context,
            data.data(),
            data.size()
        ) <= 0) {
        EVP_MAC_CTX_free(context);
        EVP_MAC_free(mac);
        return {};
    }

    size_t tag_length = 0;

    if (EVP_MAC_final(
            context,
            nullptr,
            &tag_length,
            0
        ) <= 0) {

        EVP_MAC_CTX_free(context);
        EVP_MAC_free(mac);

        return {};
    }

    std::vector<uint8_t> tag(tag_length);

    if (EVP_MAC_final(
            context,
            tag.data(),
            &tag_length,
            tag.size()
        ) <= 0) {

        EVP_MAC_CTX_free(context);
        EVP_MAC_free(mac);

        return {};
    }

    tag.resize(tag_length);

    EVP_MAC_CTX_free(context);
    EVP_MAC_free(mac);

    return tag;
}

//to comapare 2 mac tags
bool verify_hmac(
    const std::vector<uint8_t>& expected,
    const std::vector<uint8_t>& actual
) {
    if (expected.size() != actual.size()) {
        return false;
    }

    return CRYPTO_memcmp(
        expected.data(),
        actual.data(),
        expected.size()
    ) == 0;
}