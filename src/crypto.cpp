#include "crypto.h"
#include "hmac.h"

#include <openssl/evp.h>
#include <openssl/rand.h>


EncryptedMessage encrypt_message(
    const std::vector<uint8_t>& encryption_key,
    const std::vector<uint8_t>& mac_key,
    const std::string& plaintext
) {
    EncryptedMessage result;

    // AES-CBC requires a 16-byte Initialization Vector (IV).
    //
    // The IV does not need to be secret, so it will be
    // sent along with the ciphertext.
    result.iv.resize(16);

    // Generate a fresh random IV for this message.
    //
    // Using a new IV for every message prevents identical
    // plaintexts from producing predictable ciphertexts.
    if (RAND_bytes(
            result.iv.data(),
            16
        ) != 1) {

        return {};
    }

    // Create an AES encryption context.
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (ctx == nullptr) {
        return {};
    }

    // Initialize AES-256-CBC encryption using:
    //   - encryption_key -> AES key
    //   - result.iv      -> IV
    if (EVP_EncryptInit_ex(
            ctx,
            EVP_aes_256_cbc(),
            nullptr,
            encryption_key.data(),
            result.iv.data()
        ) != 1) {

        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // CBC encryption can add padding, so allocate
    // slightly more space than the plaintext.
    result.ciphertext.resize(
        plaintext.size() + 16
    );

    int len1 = 0;
    int len2 = 0;

    // Encrypt the plaintext.
    if (EVP_EncryptUpdate(
            ctx,
            result.ciphertext.data(),
            &len1,
            reinterpret_cast<const unsigned char*>(
                plaintext.data()
            ),
            static_cast<int>(plaintext.size())
        ) != 1) {

        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Finish encryption and add the required CBC padding.
    if (EVP_EncryptFinal_ex(
            ctx,
            result.ciphertext.data() + len1,
            &len2
        ) != 1) {

        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // The final ciphertext consists of the bytes
    // produced by both EncryptUpdate and EncryptFinal.
    result.ciphertext.resize(len1 + len2);

    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> data_to_auth;

    data_to_auth.insert(
        data_to_auth.end(),
        result.iv.begin(),
        result.iv.end()
    );

    data_to_auth.insert(
        data_to_auth.end(),
        result.ciphertext.begin(),
        result.ciphertext.end()
    );

    // Generate HMAC-SHA256 using the separate MAC key.
    result.mac = hmac_sha256(
        mac_key,
        data_to_auth
    );

    return result;
}


bool decrypt_message(
    const std::vector<uint8_t>& encryption_key,
    const std::vector<uint8_t>& mac_key,
    const EncryptedMessage& message,
    std::string& plaintext
) {
    // AES-CBC requires a 16-byte IV.
    //
    // HMAC-SHA256 produces a 32-byte authentication tag.
    if (message.iv.size() != 16 ||
        message.mac.size() != 32) {

        return false;
    }

    std::vector<uint8_t> data_to_auth;

    data_to_auth.insert(
        data_to_auth.end(),
        message.iv.begin(),
        message.iv.end()
    );

    data_to_auth.insert(
        data_to_auth.end(),
        message.ciphertext.begin(),
        message.ciphertext.end()
    );

    // Calculate what the MAC should be.
    std::vector<uint8_t> expected_mac =
        hmac_sha256(
            mac_key,
            data_to_auth
        );

    // Compare the received MAC with the newly calculated MAC.
    //
    // verify_hmac() uses a constant-time comparison,
    // which avoids leaking information through timing.
    if (!verify_hmac(
            expected_mac,
            message.mac
        )) {

        // If the MAC doesn't match, the message may have
        // been modified during transmission.
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (ctx == nullptr) {
        return false;
    }

    // Initialize AES-256-CBC decryption using the
    // same encryption key and IV used by the sender.
    if (EVP_DecryptInit_ex(
            ctx,
            EVP_aes_256_cbc(),
            nullptr,
            encryption_key.data(),
            message.iv.data()
        ) != 1) {

        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    plaintext.resize(
        message.ciphertext.size()
    );

    int len1 = 0;
    int len2 = 0;

    // Decrypt the ciphertext.
    if (EVP_DecryptUpdate(
            ctx,
            reinterpret_cast<unsigned char*>(
                plaintext.data()
            ),
            &len1,
            message.ciphertext.data(),
            static_cast<int>(
                message.ciphertext.size()
            )
        ) != 1) {

        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Finish decryption and remove CBC padding.
    if (EVP_DecryptFinal_ex(
            ctx,
            reinterpret_cast<unsigned char*>(
                plaintext.data()
            ) + len1,
            &len2
        ) != 1) {

        EVP_CIPHER_CTX_free(ctx);
        plaintext.clear();

        return false;
    }

    // Store the final plaintext length.
    plaintext.resize(len1 + len2);

    EVP_CIPHER_CTX_free(ctx);

    return true;
}