#include "ecdh.h"

EVP_PKEY* generate_x25519_keypair() {

    EVP_PKEY_CTX* context =
        EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);  //holds the workspace/configuration for X25519

    if (context == nullptr) {
        return nullptr;
    }

    if (EVP_PKEY_keygen_init(context) <= 0) {  //initialize context for key generation and if it fails, free the context
        EVP_PKEY_CTX_free(context);
        return nullptr;
    }

    EVP_PKEY* keypair = nullptr;

    if (EVP_PKEY_keygen(context, &keypair) <= 0) {  //keypair generation using context, stored in variable keypair
        EVP_PKEY_CTX_free(context);
        return nullptr;
    }

    EVP_PKEY_CTX_free(context);  //free the context - release resources allocated to context to prevent memory leaks

    return keypair;
}

//extracting public key in raw bytes to transfer over tcp
std::vector<uint8_t> get_public_key(EVP_PKEY* keypair) {

    size_t public_key_length = 0;

    // First ask OpenSSL how many bytes the public key needs.
    if (EVP_PKEY_get_raw_public_key(
            keypair,
            nullptr,
            &public_key_length
        ) <= 0) {
        return {};
    }
    
    std::vector<uint8_t> public_key(public_key_length); // Allocate enough space for the public key.
    // Actually copy the public key into our vector.
    if (EVP_PKEY_get_raw_public_key(
            keypair,
            public_key.data(),  
            &public_key_length
        ) <= 0) {
        return {};
    }

    return public_key;
}

std::vector<uint8_t> compute_shared_secret(
    EVP_PKEY* keypair,
    const std::vector<uint8_t>& peer_public_key
) {
    // Create an EVP_PKEY from the other side's raw public key.
    EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519,
        nullptr,
        peer_public_key.data(),
        peer_public_key.size()
    );

    if (peer_key == nullptr) {
        return {};
    }

    // Create a context for the key derivation.
    EVP_PKEY_CTX* context =
        EVP_PKEY_CTX_new(keypair, nullptr);

    if (context == nullptr) {
        EVP_PKEY_free(peer_key);
        return {};
    }

    // Initialize key derivation.
    if (EVP_PKEY_derive_init(context) <= 0) {
        EVP_PKEY_CTX_free(context);
        EVP_PKEY_free(peer_key);
        return {};
    }

    // Give OpenSSL the other side's public key.
    if (EVP_PKEY_derive_set_peer(context, peer_key) <= 0) {
        EVP_PKEY_CTX_free(context);
        EVP_PKEY_free(peer_key);
        return {};
    }

    // First ask OpenSSL how large the shared secret will be.
    size_t secret_length = 0;

    if (EVP_PKEY_derive(
            context,
            nullptr,
            &secret_length
        ) <= 0) {
        EVP_PKEY_CTX_free(context);
        EVP_PKEY_free(peer_key);
        return {};
    }

    // Allocate space for the shared secret.
    std::vector<uint8_t> shared_secret(secret_length);

    // Actually derive the shared secret.
    if (EVP_PKEY_derive(
            context,
            shared_secret.data(),
            &secret_length
        ) <= 0) {
        EVP_PKEY_CTX_free(context);
        EVP_PKEY_free(peer_key);
        return {};
    }

    shared_secret.resize(secret_length);
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(peer_key);

    return shared_secret;
}