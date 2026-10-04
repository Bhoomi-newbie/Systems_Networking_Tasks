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