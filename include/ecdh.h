#pragma once

#include <openssl/evp.h>
#include <vector>
#include <cstdint>

// Generates an X25519 keypair.
// Returns nullptr if generation fails.
EVP_PKEY* generate_x25519_keypair();
//X25519 is an ecdh algorithm based on curve25519 and is directly supported by OpenSSL

// Extracts the public key as raw bytes.
std::vector<uint8_t> get_public_key(EVP_PKEY* keypair);

//compute the shared secret key
std::vector<uint8_t> compute_shared_secret(
    EVP_PKEY* keypair,
    const std::vector<uint8_t>& peer_public_key
);