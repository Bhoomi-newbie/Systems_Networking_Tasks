#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct EncryptedMessage {
    std::vector<uint8_t> iv;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> mac;
};

EncryptedMessage encrypt_message(
    const std::vector<uint8_t>& encryption_key,
    const std::vector<uint8_t>& mac_key,
    const std::string& plaintext
);

bool decrypt_message(
    const std::vector<uint8_t>& encryption_key,
    const std::vector<uint8_t>& mac_key,
    const EncryptedMessage& message,
    std::string& plaintext
);