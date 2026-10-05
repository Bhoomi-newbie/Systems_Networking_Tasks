#pragma once

#include <cstdint>
#include <vector>

std::vector<uint8_t> hmac_sha256(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& data
);

bool verify_hmac(
    const std::vector<uint8_t>& expected,
    const std::vector<uint8_t>& actual
);