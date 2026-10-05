#pragma once

#include <cstdint>
#include <vector>

struct DerivedKeys {
    std::vector<uint8_t> encryption_key;
    std::vector<uint8_t> mac_key;
};

DerivedKeys derive_keys(
    const std::vector<uint8_t>& shared_secret
);