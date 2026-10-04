#pragma once
#include <winsock2.h> // Windows socket API; Provides networking and socket functionalities
#include <cstdint>  //fixed-size integer types
#include<string>
bool initialize_winsock(); // Initializes the Windows Socket API.

void cleanup_winsock(); // Cleans up the Windows Socket API.

void print_socket_error(const char* message); // Prints a Winsock error message and the associated error code.

// Sends exactly len bytes.
bool send_all(SOCKET socket, const char* data, int len);

// Receives exactly len bytes.
bool recv_all(SOCKET socket, char* data, int len);

// Sends a framed message:
// [TYPE][LENGTH][PAYLOAD]
bool send_frame(
    SOCKET socket,
    uint8_t type,
    const std::string& payload
);

// Receives a framed message.
bool recv_frame(
    SOCKET socket,
    uint8_t& type,
    std::string& payload
);