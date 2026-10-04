#include "socket_utils.h"
#include <iostream>
#include <windows.h>

bool initialize_winsock() {
    WSADATA wsaData;
    // Request Winsock version 2.2. and fill wsaData with Winsock implementation information
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {  //result == 0 --> connection successfull else failure
        std::cerr << "WSAStartup failed. Error: " << result << '\n';
        return false;
    }

    return true;
}

void cleanup_winsock() {
    WSACleanup();
}

void print_socket_error(const char* message) {
    std::cerr << message << " Error code: "<< WSAGetLastError() << '\n';
}

// Sends exactly len bytes.
// send() may send fewer bytes than requested,
// so we keep sending until everything is sent.
bool send_all(SOCKET socket, const char* data, int len) {

    int totalSent = 0;
    while (totalSent < len) {
        int bytesSent = send(
            socket,
            data + totalSent,
            len - totalSent,
            0
        );

        if (bytesSent == SOCKET_ERROR) {
            return false;
        }

        totalSent += bytesSent;
    }

    return true;
}


// Receives exactly len bytes.
// recv() may receive fewer bytes than requested,
// so we keep receiving until everything arrives.
bool recv_all(SOCKET socket, char* data, int len) {

    int totalReceived = 0;
    while (totalReceived < len) {
        int bytesReceived = recv(
            socket,
            data + totalReceived,
            len - totalReceived,
            0
        );

        if (bytesReceived <= 0) {
            return false;
        }

        totalReceived += bytesReceived;
    }

    return true;
}


// Frame format:
//
// [ 1 byte TYPE ]
// [ 2 byte LENGTH ]
// [ LENGTH bytes PAYLOAD ]
//
bool send_frame(
    SOCKET socket,
    uint8_t type,
    const std::string& payload
) {
    // A 2-byte length can represent at most 65535 bytes.
    if (payload.size() > 65535) {
        return false;
    }
    uint16_t length = static_cast<uint16_t>(payload.size());// length field
    // Convert length to network byte order.
    uint16_t networkLength = htons(length);

    // Send TYPE.
    if (!send_all(
            socket,
            reinterpret_cast<const char*>(&type),
            sizeof(type)
        )) {
        return false;
    }

    // Send LENGTH.
    if (!send_all(
            socket,
            reinterpret_cast<const char*>(&networkLength),
            sizeof(networkLength)
        )) {
        return false;
    }

    // Send PAYLOAD.
    if (length > 0) {
        if (!send_all(
                socket,
                payload.data(),
                length
            )) {
            return false;
        }
    }

    return true;
}


// Receives:
//
// [ TYPE ]
// [ LENGTH ]
// [ PAYLOAD ]
//
bool recv_frame(
    SOCKET socket,
    uint8_t& type,
    std::string& payload
) {
    uint16_t networkLength;

    // Receive TYPE.
    if (!recv_all(
            socket,
            reinterpret_cast<char*>(&type),
            sizeof(type)
        )) {
        return false;
    }

    // Receive LENGTH.
    if (!recv_all(
            socket,
            reinterpret_cast<char*>(&networkLength),
            sizeof(networkLength)
        )) {
        return false;
    }

    // Convert network byte order back to host byte order.
    uint16_t length = ntohs(networkLength);

    // Receive PAYLOAD.
    payload.resize(length);

    if (length > 0) {
        if (!recv_all(
                socket,
                payload.data(),
                length
            )) {
            return false;
        }
    }

    return true;
}