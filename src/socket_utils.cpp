#include "socket_utils.h"
#include <iostream>
#include <windows.h>

bool initialize_winsock() {
    WSADATA wsaData;

    // Request Winsock version 2.2.
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
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