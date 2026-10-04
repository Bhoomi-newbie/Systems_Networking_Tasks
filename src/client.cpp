#include <iostream>
#include <cstring>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "socket_utils.h"

#pragma comment(lib, "Ws2_32.lib")

constexpr int PORT = 8080;
constexpr int BUFFER_SIZE = 1024;

int main() {

    // Initialize Winsock.
    if (!initialize_winsock()) {
        return 1;
    }

    // Create a TCP socket.
    SOCKET clientSocket = socket(
        AF_INET,
        SOCK_STREAM,
        IPPROTO_TCP
    );

    if (clientSocket == INVALID_SOCKET) {
        print_socket_error("Socket creation failed.");
        cleanup_winsock();
        return 1;
    }

    // Configure the server's address.
    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);

    // Connect to the server running on localhost.
    if (inet_pton(
            AF_INET,
            "127.0.0.1",
            &serverAddress.sin_addr
        ) != 1) {

        std::cerr << "Invalid server address.\n";

        closesocket(clientSocket);
        cleanup_winsock();
        return 1;
    }

    // Establish the TCP connection.
    if (connect(
            clientSocket,
            reinterpret_cast<sockaddr*>(&serverAddress),
            sizeof(serverAddress)
        ) == SOCKET_ERROR) {

        print_socket_error("Connection failed.");

        closesocket(clientSocket);
        cleanup_winsock();
        return 1;
    }

    std::cout << "Connected to server!\n";

    // Send a message to the server.
    const char* message = "Hello from client!";

    send(
        clientSocket,
        message,
        static_cast<int>(std::strlen(message)),
        0
    );

    // Receive the server's response.
    char buffer[BUFFER_SIZE];

    int bytesReceived = recv(
        clientSocket,
        buffer,
        BUFFER_SIZE - 1,
        0
    );

    if (bytesReceived > 0) {

        buffer[bytesReceived] = '\0';

        std::cout << "Server: "
                  << buffer
                  << '\n';
    }
    else if (bytesReceived == 0) {
        std::cout << "Server closed the connection.\n";
    }
    else {
        print_socket_error("Receive failed.");
    }

    // Close the connection.
    closesocket(clientSocket);

    // Clean up Winsock.
    cleanup_winsock();

    return 0;
}