#include <iostream>
#include <cstring>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "socket_utils.h"

#pragma comment(lib, "Ws2_32.lib")

constexpr int PORT = 8080;
constexpr int BUFFER_SIZE = 1024;

int main() {

    // Initialize Winsock before using any socket functions.
    if (!initialize_winsock()) {
        return 1;
    }

    // Create a TCP socket.
    SOCKET serverSocket = socket(
        AF_INET,
        SOCK_STREAM,
        IPPROTO_TCP
    );

    if (serverSocket == INVALID_SOCKET) {
        print_socket_error("Socket creation failed.");
        cleanup_winsock();
        return 1;
    }

    // Configure the server address.
    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(PORT);

    // Bind the socket to port 8080.
    if (bind(
            serverSocket,
            reinterpret_cast<sockaddr*>(&serverAddress),
            sizeof(serverAddress)
        ) == SOCKET_ERROR) {

        print_socket_error("Bind failed.");

        closesocket(serverSocket);
        cleanup_winsock();
        return 1;
    }

    // Start listening for incoming TCP connections.
    if (listen(serverSocket, 5) == SOCKET_ERROR) {
        print_socket_error("Listen failed.");

        closesocket(serverSocket);
        cleanup_winsock();
        return 1;
    }

    std::cout << "Server listening on port "
              << PORT << "...\n";

    // Wait for a client to connect.
    sockaddr_in clientAddress{};
    int clientAddressLength = sizeof(clientAddress);

    SOCKET clientSocket = accept(
        serverSocket,
        reinterpret_cast<sockaddr*>(&clientAddress),
        &clientAddressLength
    );

    if (clientSocket == INVALID_SOCKET) {
        print_socket_error("Accept failed.");

        closesocket(serverSocket);
        cleanup_winsock();
        return 1;
    }

    std::cout << "Client connected!\n";

    // Receive a message from the client.
    char buffer[BUFFER_SIZE];

    int bytesReceived = recv(
        clientSocket,
        buffer,
        BUFFER_SIZE - 1,
        0
    );

    if (bytesReceived > 0) {

        // Add null terminator so we can print the received data as a string.
        buffer[bytesReceived] = '\0';

        std::cout << "Client: "
                  << buffer
                  << '\n';

        // Send a response back to the client.
        const char* response = "Hello from server!";

        send(
            clientSocket,
            response,
            static_cast<int>(std::strlen(response)),
            0
        );
    }
    else if (bytesReceived == 0) {
        std::cout << "Client closed the connection.\n";
    }
    else {
        print_socket_error("Receive failed.");
    }

    // Close the connected client socket.
    closesocket(clientSocket);

    // Close the listening socket.
    closesocket(serverSocket);

    // Clean up Winsock.
    cleanup_winsock();

    return 0;
}