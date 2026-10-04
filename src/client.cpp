#include <iostream>
#include <cstring>
#include <cstdint>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "socket_utils.h"
#include "ecdh.h"
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
    if (inet_pton(  // converts ip to binary form
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

    //generate client side keypair
    EVP_PKEY* keypair = generate_x25519_keypair();
if (keypair == nullptr) {
    std::cerr << "Failed to generate X25519 keypair\n";
    closesocket(clientSocket);
    return 1;
}

std::vector<uint8_t> public_key =
    get_public_key(keypair);
if (public_key.empty()) {
    std::cerr << "Failed to get public key\n";
    EVP_PKEY_free(keypair);
    closesocket(clientSocket);
    return 1;
}

// Send client's public key.
std::string public_key_data(
    reinterpret_cast<const char*>(public_key.data()),
    public_key.size()
);

if (!send_frame(clientSocket, 2, public_key_data)) {
    std::cerr << "Failed to send public key\n";
    EVP_PKEY_free(keypair);
    closesocket(clientSocket);
    return 1;
}

// Receive server's public key.
uint8_t peer_type;
std::string peer_key_data;

if (!recv_frame(clientSocket, peer_type, peer_key_data)) {
    std::cerr << "Failed to receive peer public key\n";
    EVP_PKEY_free(keypair);
    closesocket(clientSocket);
    return 1;
}

std::vector<uint8_t> peer_public_key(
    peer_key_data.begin(),
    peer_key_data.end()
);

// Compute shared secret.
std::vector<uint8_t> shared_secret =
    compute_shared_secret(keypair, peer_public_key);

if (shared_secret.empty()) {
    std::cerr << "Failed to compute shared secret\n";
    EVP_PKEY_free(keypair);
    closesocket(clientSocket);
    return 1;
}

std::cout << "ECDH key exchange successful!\n";
std::cout << "Shared secret size: "
          << shared_secret.size()
          << " bytes\n";

EVP_PKEY_free(keypair);

    // Send a message to the server.
    // const char* message = "Hello from client!";

    // send(
    //     clientSocket,
    //     message,
    //     static_cast<int>(std::strlen(message)),
    //     0
    // );

    // // Receive the server's response.
    // char buffer[BUFFER_SIZE];

    // int bytesReceived = recv(
    //     clientSocket,
    //     buffer,
    //     BUFFER_SIZE - 1,
    //     0
    // );

    // if (bytesReceived > 0) {

    //     buffer[bytesReceived] = '\0';

    //     std::cout << "Server: "
    //               << buffer
    //               << '\n';
    // }
    // else if (bytesReceived == 0) {
    //     std::cout << "Server closed the connection.\n";
    // }
    // else {
    //     print_socket_error("Receive failed.");
    // }

    // Send a framed message to the server.
send_frame(
    clientSocket,
    1,
    "Hello from client!"
);

// Receive a framed response from the server.
uint8_t type;
std::string message;

if (recv_frame(clientSocket, type, message)) {

    std::cout << "Received frame:\n";
    std::cout << "Type: " << static_cast<int>(type) << '\n';
    std::cout << "Length: " << message.size() << '\n';
    std::cout << "Payload: " << message << '\n';
}
else {
    print_socket_error("Failed to receive frame.");
}
    // Close the connection.
    closesocket(clientSocket);
    // Clean up Winsock.
    cleanup_winsock();

    return 0;
}