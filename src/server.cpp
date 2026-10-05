#include <iostream>
#include <cstring>
#include <cstdint>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>  // TCP/IP functionality
#include "kdf.h"
#include "socket_utils.h"
#include "ecdh.h"
#pragma comment(lib, "Ws2_32.lib")  //link winsock library

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
    serverAddress.sin_family = AF_INET;  //IPv4
    serverAddress.sin_addr.s_addr = INADDR_ANY;  //listen for connections on all available local network interfaces
    serverAddress.sin_port = htons(PORT); //converts port no. from host byte order to network byte order

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
    if (listen(serverSocket, 5) == SOCKET_ERROR) {  // 5--> backlog
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

    //generate server side keypair
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

// Receive client's public key.
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

// Send our public key.
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

DerivedKeys keys = derive_keys(shared_secret);

if (keys.encryption_key.empty() ||
    keys.mac_key.empty()) {

    std::cerr << "Failed to derive keys\n";

    EVP_PKEY_free(keypair);
    closesocket(clientSocket);
    return 1;
}

std::cout << "HKDF key derivation successful!\n";

std::cout << "Encryption key size: "
          << keys.encryption_key.size()
          << " bytes\n";

std::cout << "MAC key size: "
          << keys.mac_key.size()
          << " bytes\n";

EVP_PKEY_free(keypair);

    // Receive a message from the client.
    // char buffer[BUFFER_SIZE];
    // int bytesReceived = recv(
    //     clientSocket,
    //     buffer,
    //     BUFFER_SIZE - 1,
    //     0
    // );

    // if (bytesReceived > 0) {

    //     // Add null terminator so we can print the received data as a string.
    //     buffer[bytesReceived] = '\0';

    //     std::cout << "Client: "
    //               << buffer
    //               << '\n';

    //     // Send a response back to the client.
    //     const char* response = "Hello from server!";

    //     send(
    //         clientSocket,
    //         response,
    //         static_cast<int>(std::strlen(response)),
    //         0
    //     );
    // }
    // else if (bytesReceived == 0) {
    //     std::cout << "Client closed the connection.\n";
    // }
    // else {
    //     print_socket_error("Receive failed.");
    // }

    // Receive a framed message from the client.
uint8_t type;
std::string message;

if (recv_frame(clientSocket, type, message)) {

    std::cout << "Received frame:\n";
    std::cout << "Type: " << static_cast<int>(type) << '\n';
    std::cout << "Length: " << message.size() << '\n';
    std::cout << "Payload: " << message << '\n';

    // Send a framed response back to the client.
    send_frame(
        clientSocket,
        1,
        "Hello from server!"
    );
}
else {
    print_socket_error("Failed to receive frame.");
}

    // Close the connected client socket.
    closesocket(clientSocket);
    // Close the listening socket.
    closesocket(serverSocket);
    // Clean up Winsock.
    cleanup_winsock();

    return 0;
}