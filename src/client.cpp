#include <iostream>
#include <cstring>
#include <cstdint>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "kdf.h"
#include "socket_utils.h"
#include "ecdh.h"
#include "hmac.h"
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


// TEMPORARY TAMPERING TEST
//public_key[0] ^= 0x01;
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

std::vector<uint8_t> transcript;
transcript.insert(
    transcript.end(),
    public_key.begin(),
    public_key.end()
);
transcript.insert(
    transcript.end(),
    peer_public_key.begin(),
    peer_public_key.end()
);

std::vector<uint8_t> confirmation_tag =
    hmac_sha256(
        keys.mac_key,
        transcript
    );

std::string confirmation_data(
    reinterpret_cast<const char*>(
        confirmation_tag.data()
    ),
    confirmation_tag.size()
);

if (!send_frame(
        clientSocket,
        3,
        confirmation_data
    )) {

    std::cerr << "Failed to send handshake confirmation.\n";
      EVP_PKEY_free(keypair);
    closesocket(clientSocket);
    cleanup_winsock();

    return 1;
}

uint8_t confirmation_type;

if (!recv_frame(
        clientSocket,
        confirmation_type,
        confirmation_data
    )) {

    std::cerr << "Failed to receive server handshake confirmation.\n";

    EVP_PKEY_free(keypair);
    closesocket(clientSocket);
    cleanup_winsock();

    return 1;
}
if (confirmation_type != 3) {
    std::cerr << "Unexpected handshake confirmation type.\n";

    EVP_PKEY_free(keypair);
    closesocket(clientSocket);
    cleanup_winsock();

    return 1;
}
if (confirmation_data.size() != 32) {
    std::cerr << "Invalid handshake confirmation length.\n";

    EVP_PKEY_free(keypair);
    closesocket(clientSocket);
    cleanup_winsock();

    return 1;
}
std::vector<uint8_t> received_tag(
    confirmation_data.begin(),
    confirmation_data.end()
);
if (!verify_hmac(
        confirmation_tag,
        received_tag
    )) {

    std::cerr << "Server handshake confirmation failed.\n";
    std::cerr << "Aborting connection.\n";

    EVP_PKEY_free(keypair);
    closesocket(clientSocket);
    cleanup_winsock();

    return 1;
}
std::cout << "Handshake confirmation successful!\n";

EVP_PKEY_free(keypair);

    
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