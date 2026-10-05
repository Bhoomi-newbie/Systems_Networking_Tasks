#include <iostream>
#include <cstring>
#include <cstdint>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>  // TCP/IP functionality
#include "kdf.h"
#include "socket_utils.h"
#include "ecdh.h"
#include "hmac.h"
#include "crypto.h"
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

uint8_t confirmation_type;
std::string confirmation_data;

if (!recv_frame(
        clientSocket,
        confirmation_type,
        confirmation_data
    )) {

    std::cerr << "Failed to receive handshake confirmation.\n";

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

std::vector<uint8_t> transcript;
transcript.insert(
    transcript.end(),
    peer_public_key.begin(),
    peer_public_key.end()
);
transcript.insert(
    transcript.end(),
    public_key.begin(),
    public_key.end()
);

std::vector<uint8_t> expected_tag =
    hmac_sha256(
        keys.mac_key,
        transcript
    );
if (!verify_hmac(
        expected_tag,
        received_tag
    )) {

    std::cerr << "Handshake confirmation failed.\n";
    std::cerr << "Aborting connection.\n";

    EVP_PKEY_free(keypair);
    closesocket(clientSocket);
    cleanup_winsock();

    return 1;
}
std::cout << "Client handshake confirmation verified.\n";

std::string server_confirmation_data(
    reinterpret_cast<const char*>(
        expected_tag.data()
    ),
    expected_tag.size()
);

if (!send_frame(
        clientSocket,
        3,
        server_confirmation_data
    )) {

    std::cerr << "Failed to send handshake confirmation.\n";

    EVP_PKEY_free(keypair);
    closesocket(clientSocket);
    cleanup_winsock();

    return 1;
}
std::cout << "Handshake confirmation successful!\n";
EVP_PKEY_free(keypair);

uint8_t type;
std::string message;

if (!recv_frame(
        clientSocket,
        type,
        message
    )) {

    std::cerr << "Failed to receive message.\n";

    closesocket(clientSocket);
    closesocket(serverSocket);
    cleanup_winsock();

    return 1;
}

// Type 1 represents a normal chat message.
if (type != 1) {

    std::cerr << "Unexpected message type.\n";

    closesocket(clientSocket);
    closesocket(serverSocket);
    cleanup_winsock();

    return 1;
}

// The payload must contain:
// 16 bytes IV + ciphertext + 32 bytes HMAC.
if (message.size() < 48) {

    std::cerr << "Invalid encrypted message.\n";

    closesocket(clientSocket);
    closesocket(serverSocket);
    cleanup_winsock();

    return 1;
}

EncryptedMessage encrypted_message;

// Extract the 16-byte IV from the beginning.
encrypted_message.iv.assign(
    message.begin(),
    message.begin() + 16
);

// Extract the 32-byte HMAC from the end.
encrypted_message.mac.assign(
    message.end() - 32,
    message.end()
);

// The remaining bytes are the ciphertext.
encrypted_message.ciphertext.assign(
    message.begin() + 16,
    message.end() - 32
);

std::string decrypted_message;

// Verify the HMAC first.
// If verification succeeds, decrypt the ciphertext.
if (!decrypt_message(
        keys.encryption_key,
        keys.mac_key,
        encrypted_message,
        decrypted_message
    )) {

    std::cerr << "Message authentication failed.\n";
    std::cerr << "Message may have been tampered with.\n";
    std::cerr << "Aborting connection.\n";

    closesocket(clientSocket);
    closesocket(serverSocket);
    cleanup_winsock();

    return 1;
}

std::cout << "Received: "
          << decrypted_message
          << '\n';


// --------------------------------------------------
// Level 5: Encrypt and authenticate server response.
// --------------------------------------------------

std::string response =
    "Hello from server!";

// Encrypt the response using AES-256-CBC.
// A fresh random IV is generated for this message.
// An HMAC is then calculated over IV + ciphertext.
EncryptedMessage encrypted_response =
    encrypt_message(
        keys.encryption_key,
        keys.mac_key,
        response
    );

if (encrypted_response.iv.empty() ||
    encrypted_response.ciphertext.empty() ||
    encrypted_response.mac.empty()) {

    std::cerr << "Encryption failed.\n";

    closesocket(clientSocket);
    closesocket(serverSocket);
    cleanup_winsock();

    return 1;
}

// Construct the encrypted payload:
//
// [ IV ][ Ciphertext ][ HMAC ]
std::string response_payload;

response_payload.append(
    reinterpret_cast<const char*>(
        encrypted_response.iv.data()
    ),
    encrypted_response.iv.size()
);

response_payload.append(
    reinterpret_cast<const char*>(
        encrypted_response.ciphertext.data()
    ),
    encrypted_response.ciphertext.size()
);

response_payload.append(
    reinterpret_cast<const char*>(
        encrypted_response.mac.data()
    ),
    encrypted_response.mac.size()
);

// Send the encrypted response using our framing layer.
if (!send_frame(
        clientSocket,
        1,
        response_payload
    )) {

    std::cerr << "Failed to send encrypted response.\n";

    closesocket(clientSocket);
    closesocket(serverSocket);
    cleanup_winsock();

    return 1;
}

std::cout << "Encrypted response sent.\n";

    // Close the connected client socket.
    closesocket(clientSocket);
    // Close the listening socket.
    closesocket(serverSocket);
    // Clean up Winsock.
    cleanup_winsock();

    return 0;
}