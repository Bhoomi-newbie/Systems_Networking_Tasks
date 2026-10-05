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
#include "crypto.h"
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

    
std::string message_to_send =
    "Hello from client!";

// Encrypt the message using AES-256-CBC.
// The function also generates a fresh random IV
// and calculates an HMAC-SHA256 over IV + ciphertext.
EncryptedMessage encrypted =
    encrypt_message(
        keys.encryption_key,
        keys.mac_key,
        message_to_send
    );

if (encrypted.iv.empty() ||
    encrypted.ciphertext.empty() ||
    encrypted.mac.empty()) {

    std::cerr << "Encryption failed.\n";

    closesocket(clientSocket);
    cleanup_winsock();

    return 1;
}

// Construct the payload:
//
// [ IV ][ Ciphertext ][ HMAC ]
//
// The IV is not secret, so it can be sent along
// with the encrypted message.
std::string payload;

payload.append(
    reinterpret_cast<const char*>(
        encrypted.iv.data()
    ),
    encrypted.iv.size()
);

payload.append(
    reinterpret_cast<const char*>(
        encrypted.ciphertext.data()
    ),
    encrypted.ciphertext.size()
);

payload.append(
    reinterpret_cast<const char*>(
        encrypted.mac.data()
    ),
    encrypted.mac.size()
);

// Send the encrypted message using our existing
// application-layer framing:
// [ Type ][ Length ][ Payload ]
if (!send_frame(
        clientSocket,
        1,
        payload
    )) {

    std::cerr << "Failed to send encrypted message.\n";

    closesocket(clientSocket);
    cleanup_winsock();

    return 1;
}

std::cout << "Encrypted message sent.\n";

// Receive a framed response from the server.
uint8_t type;
std::string message;

if (!recv_frame(
        clientSocket,
        type,
        message
    )) {

    std::cerr << "Failed to receive message.\n";

    closesocket(clientSocket);
    cleanup_winsock();

    return 1;
}

// Type 1 represents a normal chat message.
if (type != 1) {

    std::cerr << "Unexpected message type.\n";

    closesocket(clientSocket);
    cleanup_winsock();

    return 1;
}

// The payload must contain at least:
// 16 bytes IV + 32 bytes HMAC.
// The ciphertext itself can be larger.
if (message.size() < 48) {

    std::cerr << "Invalid encrypted message.\n";

    closesocket(clientSocket);
    cleanup_winsock();

    return 1;
}

EncryptedMessage encrypted_response;

// Extract the first 16 bytes as the IV.
encrypted_response.iv.assign(
    message.begin(),
    message.begin() + 16
);

// Extract the last 32 bytes as the HMAC.
encrypted_response.mac.assign(
    message.end() - 32,
    message.end()
);

// Everything between the IV and HMAC is ciphertext.
encrypted_response.ciphertext.assign(
    message.begin() + 16,
    message.end() - 32
);

std::string decrypted_message;

// decrypt_message() first verifies the HMAC.
// Only if the HMAC is valid does it decrypt the message.
if (!decrypt_message(
        keys.encryption_key,
        keys.mac_key,
        encrypted_response,
        decrypted_message
    )) {

    std::cerr << "Message authentication failed.\n";
    std::cerr << "Message may have been tampered with.\n";
    std::cerr << "Aborting connection.\n";

    closesocket(clientSocket);
    cleanup_winsock();

    return 1;
}

std::cout << "Received: "
          << decrypted_message
          << '\n';
// else {
//     print_socket_error("Failed to receive frame.");
// }
    // Close the connection.
    closesocket(clientSocket);
    // Clean up Winsock.
    cleanup_winsock();

    return 0;
}