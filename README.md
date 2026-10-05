# Networking - TLS-Inspired Encrypted Chat

## Level 1 - Basic TCP Communication

### Implemented

- raw TCP client server model
- message framing with type bytes=[1], length field=[2] and payload=[length field] bytes

### Length field bytes

It could have fixed sizeslike 1, 2, 4 etc. as cstdint library is able to resolve them. If a size like 3 bytes would be used the it would unnecessarily make implementation complex.

### Challenges faced in Level 1

- CMake errors were coming up after initial implementation but the problem was incorrect CMake commands, so learnt them first
- I couldn't understand how client and server were connecting, so searched about it and got that the OS manages the TCP connection using the functions in code

### Architecture

```text
Client                         Server

socket()                       socket()
   |                              |
connect() --------------------> bind()
                                  |
                               listen()
                                  |
                               accept()
                                  |
send() ----------------------> recv()
   |                              |
recv() <---------------------- send()
   |                              |
close()                       closesocket()
```


## Level 2 - Diffie-Hellman Key Exchange

### Understanding
DH and ECDH

### Implemented

- X25519 key pair generation
- Public key extraction
- Public key exchange using the custom framing protocol
- Shared secret generation using X25519

### Architecture

```text
Client                              Server

Generate key pair                  Generate key pair
      |                                  |
      |---- Public Key ----------------->|
      |                                  |
      |<--- Public Key ------------------|
      |                                  |
Compute shared secret              Compute shared secret
      |                                  |
      └──────── Same shared secret ──────┘
```

## Level 3

### Understanding

A KDF takes the shared secret established through DH/ECDH and derives separate keys for different purposes, such as an encryption key and a MAC key. Since both sender and receiver have the same shared secret and use the same KDF specified by the protocol, they independently derive the same keys.
The sender encrypts the plaintext using the encryption key, producing ciphertext. It then uses the MAC key and the ciphertext with a MAC algorithm to generate a MAC tag. The sender transmits the ciphertext and MAC tag.
The receiver uses its MAC key to calculate a MAC tag over the received ciphertext and compares it with the received tag. If they match, the ciphertext has not been modified by an attacker who doesn't know the MAC key. The receiver can then decrypt the ciphertext using the encryption key

### HKDF - HMAC-based Key Derivation Function

HKDF is a two-stage key derivation construction. It first extracts a pseudorandom key from the shared secret, then expands that key into the required key material