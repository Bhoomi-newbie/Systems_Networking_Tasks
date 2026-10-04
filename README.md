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



## Level 2 - Diffie-Hellman Key Exchange

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
