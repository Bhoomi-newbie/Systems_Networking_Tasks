#pragma once
#include <winsock2.h> // Windows socket API; Provides networking functionalities

bool initialize_winsock(); // Initializes the Windows Socket API.

void cleanup_winsock(); // Cleans up the Windows Socket API.

void print_socket_error(const char* message); // Prints a Winsock error message and the associated error code.