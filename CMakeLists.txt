cmake_minimum_required(VERSION 3.15)

project(NetworkingChat)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# OpenSSL
set(OPENSSL_ROOT_DIR "C:/cpp_libs/OpenSSL")

include_directories(
    "${OPENSSL_ROOT_DIR}/include"
)

link_directories(
    "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD"
)

# Shared socket utility code.
add_library(socket_utils
    src/socket_utils.cpp
    src/ecdh.cpp
)

target_include_directories(socket_utils
    PUBLIC
        include
)

# Server executable.
add_executable(server
    src/server.cpp
)

target_link_libraries(server
    PRIVATE
        socket_utils
        ws2_32
        libcrypto
)

# Client executable.
add_executable(client
    src/client.cpp
)

target_link_libraries(client
    PRIVATE
        socket_utils
        ws2_32
        libcrypto
)