cmake_minimum_required(VERSION 3.15)

project(NetworkingChat)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Shared socket utility code.
add_library(socket_utils
    src/socket_utils.cpp
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
)

# Client executable.
add_executable(client
    src/client.cpp
)

target_link_libraries(client
    PRIVATE
        socket_utils
        ws2_32
)