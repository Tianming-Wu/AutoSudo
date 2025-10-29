cmake_minimum_required(VERSION 3.10)

project(AutoSudo
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

add_definitions("-DUNICODE" "-D_UNICODE")

# Set source and execution character sets to UTF-8 for MSVC
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/source-charset:utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/execution-charset:utf-8>")

# enable wchar_t support on logt
add_compile_definitions(LOGT_WCHAR_SUPPORT)

find_package(SharedCppLib2 REQUIRED)

# add_library(authlib STATIC src/authlib.cpp)
# target_link_libraries(authlib wintrust)
add_library(protocol STATIC src/protocol.cpp)

add_executable(AutoSudoSvc src/service_main.cpp src/pipeserver.cpp)
target_link_libraries(AutoSudoSvc protocol wtsapi32 userenv SharedCppLib2::logt)

add_executable(AutoSudo src/main.cpp src/installer.cpp src/pipeclient.cpp)
target_link_libraries(AutoSudo protocol wtsapi32 SharedCppLib2::logt)