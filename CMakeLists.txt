cmake_minimum_required(VERSION 3.10)

project(AutoSudo
    VERSION 4.0.1
    LANGUAGES CXX
)

include(CMakePackageConfigHelpers)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

add_definitions("-DUNICODE" "-D_UNICODE")

# Set source and execution character sets to UTF-8 for MSVC
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/source-charset:utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/execution-charset:utf-8>")

# enable wchar_t support on logt
add_compile_definitions(LOGT_WCHAR_SUPPORT)

find_package(SharedCppLib2 REQUIRED)
find_package(libpipe REQUIRED)

add_library(authlib STATIC src/authlib.cpp)
target_link_libraries(authlib wintrust SharedCppLib2::api)
# add_library(auth STATIC src/auth.cpp)
# target_link_libraries(auth PRIVATE SharedCppLib2::basic SharedCppLib2::sha256 SharedCppLib2::platform libpipe::libpipe)

add_library(protocol STATIC src/protocol.cpp)
target_link_libraries(protocol PRIVATE SharedCppLib2::basic)

# service
add_executable(AutoSudoSvc src/service_main.cpp src/wintoken.cpp src/approval.cpp)
target_link_libraries(AutoSudoSvc protocol authlib wtsapi32 userenv SharedCppLib2::logt SharedCppLib2::platform libpipe::libpipe SharedCppLib2::sha256 SharedCppLib2::singleinst) # auth
target_include_directories(AutoSudoSvc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# client command-line version
add_executable(AutoSudo src/client_main.cpp src/installer.cpp src/rule_client.cpp)
target_link_libraries(AutoSudo protocol wtsapi32 SharedCppLib2::basic SharedCppLib2::logt SharedCppLib2::platform SharedCppLib2::arguments libpipe::libpipe)

# client gui version
add_executable(AutoSudoW src/client_main.cpp src/installer.cpp src/rule_client.cpp)
target_link_libraries(AutoSudoW protocol comctl32 wtsapi32 SharedCppLib2::basic SharedCppLib2::logt SharedCppLib2::platform SharedCppLib2::arguments libpipe::libpipe)
set_target_properties(AutoSudoW PROPERTIES WIN32_EXECUTABLE TRUE)
target_compile_definitions(AutoSudoW PUBLIC AUTOSUDO_GUI)

# auth ui
add_executable(AuthUI src/auth_ui.cpp)
set_target_properties(AuthUI PROPERTIES WIN32_EXECUTABLE TRUE)

# broker
add_executable(AutoSudoBroker src/broker_main.cpp src/broker.cpp)
target_link_libraries(AutoSudoBroker protocol wtsapi32 userenv SharedCppLib2::logt SharedCppLib2::platform libpipe::libpipe) # auth
set_target_properties(AutoSudoBroker PROPERTIES WIN32_EXECUTABLE TRUE)
target_link_options(AutoSudoBroker PRIVATE /ENTRY:mainCRTStartup)



# sdk
add_library(AutoSudoSdk STATIC src/protocol.cpp src/sdk.cpp src/rule_client.cpp)
target_link_libraries(AutoSudoSdk PUBLIC SharedCppLib2::basic)
target_include_directories(AutoSudoSdk PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:include/AutoSudoSdk>
)

install(TARGETS AutoSudoSdk
    EXPORT AutoSudoSdkTargets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/defs.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/protocol.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sdk.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/rule_client.hpp
    DESTINATION include/AutoSudoSdk
)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/AutoSudoSdkConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/AutoSudoSdkConfig.cmake
    INSTALL_DESTINATION lib/cmake/AutoSudoSdk
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/AutoSudoSdkConfigVersion.cmake
    VERSION 1.0.0
    COMPATIBILITY SameMajorVersion
)

install(EXPORT AutoSudoSdkTargets
    FILE AutoSudoSdkTargets.cmake
    NAMESPACE AutoSudoSdk::
    DESTINATION lib/cmake/AutoSudoSdk
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/AutoSudoSdkConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/AutoSudoSdkConfigVersion.cmake
    DESTINATION lib/cmake/AutoSudoSdk
)