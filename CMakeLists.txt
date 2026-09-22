cmake_minimum_required(VERSION 3.10)

project(AutoSudo
    VERSION 5.0.0
    LANGUAGES CXX
)

include(CMakePackageConfigHelpers)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

add_definitions("-DUNICODE" "-D_UNICODE")

# add a d postfix in name to prevent colliding
set(CMAKE_DEBUG_POSTFIX "d")

# Set source and execution character sets to UTF-8 for MSVC
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/source-charset:utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/execution-charset:utf-8>")

# enable wchar_t support on logt
add_compile_definitions(LOGT_WCHAR_SUPPORT)

find_package(SharedCppLib2 REQUIRED)

# AuthUI uses SCF for the notifications (an elevated process handing a toast to the shell).
# SCF is installed beside SharedCppLib2, so a configure that knows one of them knows both.
get_filename_component(SharedCppLib2_PREFIX "${SharedCppLib2_DIR}/../../.." ABSOLUTE)
list(APPEND CMAKE_PREFIX_PATH "${SharedCppLib2_PREFIX}")
find_package(SCF REQUIRED)

add_library(authlib STATIC src/authlib.cpp)
target_link_libraries(authlib wintrust SharedCppLib2::api)
# add_library(auth STATIC src/auth.cpp)
# target_link_libraries(auth PRIVATE SharedCppLib2::basic SharedCppLib2::sha256 SharedCppLib2::platform SharedCppLib2::pipe)

add_library(protocol STATIC src/protocol.cpp)
target_link_libraries(protocol PRIVATE SharedCppLib2::basic)

# service
add_executable(AutoSudoSvc src/service_main.cpp src/wintoken.cpp src/approval.cpp src/callerid.cpp src/keyvault.cpp src/authui.cpp)
target_link_libraries(AutoSudoSvc protocol authlib wtsapi32 userenv crypt32 bcrypt SharedCppLib2::logt SharedCppLib2::platform SharedCppLib2::pipe SharedCppLib2::sha256 SharedCppLib2::xkeydb SharedCppLib2::singleinst) # auth
target_include_directories(AutoSudoSvc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# client command-line version
add_executable(AutoSudo src/client_main.cpp src/installer.cpp src/rule_client.cpp)
target_link_libraries(AutoSudo protocol wtsapi32 SharedCppLib2::basic SharedCppLib2::logt SharedCppLib2::platform SharedCppLib2::arguments SharedCppLib2::pipe)

# client gui version
add_executable(AutoSudoW src/client_main.cpp src/installer.cpp src/rule_client.cpp)
target_link_libraries(AutoSudoW protocol comctl32 wtsapi32 SharedCppLib2::basic SharedCppLib2::logt SharedCppLib2::platform SharedCppLib2::arguments SharedCppLib2::pipe)
set_target_properties(AutoSudoW PROPERTIES WIN32_EXECUTABLE TRUE)
target_compile_definitions(AutoSudoW PUBLIC AUTOSUDO_GUI)

# auth ui
# scf_static rather than scf: one less DLL to deploy beside AuthUI, and the notification
# code is a small part of what it links.
add_executable(AuthUI src/auth_ui.cpp)
target_link_libraries(AuthUI scf_static)
set_target_properties(AuthUI PROPERTIES WIN32_EXECUTABLE TRUE)

# broker
add_executable(AutoSudoBroker src/broker_main.cpp src/broker.cpp)
target_link_libraries(AutoSudoBroker protocol wtsapi32 userenv SharedCppLib2::logt SharedCppLib2::platform SharedCppLib2::pipe) # auth
set_target_properties(AutoSudoBroker PROPERTIES WIN32_EXECUTABLE TRUE)
target_link_options(AutoSudoBroker PRIVATE /ENTRY:mainCRTStartup)

# A rules CLI, for debug runs only.
# The GUI is how a rule set is meant to be handled, but a GUI is a poor place to test what is
# underneath it. This drives the control channel from a shell, so a set can be listed, edited,
# exported and imported without a window in the way.
# EXCLUDE_FROM_ALL keeps a tool for working on the service out of every normal build, and the
# define pins it to the debug channel whatever configuration it is built in - see defs.hpp. The
# client side of the SDK is compiled here rather than linked from AutoSudoSdk because that define
# has to reach the code that picks the pipe name.
add_executable(AutoSudoRuleCli EXCLUDE_FROM_ALL
    src/rules_cli.cpp
    src/sdk.cpp
    src/rules_io.cpp
    src/rule_client.cpp
    src/protocol.cpp
)
target_link_libraries(AutoSudoRuleCli SharedCppLib2::basic SharedCppLib2::logt SharedCppLib2::platform SharedCppLib2::pipe SharedCppLib2::json SharedCppLib2::base64)
target_compile_definitions(AutoSudoRuleCli PRIVATE
    SCL2_JSON_ENABLE_EXTENSIONS
    AUTOSUDO_FORCE_DEBUG_CHANNEL
)



# sdk
add_library(AutoSudoSdk STATIC src/protocol.cpp src/sdk.cpp src/rule_client.cpp src/rules_io.cpp)
target_link_libraries(AutoSudoSdk PUBLIC SharedCppLib2::basic SharedCppLib2::pipe)
target_link_libraries(AutoSudoSdk PRIVATE SharedCppLib2::json SharedCppLib2::base64)
# A rule's payload is bytes, and the export format carries it as the json extension's
# "base64:..." string, so the SDK is built with that extension on.
target_compile_definitions(AutoSudoSdk PRIVATE SCL2_JSON_ENABLE_EXTENSIONS)
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
    VERSION 2.1.0
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