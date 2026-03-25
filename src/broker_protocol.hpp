/*
    Protocol module for Broker.
*/

#include <SharedCppLib2/bytearray.hpp>

enum class BrokerSignal : uint32_t
{
    Null = 0x00,
    ResizeConsole = 0x01,
    TerminateProcess = 0x02, // Like pressing Ctrl+C
};

enum class BrokerResponse : uint32_t
{
    Success = 0x00,
    InvalidToken = 0x01,
    ProcessStartFailed = 0x02,
    ConPTYCreationFailed = 0x03,
    SessionIDMismatch = 0x04,
};

struct ResizeConsoleData {
    short width;
    short height;
};

// The broker pipe name, used for ConPTY streaming.
// #define BROKER_PIPE_NAME R"(\\.\pipe\AutoSudoBrokerPipe)"