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