#pragma once

#include <string>

#include <SharedCppLib2/platform_windows.hpp>
#include <SharedCppLib2/bytearray.hpp>

#include <SharedCppLib2/pipe.hpp>

#include "protocol.hpp"


class Broker
{
public:
    Broker(const std::string& pipeName, const std::string &inputStreamName, const std::string &outputStreamName, const scl2::bytearray& token);
    ~Broker();

    int Run();

private:
    int RunProcess(scl2::pipe::server_client&& msgClient, const AutoSudoRequest& request);

private:
    std::string m_name, m_inputStreamName, m_outputStreamName;
    scl2::bytearray m_token;

    scl2::pipe::server msgServer, inputStreamServer, outputStreamServer; // Control, input, and output streams

    // Handles for communication with child process.
    HANDLE inRead = nullptr, inWrite = nullptr;
    HANDLE outRead = nullptr, outWrite = nullptr;

    // static constexpr size_t BUFFER_SIZE = 4096; // 4KB // defined in protocol

};