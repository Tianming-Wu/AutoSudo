#pragma once

#include <string>

#include <SharedCppLib2/platform_windows.hpp>
#include <SharedCppLib2/bytearray.hpp>

#include <libpipe.hpp>

#include "protocol.hpp"


class Broker
{
public:
    Broker(const std::string& pipeName, const std::string &inputStreamName, const std::string &outputStreamName, const std::bytearray& token);
    ~Broker();

    int Run();

private:
    int RunProcess(libpipe::pipe_server_client&& msgClient, const ProcessContext& pc);

private:
    std::string m_name, m_inputStreamName, m_outputStreamName;
    std::bytearray m_token;

    libpipe::pipe_server msgServer, inputStreamServer, outputStreamServer; // Control, input, and output streams

    // Handles for communication with child process.
    HANDLE inRead = nullptr, inWrite = nullptr;
    HANDLE outRead = nullptr, outWrite = nullptr;

    // static constexpr size_t BUFFER_SIZE = 4096; // 4KB // defined in protocol

};