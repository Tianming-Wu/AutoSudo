#pragma once

#include <string>

#include <SharedCppLib2/platform_windows.hpp>
#include <SharedCppLib2/bytearray.hpp>

#include "protocol.hpp"


class Broker
{
public:
    Broker();
    ~Broker();

    int Start(const std::wstring& pipeName, const std::bytearray& token);
    

private:
    bool Init();
    bool Wait();

    std::bytearray Receive();
    size_t Send(const std::bytearray& data);

    int RunProcess(const ProcessContext& pc);


private:
    std::wstring m_name;
    std::bytearray m_token;

    HANDLE hpipe;

    // Handles for communication with child process.
    HANDLE inRead = nullptr, inWrite = nullptr;
    HANDLE outRead = nullptr, outWrite = nullptr;

    // static constexpr size_t BUFFER_SIZE = 4096; // 4KB // defined in protocol

};