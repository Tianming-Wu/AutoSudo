#pragma once
#include <windows.h>
#include <userenv.h>
#include <string>

#include <SharedCppLib2/logt.hpp>
#include <SharedCppLib2/platform.hpp>

#include "protocol.hpp"

#define PIPE_NAME L"\\\\.\\pipe\\AutoSudoPipe"
#define BUFFER_SIZE 4096

class PipeServer {
    LOGT_DECLARE
public:
    PipeServer();
    ~PipeServer();
    
    // bool Start();
    bool StartNonBlocking();
    std::wstring ReadRequest();
    // std::wstring ReadRequestWithTimeout(DWORD timeoutMs);
    bool SendResponse(const std::wstring& response);
    HANDLE GetPipeHandle() const;
    
private:
    HANDLE pipe_;
};