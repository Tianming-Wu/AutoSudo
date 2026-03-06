#pragma once
#include <SharedCppLib2/platform_windows.hpp>
#include <string>

#include "protocol.hpp"

#include <SharedCppLib2/logt.hpp>
#include <SharedCppLib2/platform.hpp>

class PipeClient {
    LOGT_DECLARE
public:
    PipeClient();
    ~PipeClient();
    
    bool Connect();
    bool SendRequest(const std::wstring& request);
    std::wstring ReadResponse();
    
private:
    HANDLE pipe_;
};