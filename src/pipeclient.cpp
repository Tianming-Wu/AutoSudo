#include "pipeclient.hpp"


LOGT_DEFINE(PipeClient, "PipeClient");

PipeClient::PipeClient() : pipe_(INVALID_HANDLE_VALUE) {}

PipeClient::~PipeClient() {
    if (pipe_ != INVALID_HANDLE_VALUE) {
        CloseHandle(pipe_);
    }
}

bool PipeClient::Connect() {
    // 等待管道可用
    if (!WaitNamedPipe(PIPE_NAME, 5000)) {
        logt.error() << "WaitNamedPipe failed: " << platform::windows::TranslateLastError();
        return false;
    }
    
    // 连接到管道
    pipe_ = CreateFile(
        PIPE_NAME,                      // 管道名称
        GENERIC_READ | GENERIC_WRITE,    // 读写权限
        0,                              // 不共享
        nullptr,                        // 默认安全属性
        OPEN_EXISTING,                  // 打开已有管道
        0,                              // 默认属性
        nullptr                         // 无模板文件
    );
    
    if (pipe_ == INVALID_HANDLE_VALUE) {
        logt.error() << "CreateFile failed: " << platform::windows::TranslateLastError();
        return false;
    }
    
    // 设置管道读取模式
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(pipe_, &mode, nullptr, nullptr)) {
        logt.error() << "SetNamedPipeHandleState failed: " << platform::windows::TranslateLastError();
        return false;
    }
    
    return true;
}

bool PipeClient::SendRequest(const std::wstring& request) {
    DWORD bytesWritten;
    if (!WriteFile(pipe_, request.c_str(), DWORD((request.size() + 1) * sizeof(wchar_t)), &bytesWritten, nullptr)) {
        logt.error() << "WriteFile failed: " << platform::windows::TranslateLastError();
        return false;
    }
    return true;
}

std::wstring PipeClient::ReadResponse() {
    wchar_t buffer[BUFFER_SIZE];
    DWORD bytesRead;
    
    if (!ReadFile(pipe_, buffer, BUFFER_SIZE * sizeof(wchar_t), &bytesRead, nullptr)) {
        logt.error() << "ReadFile failed: " << platform::windows::TranslateLastError();
        return L"";
    }
    
    return std::wstring(buffer, bytesRead / sizeof(wchar_t));
}