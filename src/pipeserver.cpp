#include "pipeserver.hpp"

LOGT_DEFINE(PipeServer, "PipeServer");

PipeServer::PipeServer() : pipe_(INVALID_HANDLE_VALUE) {}

PipeServer::~PipeServer() {
    if (pipe_ != INVALID_HANDLE_VALUE) {
        CloseHandle(pipe_);
    }
}

bool PipeServer::Start() {
    // 创建命名管道
    pipe_ = CreateNamedPipe(
        PIPE_NAME,                      // 管道名称
        PIPE_ACCESS_DUPLEX,             // 双向通信
        PIPE_TYPE_MESSAGE |             // 消息模式
        PIPE_READMODE_MESSAGE |        // 消息读取模式
        PIPE_WAIT,                      // 阻塞模式
        PIPE_UNLIMITED_INSTANCES,       // 最大实例数
        BUFFER_SIZE,                    // 输出缓冲区大小
        BUFFER_SIZE,                    // 输入缓冲区大小
        0,                              // 默认超时
        nullptr                         // 默认安全属性
    );
    
    if (pipe_ == INVALID_HANDLE_VALUE) {
        logt.error() << "CreateNamedPipe failed: " << platform::windows::TranslateLastError();
        return false;
    }
    
    logt.info() << "Named pipe server started. Waiting for client...";
    
    // 等待客户端连接
    if (!ConnectNamedPipe(pipe_, nullptr) && GetLastError() != ERROR_PIPE_CONNECTED) {
        logt.error() << "ConnectNamedPipe failed: " << platform::windows::TranslateLastError();
        return false;
    }
    
    logt.info() << "Client connected.";
    return true;
}

bool PipeServer::StartNonBlocking() {
    pipe_ = CreateNamedPipe(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        BUFFER_SIZE,
        BUFFER_SIZE,
        NMPWAIT_USE_DEFAULT_WAIT,
        nullptr
    );
    
    if (pipe_ == INVALID_HANDLE_VALUE) {
        logt.error() << "CreateNamedPipe failed: " << platform::windows::TranslateLastError();
        return false;
    }
    
    logt.info() << "Named pipe created successfully: " << PIPE_NAME;
    
    // 同步连接，带超时检测
    BOOL connected = ConnectNamedPipe(pipe_, nullptr);
    if (!connected) {
        DWORD error = GetLastError();
        if (error == ERROR_PIPE_CONNECTED) {
            logt.info() << "Client already connected";
            return true;
        } else {
            logt.error() << "ConnectNamedPipe failed: " << platform::windows::TranslateError(error);
            CloseHandle(pipe_);
            pipe_ = INVALID_HANDLE_VALUE;
            return false;
        }
    }
    
    return true;
}

std::wstring PipeServer::ReadRequest() {
    wchar_t buffer[BUFFER_SIZE];
    DWORD bytesRead;
    
    if (!ReadFile(pipe_, buffer, BUFFER_SIZE * sizeof(wchar_t), &bytesRead, nullptr)) {
        logt.error() << "ReadFile failed: " << platform::windows::TranslateLastError();
        return L"";
    }
    
    return std::wstring(buffer, bytesRead / sizeof(wchar_t));
}

bool PipeServer::SendResponse(const std::wstring& response) {
    DWORD bytesWritten;
    if (!WriteFile(pipe_, response.c_str(), DWORD((response.size() + 1) * sizeof(wchar_t)), &bytesWritten, nullptr)) {
        logt.error() << "WriteFile failed: " << platform::windows::TranslateLastError();
        return false;
    }
    return true;
}

HANDLE PipeServer::GetPipeHandle() const {
    return pipe_;
}