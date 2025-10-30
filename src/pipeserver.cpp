#include "pipeserver.hpp"
#include <accctrl.h>
#include <aclapi.h>

LOGT_DEFINE(PipeServer, "PipeServer");

PipeServer::PipeServer() : pipe_(INVALID_HANDLE_VALUE) {}

PipeServer::~PipeServer() {
    if (pipe_ != INVALID_HANDLE_VALUE) {
        CloseHandle(pipe_);
    }
}

PSECURITY_DESCRIPTOR CreatePipeSecurity() {
    // 创建安全描述符，允许所有用户访问
    PSECURITY_DESCRIPTOR sd = nullptr;
    EXPLICIT_ACCESS ea[1];
    PACL acl = nullptr;
    
    // 设置所有用户都有读写访问权限
    ZeroMemory(&ea, sizeof(ea));
    ea[0].grfAccessPermissions = GENERIC_READ | GENERIC_WRITE;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName = (LPTSTR)L"Everyone";  // 允许所有用户
    
    // 创建安全描述符
    if (SetEntriesInAcl(1, ea, nullptr, &acl) == ERROR_SUCCESS) {
        sd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
        if (sd) {
            if (InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION) &&
                SetSecurityDescriptorDacl(sd, TRUE, acl, FALSE)) {
                // 成功创建安全描述符
                return sd;
            }
            LocalFree(sd);
        }
        LocalFree(acl);
    }
    
    return nullptr;
}

// bool PipeServer::Start() {
//     // 创建命名管道
//     pipe_ = CreateNamedPipe(
//         PIPE_NAME,                      // 管道名称
//         PIPE_ACCESS_DUPLEX,             // 双向通信
//         PIPE_TYPE_MESSAGE |             // 消息模式
//         PIPE_READMODE_MESSAGE |        // 消息读取模式
//         PIPE_WAIT,                      // 阻塞模式
//         PIPE_UNLIMITED_INSTANCES,       // 最大实例数
//         BUFFER_SIZE,                    // 输出缓冲区大小
//         BUFFER_SIZE,                    // 输入缓冲区大小
//         0,                              // 默认超时
//         nullptr                         // 默认安全属性
//     );
    
//     if (pipe_ == INVALID_HANDLE_VALUE) {
//         logt.error() << "CreateNamedPipe failed: " << platform::windows::TranslateLastError();
//         return false;
//     }
    
//     logt.info() << "Named pipe server started. Waiting for client...";
    
//     // 等待客户端连接
//     if (!ConnectNamedPipe(pipe_, nullptr) && GetLastError() != ERROR_PIPE_CONNECTED) {
//         logt.error() << "ConnectNamedPipe failed: " << platform::windows::TranslateLastError();
//         return false;
//     }
    
//     logt.info() << "Client connected.";
//     return true;
// }

bool PipeServer::StartNonBlocking() {
    PSECURITY_DESCRIPTOR sd = CreatePipeSecurity();
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;

    pipe_ = CreateNamedPipe(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        BUFFER_SIZE,
        BUFFER_SIZE,
        NMPWAIT_USE_DEFAULT_WAIT,
        sd ? &sa : nullptr  // 使用安全属性
    );

    if (sd) {
        LocalFree(sd);
    }
    
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