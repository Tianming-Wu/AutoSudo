#pragma once
#include <string>
#include <vector>
#include <windows.h>

#define PIPE_NAME L"\\\\.\\pipe\\AutoSudoPipe"
#define BUFFER_SIZE 4096

enum class AuthLevel {
    NotFound = -4,          // 不在允许列表中
    InsufficientLevel = -3, // 允许级别不足
    HashMismatch = -2,      // 文件哈希不匹配
    Invalid = -1,           // 无效的权限级别码

    User = 0,
    Admin = 1,
    System = 2
};

struct ProcessContext {
    std::wstring commandLine;
    std::wstring workingDirectory;
    std::wstring calledPath;  //客户端调用路径
    std::vector<std::wstring> environmentVariables;

    DWORD sessionId = 0;  //目标会话ID
    bool useCurrentSession = true;  //是否使用当前会话

    AuthLevel requestedAuthLevel = AuthLevel::Admin;

    std::wstring Serialize() const;
    static ProcessContext Deserialize(const std::wstring& data);
};