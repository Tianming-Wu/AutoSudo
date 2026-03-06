#pragma once
#include <string>
#include <vector>
#include <SharedCppLib2/platform_windows.hpp>
#include <SharedCppLib2/stringlist.hpp>

// These macros are no longer used, now the ones in libpipe are used.
// #define AUTOSUDO_PIPE_NAME R"(\\.\pipe\AutoSudoPipe)"
// #define BUFFER_SIZE 4096

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
    std::wstring program;
    std::wstringlist arguments;
    std::wstring workingDirectory;
    std::wstring calledPath;  //客户端调用路径

    DWORD sessionId = 0;  //目标会话ID
    bool useCurrentSession = true;  //是否使用当前会话
    bool deleteAuth = false;  //是否删除授权

    AuthLevel requestedAuthLevel = AuthLevel::Admin;

    bool inheritConsole = false; // 是否继承控制台
    int ConsoleX, ConsoleY; // 控制台参数，用于 ConPTY

    // Dynamic member
    std::vector<std::wstring> environmentVariables;

    std::wstring Serialize() const;
    static ProcessContext Deserialize(const std::wstring& data);
};