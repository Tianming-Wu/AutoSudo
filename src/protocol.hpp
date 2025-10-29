#pragma once
#include <string>
#include <vector>
#include <windows.h>

#define PIPE_NAME L"\\\\.\\pipe\\AutoSudoPipe"
#define BUFFER_SIZE 4096

struct ProcessContext {
    std::wstring commandLine;
    std::wstring workingDirectory;
    std::vector<std::wstring> environmentVariables;

    DWORD sessionId = 0;  // 新增：目标会话ID
    bool useCurrentSession = true;  // 新增：是否使用当前会话

    std::wstring Serialize() const;
    static ProcessContext Deserialize(const std::wstring& data);
};