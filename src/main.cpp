#include <windows.h>
#include <iostream>
#include <string>

#include <wtsapi32.h>

#include "pipeclient.hpp"
#include "installer.hpp"

#include <SharedCppLib2/logt.hpp>

std::wstring ResolveExecutablePath(const std::wstring& commandLine) {
    // 首先检查是否已经是完整路径（带引号）
    if (commandLine.length() >= 2 && commandLine[0] == L'\"' && commandLine.back() == L'\"') {
        std::wstring quotedPath = commandLine.substr(1, commandLine.length() - 2);
        
        // 检查这个带引号的路径是否存在
        DWORD attr = GetFileAttributes(quotedPath.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
            return quotedPath;
        }
    }
    
    // 然后检查是否已经是完整路径（不带引号）
    DWORD attr = GetFileAttributes(commandLine.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        return commandLine;
    }
    
    // 如果不是完整路径，尝试提取可执行文件名
    std::wstring exeName = commandLine;
    size_t spacePos = commandLine.find(L' ');
    if (spacePos != std::wstring::npos) {
        exeName = commandLine.substr(0, spacePos);
        
        // 检查提取的部分是否已经是路径
        attr = GetFileAttributes(exeName.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
            return exeName;
        }
    }
    
    // 使用 SearchPath 在系统路径中查找
    wchar_t fullPath[MAX_PATH];
    DWORD result = SearchPath(
        nullptr,
        exeName.c_str(),
        L".exe",
        MAX_PATH,
        fullPath,
        nullptr
    );
    
    if (result > 0 && result < MAX_PATH) {
        return std::wstring(fullPath);
    }
    
    return L""; // 未找到
}

int ExecuteCommand(const std::wstring& commandLine, AuthLevel authLevel = AuthLevel::Admin) {
    LOGT_LOCAL("ExecuteCommand");
    // 构建进程上下文
    ProcessContext context;

    std::wstring resolvedPath = ResolveExecutablePath(commandLine);
    if (resolvedPath.empty()) {
        logt.error() << "Cannot resolve executable path for: " << commandLine;
        return 1;
    }
    context.commandLine = resolvedPath;

    // 获取当前工作目录
    wchar_t currentDir[MAX_PATH];
    GetCurrentDirectory(MAX_PATH, currentDir);
    context.workingDirectory = currentDir;

    context.calledPath = currentDir;

    // 设置认证级别
    context.requestedAuthLevel = authLevel;
    
    // 获取当前会话ID
    context.sessionId = ::WTSGetActiveConsoleSessionId();
    context.useCurrentSession = true;

    // 连接服务并发送请求
    PipeClient client;
    if (client.Connect()) {
        std::wstring request = context.Serialize();
        if (client.SendRequest(request)) {
            std::wstring response = client.ReadResponse();
            logt.info() << "Server response: " << response;
            return 0;
        }
    }
    
    logt.error() << "Failed to execute command";
    return 1;
}

int wmain(int argc, wchar_t** argv) {
    // 初始化日志
    logt::claim("AutoSudo");
    logt::file(platform::executable_dir()/"autosudo.log");
    
    int result = 0;
    
    if (argc < 2) {
        // ShowUsage();
        result = 1;
    } else {
        AuthLevel authLevel = AuthLevel::Admin; // 默认管理员权限
        int commandStartIndex = 1; // 命令起始位置
        bool exec = true;
        
        std::wstring firstArg = argv[1];
        if (firstArg == L"--user") {
            authLevel = AuthLevel::User;
            commandStartIndex = 2;
        } else if (firstArg == L"--system") {
            authLevel = AuthLevel::System;
            commandStartIndex = 2;
        } else if (firstArg == L"--admin") {
            authLevel = AuthLevel::Admin;
            commandStartIndex = 2;
        } else if (firstArg == L"--help") {
            // ShowUsage();
            logt::shutdown();
            return 0;
        } else if (firstArg == L"--install") {
            result = svc::InstallService() ? 0 : 1;
            commandStartIndex = 2;
            exec = false;
        } else if (firstArg == L"--uninstall") {
            result = svc::UninstallService() ? 0 : 1;
            commandStartIndex = 2;
            exec = false;
        } else if (firstArg == L"--start") {
            result = svc::_StartService() ? 0 : 1;
            commandStartIndex = 2;
            exec = false;
        } else if (firstArg == L"--stop") {
            result = svc::_StopService() ? 0 : 1;
            commandStartIndex = 2;
            exec = false;
        }

        // 执行命令模式
        if(exec) {
            if (commandStartIndex >= argc) {
                if (commandStartIndex == 2) { // 有权限参数但没有命令
                    std::wcout << L"Error: No command specified after permission flag" << std::endl;
                    result = 1;
                } else {
                    result = 1;
                }
            } else {
                // 构建命令行
                std::wstring commandLine;
                for (int i = commandStartIndex; i < argc; ++i) {
                    if (i > commandStartIndex) commandLine += L" ";
                    // 处理参数中的空格
                    if (std::wstring(argv[i]).find(L' ') != std::wstring::npos) {
                        commandLine += L"\"" + std::wstring(argv[i]) + L"\"";
                    } else {
                        commandLine += argv[i];
                    }
                }
                
                // 执行命令
                result = ExecuteCommand(commandLine, authLevel);
            }
        }
    }
    
    // 关闭日志
    logt::shutdown();
    return result;
}