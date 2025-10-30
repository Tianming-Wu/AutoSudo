#include <windows.h>
#include <iostream>
#include <string>

#include <wtsapi32.h>

#include "pipeclient.hpp"
#include "installer.hpp"

#include <SharedCppLib2/logt.hpp>

std::wstring ResolveExeutionPath(const std::wstring &commandLine) {
    std::wstring exeName = commandLine;
    size_t spacePos = commandLine.find(L' ');
    if (spacePos != std::wstring::npos) {
        exeName = commandLine.substr(0, spacePos);
    }
    
    // 移除可能的引号
    if (!exeName.empty() && exeName[0] == L'\"' && exeName.back() == L'\"') {
        exeName = exeName.substr(1, exeName.length() - 2);
    }
    
    wchar_t fullPath[MAX_PATH];
    DWORD result = SearchPath(
        nullptr,           // 使用系统搜索路径
        exeName.c_str(),   // 文件名
        L".exe",           // 扩展名（可选）
        MAX_PATH,          // 缓冲区大小
        fullPath,          // 输出完整路径
        nullptr            // 文件部分指针（不需要）
    );
    
    if (result > 0 && result < MAX_PATH) {
        return std::wstring(fullPath);
    }
    
    // 如果SearchPath失败，尝试直接作为路径访问
    DWORD attr = GetFileAttributes(exeName.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        return exeName; // 已经是完整路径或相对路径
    }
    
    return L""; // 未找到
}

int ExecuteCommand(const std::wstring& commandLine, AuthLevel authLevel = AuthLevel::Admin) {
    LOGT_LOCAL("ExecuteCommand");
    // 构建进程上下文
    ProcessContext context;

    std::wstring resolvedPath = ResolveExeutionPath(commandLine);
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
    logt::file("autosudo.log");
    
    int result = 0;
    
    if (argc < 2) {
        // ShowUsage();
        result = 1;
    } else {
        AuthLevel authLevel = AuthLevel::Admin; // 默认管理员权限
        int commandStartIndex = 1; // 命令起始位置
        bool exec = false;
        
        std::wstring firstArg = argv[1];
        if (firstArg == L"--user") {
            authLevel = AuthLevel::User;
            commandStartIndex = 2;
            exec = true;
        } else if (firstArg == L"--system") {
            exec = true;
            authLevel = AuthLevel::System;
            commandStartIndex = 2;
        } else if (firstArg == L"--admin") {
            exec = true;
            authLevel = AuthLevel::Admin;
            commandStartIndex = 2;
        } else if (firstArg == L"--help") {
            // ShowUsage();
            logt::shutdown();
            return 0;
        } else if (firstArg == L"--install") {
            result = svc::InstallService() ? 0 : 1;
            commandStartIndex = 2;
        } else if (firstArg == L"--uninstall") {
            result = svc::UninstallService() ? 0 : 1;
            commandStartIndex = 2;
        } else if (firstArg == L"--start") {
            result = svc::_StartService() ? 0 : 1;
            commandStartIndex = 2;
        } else if (firstArg == L"--stop") {
            result = svc::_StopService() ? 0 : 1;
            commandStartIndex = 2;
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