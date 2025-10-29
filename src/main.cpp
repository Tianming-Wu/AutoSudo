#include <windows.h>
#include <iostream>
#include <string>

#include <wtsapi32.h>

#include "pipeclient.hpp"
#include "installer.hpp"

#include <SharedCppLib2/logt.hpp>

int ExecuteCommand(const std::wstring& commandLine) {
    LOGT_LOCAL("ExecuteCommand");
    // 构建进程上下文
    ProcessContext context;
    context.commandLine = commandLine;
    
    // 获取当前工作目录
    wchar_t currentDir[MAX_PATH];
    GetCurrentDirectory(MAX_PATH, currentDir);
    context.workingDirectory = currentDir;
    
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
        std::wstring command = argv[1];
        
        if (command == L"--install") {
            result = svc::InstallService() ? 0 : 1;
        } else if (command == L"--uninstall") {
            result = svc::UninstallService() ? 0 : 1;
        } else if (command == L"--start") {
            result = svc::_StartService() ? 0 : 1;
        } else if (command == L"--stop") {
            result = svc::_StopService() ? 0 : 1;
        } else if (command == L"--help") {
            result = 0;
        } else {
            // 执行命令模式
            std::wstring commandLine;
            for (int i = 1; i < argc; ++i) {
                if (i > 1) commandLine += L" ";
                // 处理参数中的空格
                if (std::wstring(argv[i]).find(L' ') != std::wstring::npos) {
                    commandLine += L"\"" + std::wstring(argv[i]) + L"\"";
                } else {
                    commandLine += argv[i];
                }
            }
            result = ExecuteCommand(commandLine);
        }
    }
    
    // 关闭日志
    logt::shutdown();
    return result;
}