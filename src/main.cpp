#include <windows.h>
#include <iostream>
#include <string>

#include <wtsapi32.h>

#include "pipeclient.hpp"
#include "installer.hpp"

#include <SharedCppLib2/logt.hpp>
#include <SharedCppLib2/stringlist.hpp>

#ifdef AUTOSUDO_GUI
    #pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

std::wstring ResolveExecutablePath(const std::wstring& commandLine) {
    // 由于在上一步已经确保不包含引号所以不做处理
    // // 首先检查是否已经是完整路径（带引号）
    // if (commandLine.length() >= 2 && commandLine[0] == L'\"' && commandLine.back() == L'\"') {
    //     std::wstring quotedPath = commandLine.substr(1, commandLine.length() - 2);
        
    //     // 检查这个带引号的路径是否存在
    //     DWORD attr = GetFileAttributes(quotedPath.c_str());
    //     if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
    //         return quotedPath;
    //     }
    // }
    
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

    std::wstringlist args = std::wstringlist::xsplit(commandLine, L" ", L"\"'");

    if (args.empty()) { return 1; }

    std::wstring resolvedPath = ResolveExecutablePath(args[0]);
    if (resolvedPath.empty()) {
        logt.error() << "Cannot resolve executable path for: " << commandLine;
        return 1;
    }

    context.program = resolvedPath;
    context.arguments = args.subarr(1);

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

#ifdef AUTOSUDO_GUI
// GUI版本使用 wWinMain
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    int argc;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
#else
// 命令行版本使用 wmain  
int wmain(int argc, wchar_t** argv) {
#endif

    // 初始化日志
    logt::claim("AutoSudo");
    logt::file(platform::executable_dir()/"autosudo.log");

    ///TODO: 为GUI版本关闭命令行日志输出
    
    int result = 0;
    
    if (argc < 2) {
#ifdef AUTOSUDO_GUI
        MessageBox(nullptr, 
                  L"用法: AutoSudoW [权限选项] <命令>\n\n"
                  L"权限选项:\n"
                  L"  --user    用户权限\n"  
                  L"  --admin   管理员权限 (默认)\n"
                  L"  --system  SYSTEM权限\n\n"
                  L"示例:\n"
                  L"  AutoSudoW notepad\n"
                  L"  AutoSudoW --user cmd",
                  L"AutoSudoW - 帮助", 
                  MB_OK | MB_ICONINFORMATION);
#else
        std::wcout << L"用法: AutoSudo [权限选项] <命令>" << std::endl;
        std::wcout << L"权限选项:" << std::endl;
        std::wcout << L"  --user    用户权限" << std::endl;
        std::wcout << L"  --admin   管理员权限 (默认)" << std::endl;
        std::wcout << L"  --system  SYSTEM权限" << std::endl;
        std::wcout << L"示例:" << std::endl;
        std::wcout << L"  AutoSudo notepad" << std::endl;
        std::wcout << L"  AutoSudo --user cmd" << std::endl;
#endif
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

#ifdef AUTOSUDO_GUI
    LocalFree(argv);
#endif
    
    // 清理并退出
    logt::shutdown();
    return result;
}