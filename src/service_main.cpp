#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <userenv.h>
#include <wtsapi32.h>

#include "protocol.hpp"
#include "pipeserver.hpp"
// #include "authlib.hpp"

#include <SharedCppLib2/platform.hpp>

SERVICE_STATUS serviceStatus = {0};
SERVICE_STATUS_HANDLE serviceStatusHandle = nullptr;
HANDLE serviceStopEvent = nullptr;

HANDLE pipeThread = nullptr;
bool shouldStopPipeThread = false;

VOID WINAPI ServiceCtrlHandler(DWORD controlCode) {
    LOGT_LOCAL("ServiceCtrlHandler");
    switch (controlCode) {
        case SERVICE_CONTROL_STOP:
            logt.info() << "Service stopping...";
            serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            serviceStatus.dwWaitHint = 10000; // 10秒超时
            serviceStatus.dwCheckPoint = 1;

            SetServiceStatus(serviceStatusHandle, &serviceStatus);

            shouldStopPipeThread = true;
            if (serviceStopEvent) {
                SetEvent(serviceStopEvent);
            }

            if (pipeThread) {
                WaitForSingleObject(pipeThread, 5000); // 最多等5秒
                CloseHandle(pipeThread);
                pipeThread = nullptr;
            }

            return;
            
        case SERVICE_CONTROL_INTERROGATE:
            break;
            
        default:
            break;
    }
    
    SetServiceStatus(serviceStatusHandle, &serviceStatus);
}

void UpdateServiceStatus(DWORD state, DWORD checkpoint = 0, DWORD waitHint = 0) {
    if (serviceStatusHandle) {
        serviceStatus.dwCurrentState = state;
        serviceStatus.dwCheckPoint = checkpoint;
        serviceStatus.dwWaitHint = waitHint;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);
    }
}

bool CreateProcessWithContext(const ProcessContext& context) {
    LOGT_LOCAL("CreateProcessWithContext");
    // 准备环境块
    LPVOID envBlock = nullptr;
    if (!context.environmentVariables.empty()) {
        std::wstring envStr;
        for (const auto& env : context.environmentVariables) {
            envStr += env + L'\0';
        }
        envStr += L'\0';
        envBlock = (LPVOID)envStr.c_str();
    }
    
    STARTUPINFO si = {0};
    si.cb = sizeof(STARTUPINFO);
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    
    PROCESS_INFORMATION pi = {0};
    
    if (!CreateProcess(
        nullptr,
        const_cast<LPWSTR>(context.commandLine.c_str()),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
        envBlock,
        context.workingDirectory.empty() ? nullptr : context.workingDirectory.c_str(),
        &si,
        &pi
    )) {
        logt.error() << "CreateProcess failed: " << platform::windows::TranslateLastError();
        return false;
    }
    
    logt.info() << "Process created successfully: " << context.commandLine;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

bool CreateProcessInUserSession(const ProcessContext& context) {
    LOGT_LOCAL("CreateProcessInUserSession");
    DWORD targetSessionId = context.sessionId;
    
    // 如果useCurrentSession为false或者sessionId无效，使用默认逻辑
    if (!context.useCurrentSession || targetSessionId == 0xFFFFFFFF) {
        logt.info() << "Using default session handling";
        return CreateProcessWithContext(context); // 回退到原来的方法
    }
    
    logt.info() << "Creating process in session: " << targetSessionId;

    // 缓存当前工作目录
    wchar_t originalDir[MAX_PATH];
    GetCurrentDirectory(MAX_PATH, originalDir);
    
    // 切换到客户端调用目录（如果存在）
    bool directoryChanged = false;
    if (!context.calledPath.empty()) {
        if (SetCurrentDirectory(context.calledPath.c_str())) {
            logt.info() << "Changed working directory to: " << context.calledPath;
            directoryChanged = true;
        } else {
            logt.warn() << "Failed to change working directory to: " << context.calledPath;
        }
    }

    // 获取SYSTEM账户的令牌
    HANDLE systemToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &systemToken)) {
        logt.error() << "OpenProcessToken failed: " << platform::windows::TranslateLastError();
        return false;
    }

    // 复制令牌以便在不同会话中使用
    HANDLE duplicatedToken = nullptr;
    if (!DuplicateTokenEx(systemToken, TOKEN_ALL_ACCESS, nullptr, 
                         SecurityImpersonation, TokenPrimary, &duplicatedToken)) {
        logt.error() << "DuplicateTokenEx failed: " << platform::windows::TranslateLastError();
        CloseHandle(systemToken);
        return false;
    }

    CloseHandle(systemToken);

    // 设置令牌到目标会话
    if (!SetTokenInformation(duplicatedToken, TokenSessionId, &targetSessionId, sizeof(DWORD))) {
        logt.error() << "SetTokenInformation failed: " << platform::windows::TranslateLastError();
        CloseHandle(duplicatedToken);
        return false;
    }
    
    HANDLE userToken = nullptr;
    LPVOID envBlock = nullptr;

    if (WTSQueryUserToken(targetSessionId, &userToken)) {
        // 成功获取用户令牌，使用用户的环境
        if (!CreateEnvironmentBlock(&envBlock, userToken, FALSE)) {
            logt.warn() << "CreateEnvironmentBlock for user failed: " << platform::windows::TranslateLastError();
            envBlock = nullptr;
        }
        CloseHandle(userToken);
    } else {
        logt.warn() << "WTSQueryUserToken failed, using default environment: " << platform::windows::TranslateLastError();
    }
    
    // 如果无法获取用户环境，使用进程的默认环境
    if (!envBlock) {
        logt.info() << "Using process default environment";
    }
    
    STARTUPINFO si = {0};
    si.cb = sizeof(STARTUPINFO);
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    
    PROCESS_INFORMATION pi = {0};
    
    BOOL success = CreateProcessAsUser(
        duplicatedToken,
        nullptr,
        const_cast<LPWSTR>(context.commandLine.c_str()),
        nullptr,
        nullptr,
        FALSE,
        CREATE_UNICODE_ENVIRONMENT,
        envBlock,
        context.workingDirectory.empty() ? nullptr : context.workingDirectory.c_str(),
        &si,
        &pi
    );
    
    if (!success) {
        DWORD error = GetLastError();
        logt.error() << "CreateProcessAsUser failed: " << platform::windows::TranslateError(error);
        
        // 尝试回退到没有用户环境的方式
        if (envBlock && (error == ERROR_INVALID_PARAMETER || error == ERROR_BAD_ENVIRONMENT)) {
            logt.info() << "Retrying without user environment block...";
            success = CreateProcessAsUser(
                duplicatedToken,
                nullptr,
                const_cast<LPWSTR>(context.commandLine.c_str()),
                nullptr,
                nullptr,
                FALSE,
                CREATE_NEW_CONSOLE,
                nullptr,
                context.workingDirectory.empty() ? nullptr : context.workingDirectory.c_str(),
                &si,
                &pi
            );
            
            if (success) {
                logt.info() << "Process created successfully without user environment";
            } else {
                logt.error() << "Retry also failed: " << platform::windows::TranslateLastError();
            }
        }
    } else {
        logt.info() << "Process created successfully in user session with SYSTEM privileges, PID: " << pi.dwProcessId;
    }
    
    if (success) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    // 清理
    if (envBlock) {
        DestroyEnvironmentBlock(envBlock);
    }
    CloseHandle(duplicatedToken);

    // 恢复原始工作目录
    if (directoryChanged) {
        SetCurrentDirectory(originalDir);
    }
    
    return success;
}

bool ProcessClientRequest(PipeServer& server) {
    LOGT_LOCAL("ProcessClientRequest");

    // 读取请求
    std::wstring requestData = server.ReadRequest();
    if (requestData.empty()) {
        logt.error() << "Failed to read request from client or empty request";
        return false;
    }
    
    // 反序列化上下文
    ProcessContext context = ProcessContext::Deserialize(requestData);
    logt.info() << "Received command: " << context.commandLine;
    
    // 根据上下文决定创建方式
    bool success = false;
    if (context.useCurrentSession && context.sessionId != 0xFFFFFFFF) {
        success = CreateProcessInUserSession(context);
    } else {
        success = CreateProcessWithContext(context);
    }
    
    // 发送响应
    if (success) {
        server.SendResponse(L"SUCCESS: Process created");
    } else {
        server.SendResponse(L"ERROR: Failed to create process");
    }
    
    return true;
}

DWORD WINAPI PipeListenerThread(LPVOID param) {
    logt::claim("PipeListenerThread");
    LOGT_LOCAL("PipeListenerThread");
    logt.info() << "Pipe listener thread started";
    
    while (!shouldStopPipeThread) {
        PipeServer server;
        
        // 这个调用会阻塞，但我们可以通过外部事件来中断
        if (server.StartNonBlocking()) {
            logt.info() << "Client connected, processing request...";
            
            // 处理客户端请求
            ProcessClientRequest(server);
            
            // 断开连接
            DisconnectNamedPipe(server.GetPipeHandle());
            logt.info() << "Client disconnected";
        } else {
            // 正常的非客户端连接状态，短暂休息
            Sleep(100);
        }
        
        // 检查停止标志
        if (shouldStopPipeThread) {
            break;
        }
    }
    
    logt.info() << "Pipe listener thread exiting";
    return 0;
}

void MainServiceLoop() {
    LOGT_LOCAL("MainServiceLoop");
    logt.info() << "Service main loop started";

    UpdateServiceStatus(SERVICE_RUNNING);

    shouldStopPipeThread = false;
    pipeThread = CreateThread(nullptr, 0, PipeListenerThread, nullptr, 0, nullptr);
    if (!pipeThread) {
        logt.error() << "Failed to create pipe listener thread";
        return;
    }
    
    WaitForSingleObject(serviceStopEvent, INFINITE);

    shouldStopPipeThread = true;
    
    // 等待管道线程退出
    if (pipeThread) {
        logt.info() << "Waiting for pipe thread to finish...";
        WaitForSingleObject(pipeThread, 5000);
        CloseHandle(pipeThread);
        pipeThread = nullptr;
    }
    
    logt.info() << "Service main loop ended";
}


VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    LOGT_LOCAL("ServiceMain");

    logt::file(platform::executable_dir()/"autosudo_service.log");
    logt::claim("ServiceMain");

    serviceStatusHandle = RegisterServiceCtrlHandler(L"AutoSudoService", ServiceCtrlHandler);
    
    if (!serviceStatusHandle) {
        logt.error() << "RegisterServiceCtrlHandler failed";
        return;
    }
    
    // 初始化服务状态
    serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    serviceStatus.dwCurrentState = SERVICE_START_PENDING;
    serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    serviceStatus.dwWin32ExitCode = NO_ERROR;
    serviceStatus.dwServiceSpecificExitCode = 0;
    serviceStatus.dwCheckPoint = 0;
    serviceStatus.dwWaitHint = 3000; // 3秒
    
    SetServiceStatus(serviceStatusHandle, &serviceStatus);
    
    // 创建停止事件
    serviceStopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!serviceStopEvent) {
        logt.error() << "CreateEvent failed";
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);
        logt::shutdown();
        return;
    }
    
    // 服务运行中
    serviceStatus.dwCurrentState = SERVICE_RUNNING;
    serviceStatus.dwCheckPoint = 0;
    serviceStatus.dwWaitHint = 0;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);
    
    logt.info() << "Service started successfully";
    
    // 主服务循环
    MainServiceLoop();
    
    // 清理
    CloseHandle(serviceStopEvent);
    serviceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);
    
    logt.info() << "Service stopped";
    logt::shutdown();
}


int wmain(int argc, wchar_t** argv) {
    LOGT_LOCAL("wmain");

    logt::claim("ServiceMain");
    // 如果是控制台模式运行（调试用）
    if (argc > 1 && std::wstring(argv[1]) == L"--debug") {
        logt::file("autosudo_service_debug.log");

        logt::setFilterLevel(LogLevel::l_DEBUG);

        logt.info() << "Running in debug mode";
        
        serviceStopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        MainServiceLoop();
        CloseHandle(serviceStopEvent);
        
        logt::shutdown();
        return 0;
    } else {
        logt::file("autosudo_service.log");
        
        // 服务模式
        wchar_t serviceName[] = L"AutoSudoService";
        SERVICE_TABLE_ENTRY serviceTable[] = {
            { serviceName, ServiceMain },
            { nullptr, nullptr }
        };
    
        if (!StartServiceCtrlDispatcher(serviceTable)) {
            logt::claim("AutoSudoService");
            logt::file("autosudo_service_error.log");
            logt.error() << "StartServiceCtrlDispatcher failed: " << platform::windows::TranslateLastError();

            logt::shutdown();
            return 1;
        }
    }
}