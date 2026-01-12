#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <userenv.h>
#include <wtsapi32.h>
#include <functional>

#include "protocol.hpp"
#include "pipeserver.hpp"
#include "auth.hpp"
#include "token.hpp"
// #include "authlib.hpp"

#include "auth_ui.hpp"

#include <SharedCppLib2/platform.hpp>

#define USERAUTH_WAIT_TIMEOUT 10000

SERVICE_STATUS serviceStatus = {0};
SERVICE_STATUS_HANDLE serviceStatusHandle = nullptr;
HANDLE serviceStopEvent = nullptr;

HANDLE pipeThread = nullptr;
bool shouldStopPipeThread = false;
wchar_t originalDir[MAX_PATH] = {0};
inline void dirBack() { SetCurrentDirectory(originalDir); }

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

int RequestUserConfirmation(const ProcessContext& context, AuthUIType type) {
    LOGT_LOCAL("RequestUserConfirmation");

    // static const wchar_t* typeStr[] = {L"NOTFOUND", L"INSUFFICIENTLEVEL", L"HASHMISMATCH"};
    static const wchar_t* levelStr[] = {L"USER", L"ADMIN", L"SYSTEM"};
    
    // 构建确认对话框命令行
    std::wstring commandLine = (platform::executable_dir() / L"AuthUI.exe").wstring()
        + L" " + AuthUITypeStr[static_cast<int>(type)]
        + L" " + levelStr[static_cast<int>(context.requestedAuthLevel)]
        + L" \"" + context.program + L"\"";

    logt.debug() << "Auth command: " << commandLine;
    
    HANDLE userToken = token::getUserToken(context);
    if(userToken == nullptr) {
        logt.error() << "Failed to get user token.";
        return static_cast<int>(AuthUIResult::Deny);
    }

    DWORD targetSessionId = context.sessionId;
    if (!SetTokenInformation(userToken, TokenSessionId, &targetSessionId, sizeof(DWORD))) {
        logt.error() << "SetTokenInformation failed: " << platform::windows::TranslateLastError();
        CloseHandle(userToken);
        return static_cast<int>(AuthUIResult::Deny);
    }
    
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(STARTUPINFO);
    
    BOOL success = CreateProcessAsUser(userToken, nullptr, const_cast<LPWSTR>(commandLine.c_str()), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi);
    
    if (!success) {
        logt.error() << "Failed to launch confirmation UI";
        CloseHandle(userToken);
        return static_cast<int>(AuthUIResult::Deny);
    }
    
    // 等待用户响应
    DWORD waitResult = WaitForSingleObject(pi.hProcess, USERAUTH_WAIT_TIMEOUT); // 10秒超时
    if (waitResult == WAIT_TIMEOUT) {
        logt.warn() << "Confirmation UI timeout, terminating...";
        TerminateProcess(pi.hProcess, 1); // 超时视为拒绝
    }
    
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(userToken);
    
    logt.info() << "User confirmation result: " << exitCode;
    return static_cast<int>(exitCode);
}

std::wstring MakeFullCommandLine(const ProcessContext& context) {
    std::wstringlist args = context.arguments;
    args.insert(args.begin(), context.program);
    return args.xjoin();
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

    std::wstring fullCommandLine = MakeFullCommandLine(context);
    
    if (!CreateProcess(
        nullptr,
        const_cast<LPWSTR>(fullCommandLine.c_str()),
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

    logt.info() << "Process created successfully: " << fullCommandLine;
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
    
    if (!context.calledPath.empty()) {
        if (SetCurrentDirectory(context.calledPath.c_str())) {
            logt.info() << "Changed working directory to: " << context.calledPath;
        } else {
            logt.warn() << "Failed to change working directory to: " << context.calledPath;
        }
    }

    AuthLevel authResult = auth::authlist.test(context.program, context.requestedAuthLevel);

    // 如果设置了 deleteAuth 标志，询问用户是否删除授权
    if (context.deleteAuth) {
        int authUIResult = RequestUserConfirmation(context, AuthUIType::ConfirmDeletion);
        if (authUIResult == static_cast<int>(AuthUIResult::Delete)) {
            // 用户选择删除
            logt.info() << "User confirmed deletion of: " << context.program;
            auth::authlist.remove(context.program);
            dirBack();
            return true;  // 删除授权后返回true，不执行程序
        } else if (authUIResult == static_cast<int>(AuthUIResult::Deny)) {
            // 用户选择取消
            logt.info() << "User cancelled deletion operation";
            dirBack();
            return false;
        }
        // authUIResult == AuthUIResult::Allow 时继续执行授权检查
    }

    switch(authResult) {
        case AuthLevel::Invalid:
            logt.error() << "Invalid requested permission level, ignoring.";
            dirBack();
            return false;
        case AuthLevel::NotFound:
            if (RequestUserConfirmation(context, AuthUIType::ConfirmNew) != static_cast<int>(AuthUIResult::Allow)) {
                dirBack();
                return false;
            }
            auth::authlist.insert(context.program, context.requestedAuthLevel);
            break;
        case AuthLevel::InsufficientLevel:
            if (RequestUserConfirmation(context, AuthUIType::ConfirmRaise) != static_cast<int>(AuthUIResult::Allow)) {
                dirBack();
                return false;
            }
            // 用户确认，更新权限级别
            auth::authlist.insert(context.program, context.requestedAuthLevel);
            break;
        case AuthLevel::HashMismatch:
            if (RequestUserConfirmation(context, AuthUIType::ConfirmHashRebuild) != static_cast<int>(AuthUIResult::Allow)) {
                dirBack();
                return false;
            }
            // 用户确认，重新添加程序
            auth::authlist.remove(context.program);
            auth::authlist.insert(context.program, context.requestedAuthLevel);
            break;
        default:
            break;
    }

    AuthLevel finalLevel = (static_cast<int>(authResult) >= 0) ? authResult : context.requestedAuthLevel;

    HANDLE targetToken = nullptr;

    switch(finalLevel) {
    case AuthLevel::User:
        targetToken = token::getUserToken(context); break;
    case AuthLevel::Admin:
        targetToken = token::getAdminToken(context); break;
    case AuthLevel::System:
        targetToken = token::getSystemToken(context); break;
    default:
        targetToken = nullptr;
    }

    if(targetToken == nullptr) {
        // 获取令牌失败，退出
        // 日志已经在获取函数中输出，不再重复
        dirBack();
        return false;
    }

    // 设置令牌到目标会话
    if (!SetTokenInformation(targetToken, TokenSessionId, &targetSessionId, sizeof(DWORD))) {
        logt.error() << "SetTokenInformation failed: " << platform::windows::TranslateLastError();
        CloseHandle(targetToken);
        dirBack();
        return false;
    }
    
    HANDLE userToken = nullptr;
    LPVOID envBlock = nullptr;

    // 使用用户的环境块
    if (WTSQueryUserToken(targetSessionId, &userToken)) {
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

    std::wstring fullCommandLine = MakeFullCommandLine(context);
    
    BOOL success = CreateProcessAsUser(
        targetToken,
        nullptr,
        const_cast<LPWSTR>(fullCommandLine.c_str()),
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
                targetToken,
                nullptr,
                const_cast<LPWSTR>(fullCommandLine.c_str()),
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
        logt.info() << "Process created successfully in user session, PID: " << pi.dwProcessId;
    }
    
    if (success) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    // 清理
    if (envBlock) {
        DestroyEnvironmentBlock(envBlock);
    }
    CloseHandle(targetToken);

    // 恢复原始工作目录
    dirBack();
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
    logt.info() << "Received command: " << context.program << ", args: " << context.arguments.xjoin();
    
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
    logt.info() << "Service main thread started";

    UpdateServiceStatus(SERVICE_RUNNING);

    // 缓存当前工作目录
    GetCurrentDirectory(MAX_PATH, originalDir);

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
    
    logt.info() << "Service main thread ended";
}


VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    LOGT_LOCAL("ServiceMain");

    logt::addfile(platform::executable_dir()/"autosudo_service.log", true);
    logt::claim("ServiceMain");

    auth::authlist.load();

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
        logt::addfile("autosudo_service_debug.log", true);
        auth::authlist.load();

        logt::setFilterLevel(LogLevel::Debug);

        logt.info() << "Running in debug mode";
        
        serviceStopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        MainServiceLoop();
        CloseHandle(serviceStopEvent);
        
        logt::shutdown();
        return 0;
    } else {
        logt::addfile("autosudo_service.log", true);
        
        // 服务模式
        wchar_t serviceName[] = L"AutoSudoService";
        SERVICE_TABLE_ENTRY serviceTable[] = {
            { serviceName, ServiceMain },
            { nullptr, nullptr }
        };
    
        if (!StartServiceCtrlDispatcher(serviceTable)) {
            logt::claim("AutoSudoService");
            logt::addfile("autosudo_service_error.log", true);
            logt.error() << "StartServiceCtrlDispatcher failed: " << platform::windows::TranslateLastError();

            logt::shutdown();
            return 1;
        }
    }
}