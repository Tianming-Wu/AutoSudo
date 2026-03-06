#include "broker.hpp"

#include "broker_protocol.hpp"

#include <thread>
#include <SharedCppLib2/platform_windows.hpp>
#include <accctrl.h>
#include <aclapi.h>
#include <userenv.h>
#include <wtsapi32.h>

#include <SharedCppLib2/logt.hpp>
#include <SharedCppLib2/platform.hpp>

PSECURITY_DESCRIPTOR CreatePipeSecurity();
std::wstring MakeFullCommandLine(const ProcessContext& context);

Broker::Broker()
{
}

Broker::~Broker()
{
    if(hpipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hpipe);
    }
}

int Broker::Start(const std::wstring &pipeName, const std::bytearray& token)
{
    LOGT_LOCAL("Broker::Start");

    // Store the value
    m_name = pipeName;
    m_token = token;

    ProcessContext pc;

    if(!Init()) return GetLastError();

    // Start the pipe for a single time
    // Step 1: handshake with the client to get the process context information
    if(Wait()) {
        // Verify the token
        std::bytearray recv_token = Receive();

        if(recv_token != m_token) {
            logt.error() << "Received invalid token from client, closing connection.";
            return -1;
        }

        // Response the client to get the process context information

        Send(std::bytearray(B(0x01))); // 0x01 means handshake successful

        if(Wait()) { // wait for another client response
            std::bytearray context_data = Receive();
            pc = ProcessContext::Deserialize(
                std::wstring(reinterpret_cast<const wchar_t*>(context_data.rawData()),
                    (context_data.rawSize() / sizeof(wchar_t)))
            );
        } else {
            logt.error() << "Failed to receive process context from client.";
            return GetLastError();
        }
    } else {
        logt.error() << "Failed to wait for client connection.";
        return GetLastError();
    }
    
    return RunProcess(pc);
}

bool Broker::Init()
{
    LOGT_LOCAL("Broker::Init");

    PSECURITY_DESCRIPTOR sd = CreatePipeSecurity();
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;

    hpipe = CreateNamedPipe(
        m_name.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, // Only allow a single client to connect
        BUFFER_SIZE,
        BUFFER_SIZE,
        NMPWAIT_USE_DEFAULT_WAIT,
        sd ? &sa : nullptr  // 使用安全属性
    );

    if (sd) {
        LocalFree(sd);
    }
    
    if (hpipe == INVALID_HANDLE_VALUE) {
        logt.error() << "CreateNamedPipe failed: " << platform::windows::TranslateLastError();
        return false;
    }
    
    logt.debug() << "Named pipe created successfully: " << m_name;

    return true;
}

bool Broker::Wait()
{
    LOGT_LOCAL("Broker::Wait");

    BOOL connected = ConnectNamedPipe(hpipe, nullptr);
    if (!connected) {
        DWORD error = GetLastError();
        if (error == ERROR_PIPE_CONNECTED) {
            logt.info() << "Client already connected";
            return true;
        } else {
            logt.error() << "ConnectNamedPipe failed: " << platform::windows::TranslateError(error);
            CloseHandle(hpipe);
            hpipe = INVALID_HANDLE_VALUE;
            return false;
        }
    }
    
    return true;
}

std::bytearray Broker::Receive()
{
    LOGT_LOCAL("Broker::Receive");
    wchar_t buffer[BUFFER_SIZE];
    DWORD bytesRead;

    if (!ReadFile(hpipe, buffer, BUFFER_SIZE * sizeof(wchar_t), &bytesRead, nullptr)) {
        logt.error() << "ReadFile failed: " << platform::windows::TranslateLastError();
        return std::bytearray();
    }

    // Return the received data as a bytearray
    return std::bytearray(PCB(buffer), bytesRead);
}

size_t Broker::Send(const std::bytearray &data)
{
    LOGT_LOCAL("Broker::Send");
    DWORD bytesWritten;
    if (!WriteFile(hpipe, data.rawData(), DWORD(data.rawSize()), &bytesWritten, nullptr)) {
        logt.error() << "WriteFile failed: " << platform::windows::TranslateLastError();
        return 0;
    }
    return bytesWritten;
}

int Broker::RunProcess(const ProcessContext &pc)
{
    LOGT_LOCAL("Broker::RunProcess");

    // 1) 创建管道：ConPTY 输入/输出
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };

    CreatePipe(&inRead, &inWrite, &sa, 0);   // broker 写入 inWrite -> 子进程 stdin
    CreatePipe(&outRead, &outWrite, &sa, 0); // 子进程 stdout -> broker 从 outRead 读取

    // 2) 创建伪控制台
    HPCON hPC;
    COORD size{ SHORT(pc.ConsoleX), SHORT(pc.ConsoleY) };
    HRESULT hr = CreatePseudoConsole(size, inRead, outWrite, 0, &hPC);
    
    if (FAILED(hr)) {
        logt.error() << "CreatePseudoConsole failed: " << hr;
        Send(std::bytearray(B(0x03))); // 0x03 ConPTY 创建失败
        CloseHandle(inRead);
        CloseHandle(inWrite);
        CloseHandle(outRead);
        CloseHandle(outWrite);
        return hr;
    }

    // 3) 准备 STARTUPINFOEX 并绑定 HPCON
    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(si);
    SIZE_T attrListSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrListSize);
    std::vector<BYTE> attrListBuf(attrListSize);
    si.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrListBuf.data());
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrListSize);

    UpdateProcThreadAttribute(
        si.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
        hPC,
        sizeof(hPC),
        nullptr,
        nullptr
    );

    // 4) 准备环境和用户会话 id
    // 注意，此时 Broker 已经被以管理员权限启动了，所以它有权限访问所有会话的信息。
    // 我们可以根据 ProcessContext 中的 sessionId 来决定目标进程应该运行在哪个会话中。

    DWORD targetSessionId = pc.sessionId;

    // 检查当前的会话 id 和目标 sessionid 是否匹配
    
    if(WTSGetActiveConsoleSessionId() != targetSessionId) {
        // 说明用户发送给服务和 Broker 的 SessionId 不一致，拒绝执行。
        logt.error() << "Session ID mismatch: active session is " << WTSGetActiveConsoleSessionId()
                     << " but got " << targetSessionId << " from client. Refusing to run process.";
        Send(std::bytearray(B(0x02))); // 0x02 means session ID mismatch
        return ERROR_ACCESS_DENIED;
    }

    HANDLE userToken = nullptr;
    LPVOID envBlock = nullptr;

    if (WTSQueryUserToken(targetSessionId, &userToken)) {
        if (!CreateEnvironmentBlock(&envBlock, userToken, FALSE)) {
            logt.warn() << "CreateEnvironmentBlock for user failed: " << platform::windows::TranslateLastError();
            envBlock = nullptr;
        }
        CloseHandle(userToken);
    } else {
        logt.warn() << "WTSQueryUserToken failed, using default environment: " << platform::windows::TranslateLastError();
    }

    si.StartupInfo.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

    // 4) 启动目标进程（绑定到 ConPTY）
    PROCESS_INFORMATION pi{};
    std::wstring cmd = MakeFullCommandLine(pc);
    
    BOOL success = CreateProcessW(
        nullptr,
        cmd.data(),
        nullptr, nullptr,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
        envBlock,
        pc.workingDirectory.empty() ? nullptr : pc.workingDirectory.c_str(),
        &si.StartupInfo,
        &pi
    );

    // 清理
    DeleteProcThreadAttributeList(si.lpAttributeList);
    if (envBlock) {
        DestroyEnvironmentBlock(envBlock);
    }
    CloseHandle(outWrite);  // 关闭子进程端的写句柄
    CloseHandle(inRead);    // 关闭子进程端的读句柄

    if (!success) {
        logt.error() << "CreateProcessW failed: " << platform::windows::TranslateLastError();
        Send(std::bytearray(B(0x02))); // 0x02 启动失败
        ClosePseudoConsole(hPC);
        CloseHandle(inWrite);
        CloseHandle(outRead);
        return GetLastError();
    }

    logt.info() << "Process started successfully, PID: " << pi.dwProcessId;

    // 5) broker 负责 IO 转发
    // 先返回 0x00 告诉客户端进程启动成功。
    Send(std::bytearray(B(0x00)));

    // IO 转发循环（双向异步）
    std::thread inputThread([this]() {
        // Client -> Broker -> ConPTY
        char buffer[4096];
        while (true) {
            std::bytearray data = Receive();
            if (data.empty()) break;
            
            DWORD written;
            WriteFile(inWrite, data.rawData(), DWORD(data.rawSize()), &written, nullptr);
        }
    });

    std::thread outputThread([this]() {
        // ConPTY -> Broker -> Client
        char buffer[4096];
        DWORD read;
        while (ReadFile(outRead, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
            Send(std::bytearray(PCB(buffer), read));
        }
    });

    std::atomic_bool externalExitFlag = true;
    std::thread externalThread([& /* Captures everything in the context */]() {
        while(externalExitFlag) {
            std::bytearray Signal = Receive();
            std::bytearray_view Signal_View(Signal);
            BrokerSignal signal = Signal_View.read<BrokerSignal>();

            switch(signal) {
            case BrokerSignal::ResizeConsole: {
                // Read a COORD
                COORD newSize = Signal_View.read<COORD>();
                ResizePseudoConsole(hPC, newSize);
                break;
            }
            case BrokerSignal::TerminateProcess: {
                // Should Ctrl+C the child process.
                // Not implemented yet.
                break;
            }

            case BrokerSignal::Null:
            default:
                break;
            }
        }
    });

    // 等待进程结束
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    // 往客户端返回进程退出状态码
    Send(std::bytearray(exitCode)); // will match _Any constructors, so is fine

    // 清理
    inputThread.join();
    outputThread.join();
    externalThread.join();
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    ClosePseudoConsole(hPC);
    CloseHandle(inWrite);
    CloseHandle(outRead);

    DisconnectNamedPipe(hpipe); // close the pipe

    logt.info() << "Process exited with code: " << exitCode;
    return exitCode;
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
    ea[0].Trustee.ptstrName = (LPTSTR)L"Everyone";  ///TODO: 仅允许当前 SID 访问
    
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

std::wstring MakeFullCommandLine(const ProcessContext& context) {
    std::wstringlist args = context.arguments;
    args.insert(args.begin(), context.program);
    return args.xjoin();
}