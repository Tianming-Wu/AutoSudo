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
std::wstring MakeFullCommandLine(const AutoSudoRequest& request);

Broker::Broker(const std::string& pipeName, const std::string &inputStreamName, const std::string &outputStreamName, const std::bytearray& token)
    : m_name(pipeName), m_inputStreamName(inputStreamName), m_outputStreamName(outputStreamName), m_token(token)
    , msgServer(pipeName, libpipe::PermissionPresets::Everyone)
    , inputStreamServer(inputStreamName, libpipe::PermissionPresets::Everyone)
    , outputStreamServer(outputStreamName, libpipe::PermissionPresets::Everyone)
{
    msgServer.setPipeMode(libpipe::PipeMode::Message);
    // Stream pipes use byte mode (default)

    msgServer.setMaxClients(1);
    inputStreamServer.setMaxClients(1);
    outputStreamServer.setMaxClients(1);
}

Broker::~Broker()
{
    if (msgServer.active()) {
        msgServer.stop();
    }
    if (inputStreamServer.active()) {
        inputStreamServer.stop();
    }
    if (outputStreamServer.active()) {
        outputStreamServer.stop();
    }
}

int Broker::Run()
{
    LOGT_LOCAL("Broker::Run");

    if(!msgServer.start()) {
        logt.fatal() << "Failed to start pipe server";
        return 1;
    }

    if(!inputStreamServer.start()) {
        logt.fatal() << "Failed to start input stream pipe server";
        return 1;
    }

    if(!outputStreamServer.start()) {
        logt.fatal() << "Failed to start output stream pipe server";
        return 1;
    }
    
    if(msgServer.waitForNextConnection(std::chrono::seconds(1))) {
    
        auto client = msgServer.queryNextConnection();

        if(!client.valid()) {
            logt.fatal() << "Failed to fetch client connection.";
            return 1;
        };

        if(client.waitForReadyRead(std::chrono::milliseconds(500))) {
            std::bytearray data = client.readAll();
            AutoSudoRequest request = AutoSudoRequest::load(data);
            logt.debug() << "Received command: " << request.executableFullPath << ", args: " << request.arguments.xjoin();

            // notify client to be ready for later streamed connection
            client.write(std::bytearray(BrokerResponse::Success));

            // tell the client about the stream pipe names (input and output)
            client.write(std::bytearray(m_inputStreamName));
            client.write(std::bytearray(m_outputStreamName));

            // client must be moved and cannot be copied.
            return RunProcess(std::move(client), request);
        } else {
            logt.error() << "Client did not send data within timeout.";
            return 1;
        }
    } else {
        logt.error() << "Client did not connect within timeout.";
        return 1;
    }

    return 0;
}

int Broker::RunProcess(libpipe::pipe_server_client&& msgClient, const AutoSudoRequest &request)
{
    LOGT_LOCAL("Broker::RunProcess");

    // 等待客户端连接到输入管道
    if(!inputStreamServer.waitForNextConnection(std::chrono::seconds(1))) {
        logt.error() << "Client did not connect to input stream pipe within time limit.";
        return 1;
    }

    auto inputClient = inputStreamServer.queryNextConnection();

    // 等待客户端连接到输出管道
    if(!outputStreamServer.waitForNextConnection(std::chrono::seconds(1))) {
        logt.error() << "Client did not connect to output stream pipe within time limit.";
        return 1;
    }

    auto outputClient = outputStreamServer.queryNextConnection();

    // 1) 创建管道：ConPTY 输入/输出
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };

    CreatePipe(&inRead, &inWrite, &sa, 0);   // broker 写入 inWrite -> 子进程 stdin
    CreatePipe(&outRead, &outWrite, &sa, 0); // 子进程 stdout -> broker 从 outRead 读取

    // 2) 创建伪控制台
    HPCON hPC;
    COORD size{ SHORT(request.ihConsoleX), SHORT(request.ihConsoleY) };
    HRESULT hr = CreatePseudoConsole(size, inRead, outWrite, 0, &hPC);
    
    if (FAILED(hr)) {
        logt.error() << "CreatePseudoConsole failed: " << hr;
        msgClient.write(std::bytearray(BrokerResponse::ConPTYCreationFailed));

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

    DWORD targetSessionId = request.targetSessionId;

    // 检查当前的会话 id 和目标 sessionid 是否匹配
    
    if(WTSGetActiveConsoleSessionId() != targetSessionId) {
        // 说明用户发送给服务和 Broker 的 SessionId 不一致，拒绝执行。
        logt.error() << "Session ID mismatch: active session is " << WTSGetActiveConsoleSessionId()
                     << " but got " << targetSessionId << " from client. Refusing to run process.";
        msgClient.write(std::bytearray(BrokerResponse::SessionIDMismatch));
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
    std::wstring cmd = MakeFullCommandLine(request);
    
    BOOL success = CreateProcessW(
        nullptr,
        cmd.data(),
        nullptr, nullptr,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
        envBlock,
        request.workingDirectory.empty() ? nullptr : request.workingDirectory.c_str(),
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
        msgClient.write(std::bytearray(BrokerResponse::ProcessStartFailed));
        ClosePseudoConsole(hPC);
        CloseHandle(inWrite);
        CloseHandle(outRead);
        return GetLastError();
    }

    logt.info() << "Process started successfully, PID: " << pi.dwProcessId;

    // 5) broker 负责 IO 转发
    // 先返回 0x00 告诉客户端进程启动成功。
    msgClient.write(std::bytearray(BrokerResponse::Success));

    std::atomic_bool running { true };

    // IO 转发循环（双向异步）
    std::thread inputThread([&]() {
        // Client -> Broker -> ConPTY (阻塞式读取，无轮询延迟)
        logt.debug() << "Input forwarding thread started.";
        while (running) {
            std::bytearray data = inputClient.read(4096);
            if (data.empty()) {
                if (inputClient.broken()) {
                    logt.debug() << "Input stream pipe closed (input forward thread).";
                }
                break;
            }
            
            logt.debug() << "Received " << data.rawSize() << " bytes from client, forwarding to ConPTY.";
            DWORD written;
            const void* dataPtr = data.rawData();
            const DWORD dataSize = static_cast<DWORD>(data.rawSize());
            
            if (!WriteFile(inWrite, dataPtr, dataSize, &written, nullptr)) {
                DWORD err = GetLastError();
                if (running) {
                    logt.error() << "WriteFile to ConPTY failed: " << platform::windows::TranslateError(err);
                }
                break;
            }
            logt.debug() << "Wrote " << written << " bytes to ConPTY.";
        }
        logt.debug() << "Input forwarding thread exiting.";
    });

    std::thread outputThread([&]() {
        // ConPTY -> Broker -> Client
        logt.debug() << "Output forwarding thread started.";
        char buffer[4096];
        DWORD read;
        while (running) {
            if (ReadFile(outRead, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
                logt.debug() << "Read " << read << " bytes from ConPTY, forwarding to client.";
                if (outputClient.write(std::bytearray(buffer, read)) == 0) {
                    logt.warn() << "Write to output stream pipe failed.";
                    // 写入失败时检查连接是否断开
                    if (outputClient.broken()) {
                        logt.warn() << "Output stream pipe broken (output forward thread).";
                    }
                    running = false;
                    break;
                }
                logt.debug() << "Sent " << read << " bytes to client.";
            } else {
                DWORD err = GetLastError();
                if (err != ERROR_BROKEN_PIPE && running) {
                    logt.warn() << "ReadFile from ConPTY failed: " << platform::windows::TranslateError(err);
                }
                running = false;
                break;
            }
        }
        logt.debug() << "Output forwarding thread exiting.";
    });

    std::atomic_bool externalExitFlag = true;
    std::thread externalThread([&]() {
        logt.debug() << "Control message thread started.";
        while(running && externalExitFlag) {
            if(msgClient.waitForReadyRead(std::chrono::seconds(1))) {
                std::bytearray Signal = msgClient.readAll();
                if (Signal.empty()) {
                    // 管道已关闭或断开
                    logt.debug() << "Control message pipe closed.";
                    break;
                }
                std::bytearray_view Signal_View(Signal);
                BrokerSignal signal = Signal_View.read<BrokerSignal>();

                switch(signal) {
                case BrokerSignal::ResizeConsole: {
                    ResizeConsoleData data = Signal_View.read<ResizeConsoleData>();
                    ResizePseudoConsole(hPC, COORD{ data.width, data.height });
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

            if(!externalExitFlag) {
                break;
            }
            // 检查管道是否已断开
            if (msgClient.broken()) {
                logt.debug() << "Control message pipe broken, exiting.";
                break;
            }
        }
    });

    // 等待进程结束
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    logt.info() << "Target process exited with code: " << exitCode;

    // 通知所有线程退出
    running = false;
    externalExitFlag = false;

    // 往客户端返回进程退出状态码
    msgClient.write(std::bytearray(exitCode)); // will match _Any constructors, so is fine

    // 关闭 ConPTY 管道句柄以解除 IO 线程的阻塞
    CloseHandle(inWrite);  inWrite = nullptr;
    CloseHandle(outRead);  outRead = nullptr;

    // 关闭所有 pipe 连接以解除各线程中阻塞的 read()/waitForReadyRead()
    inputClient.close();
    outputClient.close();
    msgClient.close();

    // 所有阻塞 IO 已被中断，现在可以安全 join
    inputThread.join();
    outputThread.join();
    externalThread.join();
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    ClosePseudoConsole(hPC);

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

std::wstring MakeFullCommandLine(const AutoSudoRequest& request) {
    std::wstringlist args = request.arguments;
    args.insert(args.begin(), request.executableFullPath);
    return args.xjoin();
}