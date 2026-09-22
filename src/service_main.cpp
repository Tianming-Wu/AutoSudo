#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <atomic>
#include <userenv.h>
#include <wtsapi32.h>
#include <functional>

#include <SharedCppLib2/pipe.hpp>

#include "protocol.hpp"
// #include "pipeserver.hpp" // discarded module
// #include "auth.hpp" // deprecated module, replaced by approval (RuleEngine)
#include "wintoken.hpp"
// #include "authlib.hpp"
#include "approval.hpp"

#include "auth_ui.hpp"
#include "authui.hpp"
#include "callerid.hpp"
#include "buildflags.hpp"

#include <SharedCppLib2/platform.hpp>
#include <SharedCppLib2/platform_windows.hpp>

SERVICE_STATUS serviceStatus = {0};
SERVICE_STATUS_HANDLE serviceStatusHandle = nullptr;
HANDLE serviceStopEvent = nullptr;

HANDLE execPipeThread = nullptr;
HANDLE controlPipeThread = nullptr;
std::atomic<bool> shouldStopPipeThread{false};
std::atomic<bool> pipeListenerFailed{false};

// allowUnelevatedRuleCallers (buildflags.hpp) is what a debug build relaxes: the control
// channel is created for everyone, a caller that is not elevated is accepted, and the key
// of the rule database is left with the process default descriptor.

// The two things a listener thread needs to know about its channel.
struct PipeChannel {
    const char* name;
    scl2::pipe::permission_preset preset;
    bool control;   // whether this channel carries rule operations
};

// The execution channel is open to every local process - that is what the product is for -
// and the approval that follows is the only gate. The control channel is where that gate is
// changed, so it is created for administrators and LocalSystem only.
PipeChannel execChannel{execPipeName, scl2::pipe::permission_preset::Everyone, false};
PipeChannel controlChannel{
    controlPipeName,
    allowUnelevatedRuleCallers ? scl2::pipe::permission_preset::Everyone
                               : scl2::pipe::permission_preset::Administrators,
    true};

// The rule engine is read and written from both channels at once - an evaluation on the
// execution channel while a rule is edited on the control channel - so everything that
// touches it goes through this.
std::mutex engineMutex;

std::string GenerateBrokerPipeName() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<unsigned long long> dis;
    std::ostringstream oss;
    oss << R"(\\.\pipe\asb_msg_)" << std::hex << dis(gen);
    return oss.str();
}

std::string GenerateBrokerTokenHex(size_t bytes = 16) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, 255);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < bytes; ++i) {
        oss << std::setw(2) << dis(gen);
    }
    return oss.str();
}

VOID WINAPI ServiceCtrlHandler(DWORD controlCode) {
    LOGT_LOCAL("ServiceCtrlHandler");
    switch (controlCode) {
        case SERVICE_CONTROL_STOP:
            logt.info() << "Stopping service..."; // Edit: This should be "subjective", not "passive"
            serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            serviceStatus.dwWaitHint = 10000; // 10秒超时
            serviceStatus.dwCheckPoint = 1;

            SetServiceStatus(serviceStatusHandle, &serviceStatus);

            shouldStopPipeThread = true;
            if (serviceStopEvent) {
                SetEvent(serviceStopEvent);
            }

            // The listener threads poll the flag above, and the main loop waits for them.
            // Waiting here as well would mean closing the same handle twice.

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

// The confirmation dialog and the notifications live in authui.cpp: this file is about the
// channels and the process creation, and it was carrying enough of the user-facing side of
// the service to make both harder to read.

std::wstring MakeFullCommandLine(const AutoSudoRequest& request) {
    scl2::wstringlist args = request.arguments;
    args.insert(args.begin(), request.executableFullPath);
    return args.xjoin();
}

bool CreateProcessWithContext(const AutoSudoRequest& context, HANDLE token) {
    LOGT_LOCAL("CreateProcessWithContext");

    // The token for the level the rules approved. This used to be CreateProcess(), which
    // runs the child with the token of the service itself - LocalSystem - whatever level
    // the request named and whatever a rule allowed. The token is what decides what the
    // child runs as, on this path as on the session one.
    if (token == nullptr) {
        logt.error() << "CreateProcessWithContext was called without a token.";
        return false;
    }

    STARTUPINFO si = {0};
    si.cb = sizeof(STARTUPINFO);
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    
    PROCESS_INFORMATION pi = {0};

    std::wstring fullCommandLine = MakeFullCommandLine(context);
    
    if (!CreateProcessAsUser(
        token,
        nullptr,
        const_cast<LPWSTR>(fullCommandLine.c_str()),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
        nullptr,
        context.workingDirectory.empty() ? nullptr : context.workingDirectory.c_str(),
        &si,
        &pi
    )) {
        logt.error() << "CreateProcessAsUser failed: " << platform::windows::TranslateLastError();
        return false;
    }

    logt.info() << "Process created successfully: " << fullCommandLine;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

bool CreateProcessInUserSession(const AutoSudoRequest& request, const callerid::CallerInfo& caller,
                               std::string* brokerToken, std::string* brokerPipeName) {
    LOGT_LOCAL("CreateProcessInUserSession");
    DWORD targetSessionId = request.targetSessionId;
    
    // 如果useCurrentSession为false或者sessionId无效，使用默认逻辑
    // 此判断已经在调用处进行过一次，但这里再确认一次以防万一
    // 修改：不再在此处进行验证
    // if (!request.useCurrentSession || targetSessionId == 0xFFFFFFFF) {
    //     logt.warn() << "Fallback to using default session handling";
    //     return CreateProcessWithContext(request); // 回退到原来的方法
    // }
    
    logt.debug() << "Creating process in session: " << targetSessionId;

    // The directory the caller invoked AutoSudo from, which a plain `autosudo tool.exe`
    // is expected to run in. It used to reach the child by changing the current directory
    // of the whole service - a global, shared by two listener threads now, and a race -
    // so it is passed to CreateProcessAsUser instead.
    std::wstring workingDirectoryForCreate = request.workingDirectory;
    if (workingDirectoryForCreate.empty()) {
        workingDirectoryForCreate = request.calledPath;
    }

    if (!workingDirectoryForCreate.empty()) {
        std::error_code wdEc;
        fs::path wdPath(workingDirectoryForCreate);
        if (!fs::exists(wdPath, wdEc) || !fs::is_directory(wdPath, wdEc)) {
            fs::path fallbackDir = fs::path(request.executableFullPath).parent_path();
            if (!fallbackDir.empty() && fs::exists(fallbackDir, wdEc) && fs::is_directory(fallbackDir, wdEc)) {
                logt.warn() << "Invalid request working directory: " << workingDirectoryForCreate
                            << ", fallback to executable directory: " << fallbackDir.wstring();
                workingDirectoryForCreate = fallbackDir.wstring();
            } else {
                logt.warn() << "Invalid request working directory and executable directory unavailable: " << workingDirectoryForCreate
                            << ", CreateProcessAsUser will use default directory.";
                workingDirectoryForCreate.clear();
            }
        }
    }

    // 如果设置了 deleteAuth 标志，询问用户是否删除授权
    // 26.03.22: 这套判断逻辑已经不适用于新的规则系统，将于未来版本完全移除
    // if (request.deleteAuth) {
    //     int authUIResult = RequestUserConfirmation(request, AuthUIType::ConfirmDeletion);
    //     if (authUIResult == static_cast<int>(AuthUIResult::Delete)) {
    //         // 用户选择删除
    //         logt.info() << "User confirmed deletion of: " << request.program;
    //         auth::authlist.remove(request.program);
    //         dirBack();
    //         return true;  // 删除授权后返回true，不执行程序
    //     } else if (authUIResult == static_cast<int>(AuthUIResult::Deny)) {
    //         // 用户选择取消
    //         logt.info() << "User cancelled deletion operation";
    //         dirBack();
    //         return false;
    //     }
    //     // authUIResult == AuthUIResult::Allow 时继续执行授权检查
    // }

    // 授权判断流程：

    ApprovalResult apr;
    try {
        apr = ApprovalEngine::evaluate(protToRequest(request));
    } catch (const std::exception& ex) {
        logt.error() << "Exception during approval evaluation: " << ex.what();
        // 评估失败，视为拒绝
        return false;
    }

    logt.debug() << "Approval result: " << static_cast<int>(apr.result) 
                << (apr.reason.has_value() ? ", reason: " + apr.reason.value() : "")
                << ", allowed level: " << static_cast<int>(apr.allowUpTo);

    switch(apr.result) {
        case ApprovalResultId::Denied:
            logt.info() << "Authorization denied by approval engine" << (apr.reason.has_value() ? ", reason: " + apr.reason.value() : "");
            ///TODO: Post a toast notification to inform the user about the denial and possible reasons.
            return false;

        case ApprovalResultId::Approved:
            logt.debug() << "Authorization approved by approval engine.";

            // Check the permission level
            if (apr.allowUpTo >= request.requestedPermissionLevel) {
                // Nothing goes wrong. A rule allowed this and nobody was asked, which is the
                // one outcome with no other way of reaching the user: the process is already
                // starting by the time anyone could look at it.
                authui::notifyAutoApproved(request.executableFullPath,
                                           request.requestedPermissionLevel, caller);
                break;
            } else {
                logt.info() << "Approval engine allows up to " << static_cast<int>(apr.allowUpTo) 
                            << " but requested level is " << static_cast<int>(request.requestedPermissionLevel);
                // Bypass to RequestUserConfirmation.
                // Later we may add a individual rule to determine the behavior when the permission level is insufficient.
            }

        case ApprovalResultId::RequestConfirmation:
            ///TODO: RequestUserConfirmation also needs to be adapted to the new approval engine.
            
            // The rule handing UI is moved to a separate project made with Qt.
            // The intergration is done by AutoSudoSdk, use CMake install to make it available.
            // Check AutoSudoGUI project for details.

            ///TODO: Distinguish between no rules and not found.
            // Insufficient level is not supported by the current RuleEngine design.

            if (authui::confirm(request, AuthUIType::NoRuleMatched, &caller) != static_cast<int>(AuthUIResult::Allow)) {
                return false;
            }
            // 用户确认，更新权限级别
            // auth::authlist.insert(request.program, request.requestedPermissionLevel);
            break;
        case ApprovalResultId::Fail:
            logt.error() << "Authorization evaluation failed, treating as Denied." << (apr.reason.has_value() ? " Reason: " + apr.reason.value() : "");
            return false;
        default:
            logt.fatal() << "Unexpected approval result.";
            return false;
    }

    HANDLE targetToken = wintoken::getToken(request.requestedPermissionLevel, request);

    if(targetToken == nullptr) {
        // 获取令牌失败，退出
        logt.error() << "Failed to obtain token for the requested authorization level.";

        return false;
    }

    // 设置令牌到目标会话
    if (!SetTokenInformation(targetToken, TokenSessionId, &targetSessionId, sizeof(DWORD))) {
        if (wintoken::isNonServiceMode()) {
            logt.warn() << "SetTokenInformation failed in non-service mode, continue with current session token: "
                        << platform::windows::TranslateLastError();
        } else {
            logt.error() << "SetTokenInformation failed: " << platform::windows::TranslateLastError();
            CloseHandle(targetToken);
            return false;
        }
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

    std::wstring fullCommandLine;
    bool launchingBroker = request.inheritConsole;

    if (launchingBroker) {
        std::string assignedPipe = GenerateBrokerPipeName();
        std::string assignedToken = GenerateBrokerTokenHex();

        fullCommandLine = L"\"" + (platform::executable_dir() / L"AutoSudoBroker.exe").wstring() + L"\" ";
        
        // 在 non-service 模式下添加 debug 参数
        if (wintoken::isNonServiceMode()) {
            fullCommandLine += L"debug ";
        }
        
        fullCommandLine += scl2::str_to_wstr(assignedPipe) + L" " + scl2::str_to_wstr(assignedToken);

        if (brokerPipeName) *brokerPipeName = assignedPipe;
        if (brokerToken) *brokerToken = assignedToken;

        logt.debug() << "Launching broker: " << fullCommandLine;
    } else {
        fullCommandLine = MakeFullCommandLine(request);
    }
    
    BOOL success = CreateProcessAsUser(
        targetToken,
        nullptr,
        const_cast<LPWSTR>(fullCommandLine.c_str()),
        nullptr,
        nullptr,
        FALSE,
        CREATE_UNICODE_ENVIRONMENT,
        envBlock,
        workingDirectoryForCreate.empty() ? nullptr : workingDirectoryForCreate.c_str(),
        &si,
        &pi
    );
    
    if (!success) {
        DWORD error = GetLastError();
        logt.error() << "CreateProcessAsUser failed: " << platform::windows::TranslateError(error);
        
        // 尝试回退到没有用户环境的方式
        if (envBlock && (error == ERROR_INVALID_PARAMETER || error == ERROR_BAD_ENVIRONMENT)) {
            logt.debug() << "Retrying without user environment block...";
            success = CreateProcessAsUser(
                targetToken,
                nullptr,
                const_cast<LPWSTR>(fullCommandLine.c_str()),
                nullptr,
                nullptr,
                FALSE,
                CREATE_NEW_CONSOLE,
                nullptr,
                workingDirectoryForCreate.empty() ? nullptr : workingDirectoryForCreate.c_str(),
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
        if (launchingBroker) {
            logt.info() << "Broker created successfully in user session, PID: " << pi.dwProcessId;
        } else {
            logt.info() << "Process created successfully in user session, PID: " << pi.dwProcessId;
        }
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

    return success;
}

// Handle process execution request
bool HandleExecutionRequest(scl2::pipe::server_client& client, const scl2::bytearray& data,
                           const callerid::CallerInfo& caller) {
    LOGT_LOCAL("HandleExecutionRequest");

    // Handle program execution request
    AutoSudoRequest request = AutoSudoRequest::load(data);

    std::string reason;
    if (!request.validate(reason)) {
        logt.warn() << "Refusing an execution request from " << caller.describe() << ": " << reason;
        client.write(scl2::bytearray::fromStdWString(L"ERROR: Invalid request"));
        client.waitForFinished(std::chrono::seconds(1));
        return false;
    }

    logt.info() << "Received command: " << request.executableFullPath << ", args: " << request.arguments.xjoin();
    logt.debug() << "Request paths: workingDirectory='" << request.workingDirectory
                 << "', calledPath='" << request.calledPath << "'";

    // The session the caller is in is the session a process for that caller belongs in. A
    // request naming another one asks to put a process on a different desktop - under fast
    // user switching the console session is not necessarily the caller's - so the caller's
    // own session is used instead. 0xFFFFFFFF means the caller's session could not be read,
    // and then the request is left alone.
    if (request.useCurrentSession && caller.sessionId != 0xFFFFFFFF
        && request.targetSessionId != caller.sessionId) {
        logt.warn() << "Execution request for session " << request.targetSessionId
                    << " from a caller in session " << caller.sessionId
                    << "; using the caller's session.";
        request.targetSessionId = caller.sessionId;
    }

    // 根据上下文决定创建方式
    bool success = false;
    std::string brokerToken;
    std::string brokerMsgPipe;

    if (request.useCurrentSession && request.targetSessionId != 0xFFFFFFFF) {
        logt.debug() << "using CreateProcessInUserSession";
        success = CreateProcessInUserSession(request, caller, &brokerToken, &brokerMsgPipe);
    } else {
        logt.debug() << "using CreateProcessWithContext";
        // No session was asked for, so the approved level is what the child runs as: the
        // same token the session path goes looking for.
        HANDLE token = wintoken::getToken(request.requestedPermissionLevel, request);
        if (token == nullptr) {
            logt.error() << "Failed to obtain token for the requested authorization level.";
        } else {
            success = CreateProcessWithContext(request, token);
            CloseHandle(token);
        }
    }
    
    // 发送响应
    if (success) {
        if (request.inheritConsole && !brokerToken.empty() && !brokerMsgPipe.empty()) {
            client.write(scl2::bytearray(brokerToken));
            client.write(scl2::bytearray(brokerMsgPipe));

            if(!client.waitForFinished(std::chrono::seconds(1))) {
                logt.warn() << "Client did not acknowledge broker info.";
            }
        } else {
            client.write(scl2::bytearray::fromStdWString(L"SUCCESS: Process created"));
            if(!client.waitForFinished(std::chrono::seconds(1))) {
                logt.warn() << "Client did not acknowledge broker info.";
            }
        }
    } else {
        client.write(scl2::bytearray::fromStdWString(L"ERROR: Failed to create process"));
        if(!client.waitForFinished(std::chrono::seconds(1))) {
            logt.warn() << "Client did not acknowledge execution error response.";
        }
    }
    
    return true;
}

// Handle rule management operations
bool ProcessRuleOperation(scl2::pipe::server_client& client, const scl2::bytearray& data,
                          const callerid::CallerInfo& caller) {
    LOGT_LOCAL("ProcessRuleOperation");
    
    try {
        RuleEngineOperationRequest op = RuleEngineOperationRequest::load(data);

        std::string reason;
        if (!op.validate(reason)) {
            logt.warn() << "Refusing a rule operation from " << caller.describe() << ": " << reason;
            RuleEngineOperationResult refusal;
            refusal.success = false;
            refusal.message = "Invalid rule operation: " + reason;
            client.write(refusal.dump());
            client.waitForFinished(std::chrono::seconds(1));
            return false;
        }

        // One engine, two channels: an evaluation on the execution channel must not run
        // while a rule is being replaced here.
        std::lock_guard<std::mutex> lock(engineMutex);

        auto enginePtr = ApprovalEngine::instance();
        if (enginePtr == nullptr) {
            // The engine is created by the entry point. Reaching this means the process was
            // started in a way that skipped it, and there is nothing to operate on - but
            // that stays this connection's problem, not the service's.
            logt.error() << "Rule operations are unavailable: no approval engine instance.";
            RuleEngineOperationResult failure;
            failure.success = false;
            failure.message = "Rule engine is not available";
            client.write(failure.dump());
            client.waitForFinished(std::chrono::seconds(1));
            return false;
        }

        RuleEngineOperationResult result;
        
        switch (op.op) {
            case RuleEngineOperation::Create: {
                logt.info() << "Creating new rule, type=" << static_cast<int>(op.ruleType);
                apprule_uid_t newUid = enginePtr->create(
                    static_cast<ApprovalRule::Type>(op.ruleType),
                    static_cast<ApprovalRule::EType>(op.ruleEType),
                    static_cast<ApprovalRule::Action>(op.ruleAction),
                    op.ruleAllowUpTo,
                    op.payload,
                    op.insertAt
                );
                result.success = true;
                result.createdUid = newUid;
                result.message = "Rule created successfully";
                break;
            }
            
            case RuleEngineOperation::Modify: {
                logt.info() << "Modifying rule, uid=" << op.targetUid;
                bool success = enginePtr->modify(
                    op.targetUid,
                    static_cast<ApprovalRule::Type>(op.ruleType),
                    static_cast<ApprovalRule::EType>(op.ruleEType),
                    static_cast<ApprovalRule::Action>(op.ruleAction),
                    op.ruleAllowUpTo,
                    op.payload,
                    op.moveToOrder
                );
                result.success = success;
                result.message = success ? "Rule modified successfully" : "Failed to modify rule: UID not found";
                break;
            }
            
            case RuleEngineOperation::Delete: {
                logt.info() << "Deleting rule, uid=" << op.targetUid;
                bool success = enginePtr->remove(op.targetUid);
                result.success = success;
                result.message = success ? "Rule deleted successfully" : "Failed to delete rule: UID not found";
                break;
            }
            
            case RuleEngineOperation::Move: {
                logt.info() << "Moving rule, uid=" << op.targetUid << " to order=" << op.moveToOrder.value_or(0);
                bool success = false;
                if (op.moveToOrder.has_value()) {
                    success = enginePtr->moveTo(op.targetUid, op.moveToOrder.value());
                    result.message = success ? "Rule moved successfully" : "Failed to move rule";
                } else {
                    result.message = "Move operation requires moveToOrder value";
                }
                result.success = success;
                break;
            }
            
            case RuleEngineOperation::List: {
                logt.info() << "Listing all rules";
                RuleListResponse listResponse;
                listResponse.rules = enginePtr->listRules();
                logt.info() << "List operation returns " << listResponse.rules.size() << " rules";
                client.write(listResponse.dump());
                if(!client.waitForFinished(std::chrono::seconds(1))) {
                    logt.warn() << "Client did not acknowledge rule list response.";
                }
                return true;
            }
            
            default:
                result.success = false;
                result.message = "Unknown operation";
                break;
        }
        
        // Send result
        client.write(result.dump());
        if(!client.waitForFinished(std::chrono::seconds(1))) {
            logt.warn() << "Client did not acknowledge rule operation response.";
        }
        return true;
        
    } catch (const std::exception& e) {
        logt.error() << "Exception in ProcessRuleOperation: " << e.what();
        RuleEngineOperationResult result;
        result.success = false;
        result.message = std::string("Exception: ") + e.what();
        client.write(result.dump());
        return false;
    }
}

bool ProcessClientRequest(scl2::pipe::server_client& client, bool controlChannel) {
    LOGT_LOCAL("ProcessClientRequest");

    // 读取请求数据
    scl2::bytearray data = client.readAll();
    if (data.empty()) {
        if(client.broken()) {
            logt.error() << "Client connection is broken.";
        } else {
            logt.error() << "Failed to read request from client or empty request";
        }
        return false;
    }

    // The size is checked before anything is interpreted: a request decides how much is
    // read from it, and the peer does not get to decide that.
    if (data.size() > limits::maxRequestBytes) {
        logt.warn() << "Refusing a " << data.size() << " byte request, the limit is "
                    << limits::maxRequestBytes << " bytes.";
        return false;
    }

    // The frame carries the protocol version, the request type and the payload. A frame
    // this build cannot use is refused as a whole - a request one version off would
    // otherwise be read into fields that mean something else.
    ClientRequestType reqType = ClientRequestType::ExecuteCommand;
    scl2::bytearray payload;
    std::string reason;
    if (!parseRequestFrame(data, reqType, payload, reason)) {
        logt.warn() << "Refusing a request: " << reason;
        return false;
    }

    // Who is asking is read before anything is decided. It comes from the token the kernel
    // attached to this connection, not from the request, so it is the one part of a request
    // that a client cannot choose.
    const callerid::CallerInfo caller = callerid::identify(client.nativeHandle());
    logt.info() << "Request type " << static_cast<int>(reqType) << " on the "
                << (controlChannel ? "control" : "execution") << " channel from "
                << caller.describe();

    if (controlChannel) {
        // Rules decide what may run without asking the user, so changing them is an
        // administrative act. The channel is created for administrators and LocalSystem;
        // this is the same check at the level of the caller, because a descriptor belongs
        // to the name and every instance of it, not to the conversation.
        if (!caller.isPrivileged()) {
            if (!allowUnelevatedRuleCallers) {
                logt.warn() << "Refusing rule operations from " << caller.describe() << ".";
                return false;   // the connection closes without a reply
            }
            logt.warn() << "Accepting rule operations from " << caller.describe()
                        << " because this is a debug build.";
        }

        if (reqType != ClientRequestType::RuleEngineCommand) {
            logt.warn() << "Refusing request type " << static_cast<int>(reqType)
                        << " on the control channel.";
            return false;
        }

        return ProcessRuleOperation(client, payload, caller);
    }

    switch(reqType) {
    case ClientRequestType::ExecuteCommand:
        return HandleExecutionRequest(client, payload, caller);
    case ClientRequestType::RuleEngineCommand:
        // Rule operations belong on the control channel, which is the one the service
        // checks the caller on. Accepting them here would go around that check.
        logt.warn() << "Refusing a rule operation on the execution channel from " << caller.describe() << ".";
        return false;
    case ClientRequestType::ServiceMgrCommand:
        logt.warn() << "Refusing a service management request: not implemented.";
        return false;
    default: {
        logt.error() << "Unknown client request type: " << static_cast<int>(reqType);
        return false;
    }
    }
}

DWORD WINAPI PipeListenerThread(LPVOID param) {
    const PipeChannel channel = *static_cast<const PipeChannel*>(param);

    logt::claim(channel.control ? "ControlPipeListener" : "PipeListener");
    LOGT_LOCAL("PipeListenerThread");
    logt.info() << "Pipe listener thread started on " << channel.name;

    scl2::pipe::server server(channel.name, scl2::pipe::permissions(channel.preset));

    server.setPipeMode(scl2::pipe::mode::Message);

    if(!server.start()) {
        // The usual reason is another instance: start() claims the name, so a second server on
        // it fails instead of sharing it. That is worth spelling out, because the service
        // otherwise looks like it started and quietly serves nobody.
        logt.error() << "Failed to start the pipe server on " << channel.name << ": "
                     << platform::windows::TranslateLastError();
        logt.error() << "Another instance of this service is probably already listening, or a "
                        "debug run was left behind.";
        pipeListenerFailed = true;
        return 1;
    }

    while (!shouldStopPipeThread) {
        if (!server.waitForNextConnection(std::chrono::seconds(1))) {
            continue;   // the stop flag is checked at the top of the loop
        }

        logt.debug() << "Client connected.";

        auto client = server.queryNextConnection();

        if(client.valid()) {
            // Nothing a client can send is worth taking a SYSTEM service down for, so a
            // bad message costs this one connection and nothing else.
            try {
                ProcessClientRequest(client, channel.control);
            } catch (const std::exception& ex) {
                logt.error() << "Request handling failed: " << ex.what();
            } catch (...) {
                logt.error() << "Request handling failed with a non-standard exception.";
            }
        } else {
            logt.error() << "Failed to fetch client connection.";
        }

        // 断开连接
        client.close();
        logt.debug() << "Client disconnected";
    }

    logt.debug() << "Pipe listener thread exiting";
    return 0;
}

void MainServiceLoop() {
    LOGT_LOCAL("MainServiceLoop");
    logt.debug() << "Service main thread started";

    UpdateServiceStatus(SERVICE_RUNNING);

    if (allowUnelevatedRuleCallers) {
        logt.warn() << "This is a debug build: the control channel is created with the "
                       "Everyone descriptor and accepts unelevated rule callers, so that a "
                       "non-elevated GUI can be debugged against it. Do not install this "
                       "build as the service.";
    }

    shouldStopPipeThread = false;
    pipeListenerFailed = false;
    execPipeThread = CreateThread(nullptr, 0, PipeListenerThread, const_cast<PipeChannel*>(&execChannel), 0, nullptr);
    controlPipeThread = CreateThread(nullptr, 0, PipeListenerThread, const_cast<PipeChannel*>(&controlChannel), 0, nullptr);
    if (!execPipeThread || !controlPipeThread) {
        logt.error() << "Failed to create the pipe listener threads.";
        return;
    }
    
    // A listener that could not claim its name leaves the service with nothing to serve, so it
    // stops instead of staying up and looking healthy. The thread that failed has already said
    // why, in the log.
    while (WaitForSingleObject(serviceStopEvent, 1000) == WAIT_TIMEOUT) {
        if (pipeListenerFailed) {
            logt.error() << "A pipe listener could not start, stopping the service.";
            SetEvent(serviceStopEvent);
        }
    }

    shouldStopPipeThread = true;
    
    // 等待管道线程退出
    HANDLE threads[2] = {execPipeThread, controlPipeThread};
    for (HANDLE thread : threads) {
        if (!thread) continue;
        logt.info() << "Waiting for a pipe thread to finish...";
        WaitForSingleObject(thread, 5000);
        CloseHandle(thread);
    }
    execPipeThread = nullptr;
    controlPipeThread = nullptr;
    
    logt.info() << "Service main thread ended";
}


// Load the rules, and tell the user when they are not in effect.
//
// A database that cannot be read must not keep the service from starting: no rules is "ask
// the user about everything", which is the safe end of the scale. What it does need is
// saying out loud - the rules the user wrote are not in effect, and nothing else would tell
// them. That is what the notification is for; the service cannot show one from session 0,
// so AuthUI shows it where the user is.
void LoadApprovalRules(ApprovalEngine& engine)
{
    LOGT_LOCAL("LoadApprovalRules");

    bool loaded = false;

    try {
        loaded = engine.loadFile();
    } catch (const std::exception& ex) {
        logt.error() << "Exception while loading the approval rules: " << ex.what();
    }

    if (loaded) {
        return;
    }

    logt.error() << "Failed to load the approval rules, continuing with none.";

    authui::notify(L"AutoSudo：规则库未通过校验",
                   L"规则库无法读取或未通过完整性校验，已被移到 rules.db.invalid。"
                   L"服务现在对所有请求都会询问你的意见。");
}

VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    LOGT_LOCAL("ServiceMain");

    logt::claim("ServiceMain");

    // auth::authlist.load();

    ApprovalEngine engine; // Create engine instance

    LoadApprovalRules(engine);

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
    
    logt.debug() << "Service started successfully";
    
    // 主服务循环
    MainServiceLoop();
    
    // 清理
    CloseHandle(serviceStopEvent);
    // Manual save on service stop.
    if(!engine.save()) {
        logt.error() << "Failed to save approval rules while stopping service.";
    }

    serviceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);
    
    logt.debug() << "Service stopped";
    logt::shutdown();
}


int wmain(int argc, wchar_t** argv) {
    LOGT_LOCAL("wmain");

    logt::claim("ServiceMain");
    // 如果是控制台模式运行（调试用）
    if (argc > 1 && std::wstring(argv[1]) == L"--debug") {
        logt::addfile(platform::executable_dir()/"autosudo_service_debug.log", true);
        logt::stdcout(true, true); // Enable console logging
        // auth::authlist.load();
        wintoken::setNonServiceMode(true); // Prevent token from failing when not under session 0.

        logt::setFilterLevel(LogLevel::Debug);

        logt.debug() << "Running in debug mode";

        // The rule operations reach the engine through its single instance, which the
        // service entry point creates. A debug run goes through this branch instead, so it
        // has to create one too: without it, the first rule operation has nothing to talk
        // to, and reaching through a null instance is what the check in
        // ProcessRuleOperation exists for.
        ApprovalEngine engine;
        LoadApprovalRules(engine);
        
        serviceStopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        MainServiceLoop();
        CloseHandle(serviceStopEvent);
        
        logt::shutdown();
        return 0;
    } else {
        // 常规服务模式
        wintoken::setNonServiceMode(false);
        logt::addfile(platform::executable_dir()/"autosudo_service.log", true);

        // If debug flag file detected, set log level to debug.
        // This allows debugging in service mode.
        if(fs::exists(platform::executable_dir() / "debug.flag")) {
            logt::setFilterLevel(LogLevel::Debug);
        }
        
        // 服务模式
        wchar_t serviceName[] = L"AutoSudoService";
        SERVICE_TABLE_ENTRY serviceTable[] = {
            { serviceName, ServiceMain },
            { nullptr, nullptr }
        };
    
        if (!StartServiceCtrlDispatcher(serviceTable)) {
            logt::claim("AutoSudoService");
            logt::addfile(platform::executable_dir()/"autosudo_service_error.log", true);
            logt.error() << "StartServiceCtrlDispatcher failed: " << platform::windows::TranslateLastError();

            logt::shutdown();
            return 1;
        }
    }
}