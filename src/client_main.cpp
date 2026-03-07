#include <windows.h>
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <array>

#include <wtsapi32.h>

#include <libpipe.hpp>

#include "protocol.hpp"
// #include "pipeclient.hpp"
#include "installer.hpp"

#include "broker_protocol.hpp"

#include <SharedCppLib2/logt.hpp>
#include <SharedCppLib2/stringlist.hpp>
#include <SharedCppLib2/arguments.hpp>

#include "help_doc.hpp"

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

int ExecuteCommand(const std::wstring& commandLine, AuthLevel authLevel = AuthLevel::Admin, bool deleteAuth = false) {
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

    // 设置认证级别和删除标志
    context.requestedAuthLevel = authLevel;
    context.deleteAuth = deleteAuth;

    // 配置 ConPTY 参数
    #ifndef AUTOSUDO_GUI
    context.inheritConsole = true; // 继承当前控制台
    
    // 设置控制台为 UTF-8 模式以正确显示 ConPTY 输出
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
    
    // 注意：不修改控制台模式标志，保持 Windows Terminal 的原有设置
    // Windows Terminal + PowerShell 7 已经正确配置了虚拟终端处理
    
    // 获取当前控制台窗口大小
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
        context.ConsoleX = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        context.ConsoleY = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
    } else {
        // 默认值
        context.ConsoleX = 80;
        context.ConsoleY = 25;
    }

    #endif

    // 获取当前会话ID
    context.sessionId = ::WTSGetActiveConsoleSessionId();
    context.useCurrentSession = true;

    libpipe::pipe_client client(R"(\\.\pipe\AutoSudoPipe)");

    if(!client.waitForConnection(std::chrono::seconds(1))) {
        logt.error() << "Failed to connect to AutoSudo service.";
        logt.error() << "Reason: " << platform::windows::TranslateLastError();
        #ifdef AUTOSUDO_GUI
        MessageBox(nullptr,
                  L"无法连接到 AutoSudo 服务。\n请确保服务已安装并正在运行。",
                  L"AutoSudo 连接错误",
                  MB_OK | MB_ICONERROR);
        #endif
        return 1;
    }

    logt.debug() << "Connected to AutoSudo service.";

    if (client.write(std::bytearray::fromStdWString(context.Serialize())) == 0) {
        logt.error() << "Failed to send command to AutoSudo service.";
        #ifdef AUTOSUDO_GUI
        MessageBox(nullptr,
                L"无法发送命令到 AutoSudo 服务。\n请联系开发者并提供日志。",
                L"AutoSudo 连接错误",
                MB_OK | MB_ICONERROR);
        #endif
        return 1;
    }

    if(!client.waitForReadyRead(std::chrono::seconds(30))) {
        if(client.broken()) {
            logt.error() << "Connection to service was broken.";
        } else {
            logt.warn() << "Wait for response from service timed out.";
        }
        return 1;
    }

    std::bytearray firstPacket = client.readAll();
    if(firstPacket.empty()) {
        logt.error() << "Empty response from service.";
        return 1;
    }

    std::wstring firstPacketW = firstPacket.toStdWString();
    if(firstPacketW.starts_with(L"SUCCESS:") || firstPacketW.starts_with(L"ERROR:")) {
        logt.info() << "Server response: " << firstPacketW;
        return firstPacketW.starts_with(L"SUCCESS:") ? 0 : 1;
    }

    #ifdef AUTOSUDO_GUI
    logt.error() << "GUI mode received broker handshake payload unexpectedly.";
    return 1;
    #else
    std::string token = firstPacket.toStdString();
    if(!client.waitForReadyRead(std::chrono::seconds(5))) {
        logt.error() << "Broker message pipe name was not returned by service.";
        return 1;
    }

    std::string brokerMsgPipe = client.readAll().toStdString();

    if(brokerMsgPipe.empty()) {
        logt.error() << "Received empty broker message pipe name.";
        return 1;
    }

    // 确认已接收到 broker 信息，防止服务端过早关闭
    client.acknowledge();

    libpipe::pipe_client brokerMsgClient(brokerMsgPipe);
    if(!brokerMsgClient.waitForConnection(std::chrono::seconds(5))) {
        logt.error() << "Failed to connect to broker message pipe: " << brokerMsgPipe;
        return 1;
    }

    logt.debug() << "Connected to broker message pipe.";

    if (brokerMsgClient.write(std::bytearray::fromStdWString(context.Serialize())) == 0) {
        logt.error() << "Failed to send ProcessContext to broker.";
        return 1;
    }

    if (!brokerMsgClient.waitForReadyRead(std::chrono::seconds(5))) {
        logt.error() << "Broker did not acknowledge context in time.";
        return 1;
    }

    BrokerResponse br = brokerMsgClient.readAll().convert_to<BrokerResponse>();
    if(br != BrokerResponse::Success) {
        logt.error() << "Broker rejected context, response code: " << static_cast<uint32_t>(br);
        return 1;
    }

    // 读取输入管道名称
    if (!brokerMsgClient.waitForReadyRead(std::chrono::seconds(5))) {
        logt.error() << "Broker did not provide input stream pipe name.";
        return 1;
    }

    std::string inputPipeName = brokerMsgClient.readAll().toStdString();
    if(inputPipeName.empty()) {
        logt.error() << "Broker provided empty input stream pipe name.";
        return 1;
    }

    // 读取输出管道名称
    if (!brokerMsgClient.waitForReadyRead(std::chrono::seconds(5))) {
        logt.error() << "Broker did not provide output stream pipe name.";
        return 1;
    }

    std::string outputPipeName = brokerMsgClient.readAll().toStdString();
    if(outputPipeName.empty()) {
        logt.error() << "Broker provided empty output stream pipe name.";
        return 1;
    }

    // 连接到输入管道（客户端写入，broker 读取）
    libpipe::pipe_client inputClient(inputPipeName);
    if(!inputClient.waitForConnection(std::chrono::seconds(5))) {
        logt.error() << "Failed to connect to broker input stream pipe: " << inputPipeName;
        return 1;
    }

    // 连接到输出管道（broker 写入，客户端读取）
    libpipe::pipe_client outputClient(outputPipeName);
    if(!outputClient.waitForConnection(std::chrono::seconds(5))) {
        logt.error() << "Failed to connect to broker output stream pipe: " << outputPipeName;
        return 1;
    }

    if (!brokerMsgClient.waitForReadyRead(std::chrono::seconds(10))) {
        logt.error() << "Broker did not send process start status.";
        return 1;
    }

    BrokerResponse startResponse = brokerMsgClient.readAll().convert_to<BrokerResponse>();
    if(startResponse != BrokerResponse::Success) {
        logt.error() << "Process start failed in broker, response code: " << static_cast<uint32_t>(startResponse);
        return 1;
    }

    logt.debug() << "ConPTY stream established.";

    std::atomic_bool running { true };
    std::atomic_int processExitCode { 1 };

    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);

    // 保存原始控制台模式
    DWORD originalInMode = 0, originalOutMode = 0;
    GetConsoleMode(hIn, &originalInMode);
    GetConsoleMode(hOut, &originalOutMode);

    // RAII 类确保控制台模式总是被恢复，即使程序崩溃
    struct ConsoleModeGuard {
        HANDLE hIn, hOut;
        DWORD originalInMode, originalOutMode;
        
        ConsoleModeGuard(HANDLE in, HANDLE out, DWORD inMode, DWORD outMode) 
            : hIn(in), hOut(out), originalInMode(inMode), originalOutMode(outMode) {}
        
        ~ConsoleModeGuard() {
            SetConsoleMode(hIn, originalInMode);
            SetConsoleMode(hOut, originalOutMode);
        }
    } consoleModeGuard(hIn, hOut, originalInMode, originalOutMode);

    // 设置为原始模式：禁用行缓冲、回显、处理和鼠标输入，但保留其他标志
    DWORD rawInMode = originalInMode;
    rawInMode &= ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT | ENABLE_MOUSE_INPUT | ENABLE_WINDOW_INPUT);
    rawInMode |= ENABLE_VIRTUAL_TERMINAL_INPUT;
    
    DWORD rawOutMode = originalOutMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
    
    SetConsoleMode(hIn, rawInMode);
    SetConsoleMode(hOut, rawOutMode);

    logt.debug() << "Console mode set: input=" << std::hex << rawInMode << " output=" << rawOutMode << std::dec;

    auto sendThread = std::thread([&]() {
        std::array<char, 4096> inputBuffer{};
        logt.debug() << "Input thread started.";
        while (running) {
            // 直接使用 ReadFile 读取标准输入（在原始模式下会立即返回可用数据）
            DWORD bytesRead = 0;
            if (ReadFile(hIn, inputBuffer.data(), DWORD(inputBuffer.size()), &bytesRead, nullptr)) {
                if (bytesRead > 0) {
                    logt.debug() << "Read " << bytesRead << " bytes from stdin.";
                    if (inputClient.write(std::bytearray(inputBuffer.data(), bytesRead)) == 0) {
                        logt.warn() << "Write to broker input stream failed.";
                        // 写入失败时检查连接是否断开
                        if (inputClient.broken()) {
                            logt.warn() << "Input stream pipe broken (input thread).";
                        }
                        running = false;
                        break;
                    }
                    logt.debug() << "Sent " << bytesRead << " bytes to broker.";
                }
            } else {
                DWORD err = GetLastError();
                if (err != ERROR_BROKEN_PIPE && running) {
                    logt.warn() << "Read stdin failed: " << platform::windows::TranslateError(err);
                }
                break;
            }
        }
        logt.debug() << "Input thread exiting.";
    });

    auto recvThread = std::thread([&]() {
        logt.debug() << "Output thread started.";
        while (running) {
            // 阻塞式读取，数据一到就返回，无轮询延迟
            std::bytearray output = outputClient.read(4096);
            if(output.empty()) {
                if (outputClient.broken()) {
                    logt.debug() << "Output stream pipe closed (output thread).";
                }
                break;
            }

            logt.debug() << "Received " << output.rawSize() << " bytes from broker, writing to stdout.";
            DWORD bytesWritten = 0;
            const void* dataPtr = output.rawData();
            const DWORD dataSize = static_cast<DWORD>(output.rawSize());
            
            if (!WriteFile(hOut, dataPtr, dataSize, &bytesWritten, nullptr)) {
                DWORD err = GetLastError();
                logt.error() << "WriteFile to stdout failed: " << platform::windows::TranslateError(err);
                break;
            }
            logt.debug() << "Wrote " << bytesWritten << " bytes to stdout.";
        }
        running = false;
        logt.debug() << "Output thread exiting.";
    });

    auto msgThread = std::thread([&]() {
        logt.debug() << "Control thread started.";
        while (running) {
            // 阻塞式读取控制消息
            std::bytearray msg = brokerMsgClient.readAll();
            if(msg.empty()) {
                if (brokerMsgClient.broken()) {
                    logt.debug() << "Broker message pipe closed (control thread).";
                }
                break;
            }

            logt.debug() << "Received control message of size " << msg.rawSize();
            if(msg.rawSize() == sizeof(uint32_t)) {
                processExitCode = static_cast<int>(msg.convert_to<uint32_t>());
                logt.debug() << "Received process exit code: " << processExitCode.load();
                break;
            }
        }
        running = false;
        logt.debug() << "Control thread exiting.";
    });

    msgThread.join();
    running = false;

    // 关闭管道以解除 recvThread 的阻塞式 read()
    inputClient.close();
    outputClient.close();
    brokerMsgClient.close();

    // 取消 sendThread 中阻塞的 ReadFile(hIn) 控制台读取
    CancelSynchronousIo(sendThread.native_handle());

    sendThread.join();
    recvThread.join();

    // 控制台模式由 RAII guard 自动恢复

    logt.info() << "Process exited with code: " << processExitCode.load();
    return processExitCode.load();
    #endif
}

// 主入口点
#ifdef AUTOSUDO_GUI
// GUI版本使用 wWinMain
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    int argc;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
#else
// 命令行版本使用 wmain  
int wmain(int argc, wchar_t** argv) {
#endif
    std::warguments args(argc, argv);


    // 初始化日志
    logt::claim("AutoSudo");
    LOGT_LOCAL("main");
    logt::addfile(platform::executable_dir()/"autosudo.log", true);

    // GUI 版本不需要命令行输出，不使用 stdcout
    // 修改：不再使用以保证输出被完全转移
// #ifndef AUTOSUDO_GUI
    // logt::stdcout(true, true);
// #endif
    
    int result = 0;
    
    if (args.empty()) {
        show_help();
        logt::exit(1);
    }

    if (args.addHelp(show_help)) {
        logt::exit(0);
    }

    if (args.addFlag(L"log-console")) {
        logt::stdcout(true, true);
    }

    AuthLevel authLevel = AuthLevel::Admin; // 默认管理员权限
    std::wstring commandLine;
    bool exec = true;
    bool deleteAuth = false;

    if(args.addFlag(L"debug")) {
        logt::setFilterLevel(LogLevel::Debug);
    }

    if (args.addFlag(L"user")) {
        authLevel = AuthLevel::User;
        commandLine = args.anyAfter(L"user");
    } else if (args.addFlag(L"system")) {
        authLevel = AuthLevel::System;
        commandLine = args.anyAfter(L"system");
    } else if (args.addFlag(L"admin")) {
        authLevel = AuthLevel::Admin;
        commandLine = args.anyAfter(L"admin");
    } else if (args.addFlag(L"delete")) {
        // --delete 标志，表示删除授权
        deleteAuth = true;
        commandLine = args.anyAfter(L"delete");
    }
    
    else if (args.addFlag(L"install")) {
        result = svc::InstallService() ? 0 : 1;
        exec = false;
    } else if (args.addFlag(L"uninstall")) {
        result = svc::UninstallService() ? 0 : 1;
        exec = false;
    } else if (args.addFlag(L"start")) {
        result = svc::_StartService() ? 0 : 1;
        exec = false;
    } else if (args.addFlag(L"stop")) {
        result = svc::_StopService() ? 0 : 1;
        exec = false;
    }

    // 执行命令模式
    if(exec) {
        if (commandLine.empty()) {
            std::wcout << L"Error: No command specified after permission flag" << std::endl;
            result = 1;
        } else {
            // 执行命令
            result = ExecuteCommand(commandLine, authLevel, deleteAuth);
        }
    }

#ifdef AUTOSUDO_GUI
    LocalFree(argv);
#endif
    
    // 清理并退出
    logt::shutdown();
    return result;
}