// #include <SharedCppLib2/platform_windows.hpp>
#include <windows.h>
#include <string>
#include <vector>

#include <scf/scf_toast.hpp>

#include "auth_ui.hpp"

#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

LPWSTR* argv;
int cleanup(const int &ret) {
    LocalFree(argv);
    return ret;
}

AuthUIType getType(const std::wstring& typestr) {
    for(int w = 0; w != 2; w++) {
        if(typestr == AuthUITypeStr[w]) return static_cast<AuthUIType>(w);
    }
    return static_cast<AuthUIType>(2); // Invalid type, should not happen
}

bool IsUserAnAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;

    // Create a SID for the Administrators group.
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        return false;
    }

    // Check if the current token has the admin SID.
    if (!CheckTokenMembership(nullptr, adminGroup, &isAdmin)) {
        isAdmin = FALSE;
    }

    FreeSid(adminGroup);
    return isAdmin == TRUE;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    // 使用Per-Monitor V2 DPI感知（Windows 10 1703+）
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    // 解析命令行参数
    int argc;
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    if(argc < 2) { // 不带参数
        return cleanup(1);
    }

    // 通知模式：服务在 session 0，无法自己显示通知（通知属于某个会话），
    // 所以把这件事交给运行在用户会话里的我们。由 shell 绘制，不需要窗口。
    if (std::wstring(argv[1]) == L"--toast") {
        if (argc < 4) {
            return cleanup(1);
        }

        scf::claim_notifications(notificationAumid);

        // 未打包的应用只能通过带 AUMID 的开始菜单快捷方式向 shell 表明身份。
        //
        // 每次都重写，而不是"只建不存在的那一份"：一份 shell 没认下的快捷方式会一直躺在
        // 那儿，而重写会重新读一遍。写在 HKCU，不需要提权，只对当前用户生效。
        // register_notifications 会把 AUMID 读回来核对：SetValue/Commit 失败不会吭声，
        // 而没有 AUMID 的快捷方式看上去和正常的一模一样。
        if (!scf::register_notifications(notificationAumid, notificationDisplayName,
                                         notificationShortcutName, L"")) {
            MessageBoxW(nullptr,
                        L"无法向 Windows 注册通知身份：开始菜单快捷方式没写上 AUMID。\n"
                        L"通知会被系统默默丢弃。",
                        L"AutoSudo 通知不可用", MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
            return cleanup(1);
        }

        scf::notification notice;
        notice.title = argv[2];
        notice.body = argv[3];
        notice.tag = L"autosudo-notice";
        notice.group = L"autosudo";
        notice.stay_on_screen = true;   // 这类警告不该自己消失

        const bool shown = scf::show_notification(notificationAumid, notice);

        if (!shown) {
            // 没弹出来不能当作已经说过了：退回一个窗口提示，反正我们就是这个进程。
            MessageBoxW(nullptr, argv[3], argv[2], MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
        }

        return cleanup(shown ? 0 : 1);
    }

    // 以下是确认对话框，需要提权。
    //
    // 服务负责以管理员权限启动此程序，这是利用 UI 隔离的安全设计：非管理员进程不能让
    // 这个对话框替它按“是”。通知模式不需要这一步 —— 通知由 shell 绘制，它不做任何决定；
    // 而且未打包应用的 AUMID 本来就不绑定到具体二进制，同用户的任何进程都能用这个
    // AUMID 弹一条。拿提权去卡它只会让调试（Debug 构建的服务以普通用户跑）跑不起来。
    if (!IsUserAnAdmin()) {
        return cleanup(1);
    }

    AuthUIType uiType = getType(argv[1]);
    
    // std::wstring confirmType = argv[1];  // NOTFOUND, INSUFFICIENTLEVEL, HASHMISMATCH
    std::wstring authLevel = argv[2];    // USER, ADMIN, SYSTEM
    std::wstring programPath = argv[3];  // 程序路径

    // 发起进程：服务从连接对端的令牌里读出来的，不是请求里自称的（客户端无法伪造）。
    // 旧调用方不给这个参数，那时这一段为空。
    std::wstring callerLine;
    if (argc >= 5) {
        callerLine = L"\n\n发起进程: " + std::wstring(argv[4]);
    }

    // 构建确认消息
    std::wstring message;
    std::wstring title = L"AutoSudo 权限请求";

    switch(uiType) {
    case NoRuleMatched:
        message = L"没有规则匹配程序：\n\n"
                  L"程序: " + programPath + L"\n\n"
                  L"请求权限级别: " + authLevel + callerLine + L"\n\n"
                  L"是否允许执行？";
        break;
    case InsufficientLevel:
        message = L"程序需要提升权限级别：\n\n"
                  L"程序: " + programPath + L"\n\n"
                  L"当前允许级别不足，请求提升至: " + authLevel + callerLine + L"\n\n"
                  L"是否同意提升权限？";
        break;
    
    default:
        MessageBox(nullptr, L"未知的权限请求类型。", L"AutoSudo 错误", 
                  MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
        return cleanup(1);
    }
    
    // 设置对话框图标
    UINT iconType = MB_ICONQUESTION;
    int result = static_cast<int>(AuthUIResult::Deny); // 默认拒绝
    
    // if (uiType == ConfirmDeletion) {
    //     // ConfirmDeletion 使用三按钮对话框
    //     // MB_YESNOCANCEL: Yes(6), No(7), Cancel(2)
    //     int msgResult = MessageBox(nullptr, message.c_str(), title.c_str(), 
    //                                MB_YESNOCANCEL | iconType | MB_SYSTEMMODAL);
        
    //     switch(msgResult) {
    //         case IDYES:
    //             result = static_cast<int>(AuthUIResult::Delete);  // 2 - 删除
    //             break;
    //         case IDNO:
    //             result = static_cast<int>(AuthUIResult::Allow);   // 0 - 保留（允许通过）
    //             break;
    //         case IDCANCEL:
    //             result = static_cast<int>(AuthUIResult::Deny);    // 1 - 拒绝（取消）
    //             break;
    //     }
    // } else {
        // 其他类型使用两按钮对话框
        int msgResult = MessageBox(nullptr, message.c_str(), title.c_str(), 
                                   MB_YESNO | iconType | MB_SYSTEMMODAL);
        
        result = (msgResult == IDYES) ? static_cast<int>(AuthUIResult::Allow) 
                                      : static_cast<int>(AuthUIResult::Deny);
    // }

    return cleanup(result);
}