// #include <SharedCppLib2/platform_windows.hpp>
#include <windows.h>
#include <string>
#include <vector>

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

    // 如果是以非管理员权限启动，禁止继续执行。服务负责以管理员权限启动此程序，这是利用 UI 隔离的安全设计
    if (!IsUserAnAdmin()) {
        return cleanup(1);
    }

    // 解析命令行参数
    int argc;
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    if(argc < 2) { // 不带参数
        return cleanup(1);
    }

    AuthUIType uiType = getType(argv[1]);
    
    // std::wstring confirmType = argv[1];  // NOTFOUND, INSUFFICIENTLEVEL, HASHMISMATCH
    std::wstring authLevel = argv[2];    // USER, ADMIN, SYSTEM
    std::wstring programPath = argv[3];  // 程序路径

    // 构建确认消息
    std::wstring message;
    std::wstring title = L"AutoSudo 权限请求";

    switch(uiType) {
    case NoRuleMatched:
        message = L"没有规则匹配程序：\n\n"
                  L"程序: " + programPath + L"\n\n"
                  L"请求权限级别: " + authLevel + L"\n\n"
                  L"是否允许执行？";
        break;
    case InsufficientLevel:
        message = L"程序需要提升权限级别：\n\n"
                  L"程序: " + programPath + L"\n\n"
                  L"当前允许级别不足，请求提升至: " + authLevel + L"\n\n"
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