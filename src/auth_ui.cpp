#include <windows.h>
#include <string>
#include <vector>

#include "auth_ui.hpp"

LPWSTR* argv;
int cleanup(const int &ret) {
    LocalFree(argv);
    return ret;
}

AuthUIType getType(const std::wstring& typestr) {
    for(int w = AuthUIType::ConfirmNew; w != AuthUIType::_sizetag; w++) {
        if(typestr == AuthUITypeStr[w]) return static_cast<AuthUIType>(w);
    }
    return AuthUIType::_sizetag;
}

#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    // 使用Per-Monitor V2 DPI感知（Windows 10 1703+）
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

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
    case ConfirmNew:
        message = L"以下程序不在允许列表中：\n\n"
                  L"程序: " + programPath + L"\n\n"
                  L"请求权限级别: " + authLevel + L"\n\n"
                  L"是否允许执行？";
        break;
    case ConfirmRaise:
        message = L"程序需要提升权限级别：\n\n"
                  L"程序: " + programPath + L"\n\n"
                  L"当前允许级别不足，请求提升至: " + authLevel + L"\n\n"
                  L"是否同意提升权限？";
        break;
    case ConfirmHashRebuild:
        message = L"文件完整性验证失败：\n\n"
                  L"程序: " + programPath + L"\n\n"
                  L"请求权限级别: " + authLevel + L"\n\n"
                  L"文件已被修改，是否允许执行更新后的程序？\n";
        break;
    case ConfirmDeletion:
        title = L"AutoSudo 删除确认";
        message = L"用户手动阻止请求通过：\n\n"
                  L"程序: " + programPath + L"\n\n"
                  L"请求权限级别: " + authLevel + L"\n\n"
                  L"是否删除授权？\n";
        break;
    
    default:
        MessageBox(nullptr, L"未知的权限请求类型。", L"AutoSudo 错误", 
                  MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
        return cleanup(1);
    }
    
    // 设置对话框图标
    UINT iconType = MB_ICONQUESTION;
    
    // 显示确认对话框
    int result = MessageBox(nullptr, message.c_str(), title.c_str(), 
                           MB_YESNO | iconType | MB_SYSTEMMODAL);

    return cleanup((result == IDYES) ? 0 : 1);
}