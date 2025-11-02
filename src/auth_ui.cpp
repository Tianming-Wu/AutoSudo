#include <windows.h>
#include <string>
#include <vector>

#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    // 使用Per-Monitor V2 DPI感知（Windows 10 1703+）
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    // 解析命令行参数
    int argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    
    if (argc < 4) {
        MessageBox(nullptr,
                  L"参数错误：缺少必要的参数\n\n"
                  L"请联系开发者并附带日志autosudo_service.log。", 
                  L"AutoSudo AuthUI - 错误", 
                  MB_OK | MB_ICONERROR);
        LocalFree(argv);
        return 1;
    }
    
    std::wstring confirmType = argv[1];  // NOTFOUND, INSUFFICIENTLEVEL, HASHMISMATCH
    std::wstring authLevel = argv[2];    // USER, ADMIN, SYSTEM
    std::wstring programPath = argv[3];  // 程序路径
    
    // 构建确认消息
    std::wstring message;
    std::wstring title = L"AutoSudo 权限请求";
    
    if (confirmType == L"NOTFOUND") {
        message = L"以下程序不在允许列表中：\n\n"
                  L"程序: " + programPath + L"\n\n"
                  L"请求权限级别: " + authLevel + L"\n\n"
                  L"是否允许执行？";
    }
    else if (confirmType == L"INSUFFICIENTLEVEL") {
        message = L"程序需要提升权限级别：\n\n"
                  L"程序: " + programPath + L"\n\n"
                  L"当前允许级别不足，请求提升至: " + authLevel + L"\n\n"
                  L"是否同意提升权限？";
    }
    else if (confirmType == L"HASHMISMATCH") {
        message = L"文件完整性验证失败：\n\n"
                  L"程序: " + programPath + L"\n\n"
                  L"请求权限级别: " + authLevel + L"\n\n"
                  L"文件已被修改，可能与原始版本不同。\n"
                  L"出于安全考虑，执行已被阻止。\n\n"
                  L"如需执行，请从允许列表中移除后重新添加。";
                  
        // 哈希不匹配时显示错误对话框，不允许继续
        MessageBox(nullptr, message.c_str(), title.c_str(), 
                  MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
        LocalFree(argv);
        return 1;
    }
    else {
        message = L"未知的确认类型：\n\n"
                  L"程序: " + programPath + L"\n\n"
                  L"请求权限级别: " + authLevel + L"\n\n"
                  L"是否允许执行？";
    }
    
    // 设置对话框图标
    UINT iconType = MB_ICONQUESTION;
    if (confirmType == L"HASHMISMATCH") {
        iconType = MB_ICONWARNING;
    }
    
    // 显示确认对话框
    int result = MessageBox(nullptr, message.c_str(), title.c_str(), 
                           MB_YESNO | iconType | MB_SYSTEMMODAL);
    
    LocalFree(argv);
    return (result == IDYES) ? 0 : 1;
}