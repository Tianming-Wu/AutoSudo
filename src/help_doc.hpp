#pragma once

#include <iostream>
#include <string>

void show_help() {
#ifdef AUTOSUDO_GUI
    MessageBox(nullptr, 
        L"用法: AutoSudoW [权限选项] <命令>\n\n"
        L"权限选项:\n"
        L"  --user    用户权限\n"  
        L"  --admin   管理员权限 (默认)\n"
        L"  --system  SYSTEM权限\n\n"
        L"示例:\n"
        L"  AutoSudoW notepad\n"
        L"  AutoSudoW --user cmd",
        L"AutoSudoW - 帮助", 
        MB_OK | MB_ICONINFORMATION
    );
#else
    std::wcout << L"用法: AutoSudo [权限选项] <命令>" << std::endl;
    std::wcout << L"权限选项:" << std::endl;
    std::wcout << L"  --user    用户权限" << std::endl;
    std::wcout << L"  --admin   管理员权限 (默认)" << std::endl;
    std::wcout << L"  --system  SYSTEM权限" << std::endl;
    std::wcout << L"示例:" << std::endl;
    std::wcout << L"  AutoSudo notepad" << std::endl;
    std::wcout << L"  AutoSudo --user cmd" << std::endl;
#endif
}