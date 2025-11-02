#include <windows.h>
#include <iostream>

#include <SharedCppLib2/logt.hpp>
#include <SharedCppLib2/platform.hpp>

namespace svc {

LOGT_MODULE("ServiceInstaller");

bool InstallService() {
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        logt.error() << "OpenSCManager failed: " << platform::windows::TranslateLastError();
        return false;
    }
    
    wchar_t modulePath[MAX_PATH];
    GetModuleFileName(nullptr, modulePath, MAX_PATH);

    std::wstring servicePath = modulePath;
    size_t lastSlash = servicePath.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        // 获取当前目录，然后指向服务端程序
        std::wstring currentDir = servicePath.substr(0, lastSlash + 1);
        servicePath = currentDir + L"AutoSudoSvc.exe";
        
        logt.info() << "Installing service from: " << servicePath;
    } else {
        logt.error() << "Failed to extract directory from module path";
        CloseServiceHandle(scm);
        return false;
    }

    DWORD fileAttr = GetFileAttributes(servicePath.c_str());
    if (fileAttr == INVALID_FILE_ATTRIBUTES) {
        logt.error() << "Service executable not found: " << servicePath;
        CloseServiceHandle(scm);
        return false;
    }
    
    SC_HANDLE service = CreateService(
        scm,
        L"AutoSudoService",
        L"Auto Sudo Service",
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
        SERVICE_AUTO_START, // 自动启动
        SERVICE_ERROR_NORMAL,
        servicePath.c_str(),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    );

    // 设置服务描述
    if (service) {
        SERVICE_DESCRIPTION sd = {0};
        WCHAR descp[] = L"Provides sudo-like privilege elevation for Windows applications";
        sd.lpDescription = descp;
        
        ChangeServiceConfig2(
            service,
            SERVICE_CONFIG_DESCRIPTION,
            &sd
        );
    } else {
        logt.error() << "CreateService failed: " << platform::windows::TranslateLastError();
        CloseHandle(scm);
        return false;
    }
    
    logt.info() << "Service installed successfully!";
#ifdef AUTOSUDO_GUI
    MessageBox(nullptr,
               L"服务安装成功！\n\n"
               L"您可以在服务管理器中启动“Auto Sudo Service”服务，"
               L"或者重启计算机以自动启动该服务。",
               L"安装成功",
               MB_OK | MB_ICONINFORMATION);
#else
    std::cout << "Service installed successfully!" << std::endl;
#endif
    
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}

bool UninstallService() {
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        return false;
    }
    
    SC_HANDLE service = OpenService(scm, L"AutoSudoService", DELETE);
    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }
    
    bool success = DeleteService(service);
    
    logt.info() << "Service uninstalled successfully!";

#ifdef AUTOSUDO_GUI
    MessageBox(nullptr,
               L"服务卸载成功！",
               L"卸载成功",
               MB_OK | MB_ICONINFORMATION);
#else
    std::cout << "Service uninstalled successfully!" << std::endl;
#endif

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return success;
}

bool _StartService() {
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        logt.error() << "OpenSCManager failed: " << platform::windows::TranslateLastError();
        return false;
    }
    
    SC_HANDLE service = OpenService(scm, L"AutoSudoService", SERVICE_START);
    if (!service) {
        logt.error() << "OpenService failed: " << platform::windows::TranslateLastError();
        CloseServiceHandle(scm);
        return false;
    }
    
    bool success = ::StartService(service, 0, nullptr);
    if (success) {
        logt.info() << "Service started successfully!";
    } else {
        logt.error() << "StartService failed: " << platform::windows::TranslateLastError();
    }

    logt.info() << "Service started successfully!";

#ifdef AUTOSUDO_GUI
    MessageBox(nullptr,
               L"服务启动成功！",
               L"启动成功",
               MB_OK | MB_ICONINFORMATION);
#else
    std::cout << "Service started successfully!" << std::endl;
#endif
    
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return success;
}

bool _StopService() {
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        logt.error() << "OpenSCManager failed: " << platform::windows::TranslateLastError();
        return false;
    }
    
    SC_HANDLE service = OpenService(scm, L"AutoSudoService", SERVICE_STOP);
    if (!service) {
        logt.error() << "OpenService failed: " << platform::windows::TranslateLastError();
        CloseServiceHandle(scm);
        return false;
    }
    
    SERVICE_STATUS status;
    bool success = ControlService(service, SERVICE_CONTROL_STOP, &status);
    if (success) {
        logt.info() << "Service stopped successfully!";
    } else {
        logt.error() << "ControlService failed: " << platform::windows::TranslateLastError();
    }

    logt.info() << "Service stopped successfully!";

#ifdef AUTOSUDO_GUI
    MessageBox(nullptr,
               L"服务停止成功！",
               L"停止成功",
               MB_OK | MB_ICONINFORMATION);
#else
    std::cout << "Service stopped successfully!" << std::endl;
#endif
    
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return success;
}

}