#pragma once

namespace svc {

bool InstallService();
bool UninstallService();

inline bool ReInstallService() {
    return UninstallService() && InstallService();
    // If uninstallservice() failed, installservice() natually doesn't execute, which is a feature of && operator.
}

bool _StartService();
bool _StopService();

}