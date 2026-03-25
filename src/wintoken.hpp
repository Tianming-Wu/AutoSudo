/*
    Token module for AutoSudo project.

    To be clear, this is not a message validation module, and it only
    deals with the process elevation tokens. Only works when the
    process is running in a service environment (Session 0). In
    non-service environments, it always fails and fallback.

*/

#pragma once

#include <SharedCppLib2/platform_windows.hpp>
#include <SharedCppLib2/logt.hpp>

#include "protocol.hpp"
#include "defs.hpp"

namespace wintoken {

void setNonServiceMode(bool enabled);
bool isNonServiceMode();

HANDLE getSystemToken(const AutoSudoRequest& request);
HANDLE getUserToken(const AutoSudoRequest& request);
HANDLE getAdminToken(const AutoSudoRequest& request);

HANDLE getToken(PermissionLevel level, const AutoSudoRequest& request);

} // namespace token