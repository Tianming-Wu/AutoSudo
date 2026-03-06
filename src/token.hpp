#pragma once

#include <SharedCppLib2/platform_windows.hpp>
#include <SharedCppLib2/logt.hpp>

#include "protocol.hpp"

namespace token {

void setNonServiceMode(bool enabled);
bool isNonServiceMode();

HANDLE getSystemToken(const ProcessContext& context);
HANDLE getUserToken(const ProcessContext& context);
HANDLE getAdminToken(const ProcessContext& context);

} // namespace token