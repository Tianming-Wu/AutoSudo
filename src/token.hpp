#pragma once

#include <windows.h>
#include <SharedCppLib2/logt.hpp>

#include "protocol.hpp"

namespace token {

HANDLE getSystemToken(const ProcessContext& context);
HANDLE getUserToken(const ProcessContext& context);
HANDLE getAdminToken(const ProcessContext& context);

} // namespace token