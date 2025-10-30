#include "token.hpp"

#include <userenv.h>
#include <wtsapi32.h>
#include <SharedCppLib2/platform.hpp>

namespace token {

LOGT_MODULE("token");

HANDLE getSystemToken(const ProcessContext& context) {
    HANDLE systemToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &systemToken)) {
        logt.error() << "OpenProcessToken failed: " << platform::windows::TranslateLastError();
        return nullptr;
    }

    HANDLE duplicatedToken = nullptr;
    if (!DuplicateTokenEx(systemToken, TOKEN_ALL_ACCESS, nullptr, 
                         SecurityImpersonation, TokenPrimary, &duplicatedToken)) {
        logt.error() << "DuplicateTokenEx failed: " << platform::windows::TranslateLastError();
        CloseHandle(systemToken);
        return nullptr;
    }

    CloseHandle(systemToken);
    return duplicatedToken;
}

HANDLE getUserToken(const ProcessContext& context) {
    HANDLE userToken = nullptr;
    if (!WTSQueryUserToken(context.sessionId, &userToken)) {
        logt.error() << "WTSQueryUserToken failed: " << GetLastError();
        return nullptr;
    }
    return userToken;
}

HANDLE getAdminToken(const ProcessContext& context) {
    HANDLE userToken = getUserToken(context);

    HANDLE elevatedToken = nullptr;
    if (!DuplicateTokenEx(userToken, TOKEN_ALL_ACCESS, nullptr, 
                         SecurityImpersonation, TokenPrimary, &elevatedToken)) {
        logt.error() << "DuplicateTokenEx failed: " << GetLastError();
        CloseHandle(userToken);
        return nullptr;
    }

    TOKEN_ELEVATION_TYPE elevationType;
    DWORD size;
    if (GetTokenInformation(elevatedToken, TokenElevationType, &elevationType, 
                          sizeof(elevationType), &size)) {
        if (elevationType == TokenElevationTypeLimited) {
            // 令牌是受限的，需要获取链接令牌（管理员权限）
            HANDLE linkedToken = nullptr;
            DWORD linkedSize;
            if (GetTokenInformation(elevatedToken, TokenLinkedToken, &linkedToken, 
                                  sizeof(linkedToken), &linkedSize)) {
                CloseHandle(elevatedToken);
                elevatedToken = linkedToken;
            }
        }
    }

    CloseHandle(userToken);

    return elevatedToken;
}

} // namespace token