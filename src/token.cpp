#include "token.hpp"

#include <userenv.h>
#include <wtsapi32.h>
#include <SharedCppLib2/platform.hpp>

namespace token {

namespace {
bool g_nonServiceMode = false;

HANDLE duplicateCurrentProcessToken() {
    HANDLE processToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &processToken)) {
        return nullptr;
    }

    HANDLE duplicatedToken = nullptr;
    if (!DuplicateTokenEx(processToken, TOKEN_ALL_ACCESS, nullptr,
                          SecurityImpersonation, TokenPrimary, &duplicatedToken)) {
        CloseHandle(processToken);
        return nullptr;
    }

    CloseHandle(processToken);
    return duplicatedToken;
}
}

void setNonServiceMode(bool enabled) {
    g_nonServiceMode = enabled;
}

bool isNonServiceMode() {
    return g_nonServiceMode;
}

HANDLE getSystemToken(const ProcessContext& context) {
    LOGT_LOCAL("getSystemToken");

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
    LOGT_LOCAL("getUserToken");

    HANDLE userToken = nullptr;
    if (!WTSQueryUserToken(context.sessionId, &userToken)) {
        if (!g_nonServiceMode) {
            logt.error() << "WTSQueryUserToken failed: " << platform::windows::TranslateLastError();
            return nullptr;
        }

        logt.warn() << "WTSQueryUserToken failed in non-service mode, falling back to current process token.";
        userToken = duplicateCurrentProcessToken();
        if (userToken == nullptr) {
            logt.error() << "Fallback token acquisition failed in non-service mode.";
            return nullptr;
        }
    }

    return userToken;
}

HANDLE getAdminToken(const ProcessContext& context) {
    LOGT_LOCAL("getAdminToken");

    HANDLE userToken = getUserToken(context);
    if (userToken == nullptr) {
        logt.error() << "getUserToken failed while acquiring admin token.";
        return nullptr;
    }

    HANDLE elevatedToken = nullptr;
    if (!DuplicateTokenEx(userToken, TOKEN_ALL_ACCESS, nullptr, 
                         SecurityImpersonation, TokenPrimary, &elevatedToken)) {
        logt.error() << "DuplicateTokenEx failed: " << platform::windows::TranslateLastError();
        CloseHandle(userToken);
        return nullptr;
    }

    TOKEN_ELEVATION_TYPE elevationType;
    DWORD size;
    if (GetTokenInformation(elevatedToken, TokenElevationType, &elevationType, 
                          sizeof(elevationType), &size)) {
        if (elevationType == TokenElevationTypeLimited) {
            // 令牌是受限的，需要获取链接令牌（管理员权限）
            // 注意，这一步如果不在服务环境（Session 0）运行，一定会失败
            // 这个行为不影响部署环境，只影响 non-service 测试环境，所以不做处理
            logt.debug() << "Token is limited, trying to get linked elevated token.";
            HANDLE linkedToken = nullptr;
            DWORD linkedSize;
            if (GetTokenInformation(elevatedToken, TokenLinkedToken, &linkedToken, 
                                  sizeof(linkedToken), &linkedSize)) {
                CloseHandle(elevatedToken);
                elevatedToken = linkedToken;
            } else {
                logt.error() << "GetTokenInformation for linked token failed: " << platform::windows::TranslateLastError();
                CloseHandle(elevatedToken);
                elevatedToken = nullptr;
            }
        }
    }

    CloseHandle(userToken);

    return elevatedToken;
}

} // namespace token