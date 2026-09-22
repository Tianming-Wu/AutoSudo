#include "callerid.hpp"

#include <SharedCppLib2/platform.hpp>
#include <SharedCppLib2/platform_windows.hpp>
#include <SharedCppLib2/string.hpp>
#include <SharedCppLib2/logt.hpp>

#include <windows.h>
#include <sddl.h>

#include <vector>

// Logging is claimed per function, with LOGT_LOCAL naming it in full. A file-wide LOGT_MODULE
// signature was used here until it turned out that lines written through it never reached the
// log - the worst possible property for the code that has to report why a caller was refused.

namespace callerid {

namespace {

std::string toUtf8(const std::wstring& text)
{
    return scl2::wstr_to_str(text);
}

std::string sidToString(PSID sid)
{
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(sid, &text)) {
        return {};
    }

    std::string result = toUtf8(text);
    LocalFree(text);
    return result;
}

// The attributes the token gives a well-known group, or 0 when the token does not hold it.
//
// CheckTokenMembership(nullptr, ...) was used here, and it answered "not a member" for a token
// whose group list holds Administrators enabled and not deny-only - the elevated administrator
// this function exists to recognise. So the group list is read directly instead: the attribute is
// the whole answer, and it is also where the difference that matters lives. An administrator who
// did not go through UAC holds the group with SE_GROUP_USE_FOR_DENY_ONLY, and only the other one
// may change rules.
DWORD tokenGroupAttributes(HANDLE token, WELL_KNOWN_SID_TYPE type)
{
    BYTE sidBuffer[SECURITY_MAX_SID_SIZE];
    DWORD sidSize = sizeof(sidBuffer);
    if (!CreateWellKnownSid(type, nullptr, sidBuffer, &sidSize)) {
        return 0;
    }

    DWORD size = 0;
    GetTokenInformation(token, TokenGroups, nullptr, 0, &size);
    if (size == 0) {
        return 0;
    }

    std::vector<std::byte> buffer(size);
    if (!GetTokenInformation(token, TokenGroups, buffer.data(), size, &size)) {
        return 0;
    }

    const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(buffer.data());
    for (DWORD i = 0; i < groups->GroupCount; ++i) {
        if (EqualSid(groups->Groups[i].Sid, sidBuffer)) {
            return groups->Groups[i].Attributes;
        }
    }

    return 0;
}

bool tokenInGroup(HANDLE token, WELL_KNOWN_SID_TYPE type)
{
    const DWORD attributes = tokenGroupAttributes(token, type);
    return (attributes & SE_GROUP_ENABLED) != 0
        && (attributes & SE_GROUP_USE_FOR_DENY_ONLY) == 0;
}

std::wstring queryImagePath(DWORD processId)
{
    if (processId == 0) {
        return {};
    }

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (process == nullptr) {
        return {};
    }

    wchar_t buffer[MAX_PATH * 2] = {0};
    DWORD size = static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0]));

    std::wstring path;
    if (QueryFullProcessImageNameW(process, 0, buffer, &size)) {
        path.assign(buffer, size);
    }

    CloseHandle(process);
    return path;
}

} // namespace

std::string CallerInfo::describe() const
{
    if (!identified) {
        return "unidentified caller";
    }

    std::string text = "pid " + std::to_string(processId);
    if (!imagePath.empty()) {
        text += " (" + imagePath + ")";
    }
    text += ", session " + std::to_string(sessionId);
    text += ", user " + (userName.empty() ? userSid : userName);
    if (!userName.empty() && !userSid.empty()) {
        text += " (" + userSid + ")";
    }
    text += isSystem ? ", SYSTEM" : (elevated ? ", elevated" : ", not elevated");
    return text;
}

CallerInfo identify(void* nativeHandle)
{
    LOGT_LOCAL("callerid::identify");

    CallerInfo info;

    HANDLE pipe = static_cast<HANDLE>(nativeHandle);
    if (pipe == nullptr || pipe == INVALID_HANDLE_VALUE) {
        logt.error() << "callerid::identify: no pipe handle to inspect.";
        return info;
    }

    // Read for the log. The answer that decides anything is the token read below.
    DWORD processId = 0;
    if (GetNamedPipeClientProcessId(pipe, &processId)) {
        info.processId = processId;
    }

    if (!ImpersonateNamedPipeClient(pipe)) {
        logt.warn() << "callerid::identify: ImpersonateNamedPipeClient failed: "
                    << platform::windows::TranslateLastError();
        return info;
    }

    // From here on this thread acts as the peer, so every way out must revert.

    HANDLE token = nullptr;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        logt.warn() << "callerid::identify: OpenThreadToken failed: "
                    << platform::windows::TranslateLastError();
        RevertToSelf();
        return info;
    }

    info.identified = true;
    info.elevated = tokenInGroup(token, WinBuiltinAdministratorsSid);

    DWORD returned = 0;
    DWORD sessionId = 0;
    if (GetTokenInformation(token, TokenSessionId, &sessionId, sizeof(sessionId), &returned)) {
        info.sessionId = sessionId;
    }

    DWORD userSize = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &userSize);
    if (userSize > 0) {
        std::vector<std::byte> userBuffer(userSize);
        if (GetTokenInformation(token, TokenUser, userBuffer.data(), userSize, &returned)) {
            const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(userBuffer.data());
            info.userSid = sidToString(tokenUser->User.Sid);
            info.isSystem = (info.userSid == "S-1-5-18");

            // A domain name can be longer than DNLEN, so both buffers are the size the
            // longest account or domain name can be.
            wchar_t name[256] = {0};
            wchar_t domain[256] = {0};
            DWORD nameSize = static_cast<DWORD>(sizeof(name) / sizeof(name[0]));
            DWORD domainSize = static_cast<DWORD>(sizeof(domain) / sizeof(domain[0]));
            SID_NAME_USE use = SidTypeUnknown;
            if (LookupAccountSidW(nullptr, tokenUser->User.Sid, name, &nameSize,
                                  domain, &domainSize, &use)) {
                info.userName = toUtf8(std::wstring(domain) + L"\\" + name);
            }
        }
    }

    CloseHandle(token);
    RevertToSelf();

    // Read after reverting: the peer's own rights do not necessarily reach its own
    // process object, the service's do.
    info.imagePath = toUtf8(queryImagePath(info.processId));

    return info;
}

} // namespace callerid
