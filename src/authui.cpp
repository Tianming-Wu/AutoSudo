#include "authui.hpp"

#include "auth_ui.hpp"
#include "wintoken.hpp"

#include <SharedCppLib2/platform.hpp>
#include <SharedCppLib2/platform_windows.hpp>
#include <SharedCppLib2/logt.hpp>

#include <windows.h>
#include <wtsapi32.h>

#include <string>

LOGT_MODULE("authui");

namespace authui {

namespace {

// The name a permission level goes by in the dialog. A lookup with a fallback, not an index:
// PermissionLevel has more values than the three that have a name, and the array this used
// to index had exactly three entries.
const wchar_t* levelName(PermissionLevel level)
{
    switch(level) {
    case PermissionLevel::User:   return L"USER";
    case PermissionLevel::Admin:  return L"ADMIN";
    case PermissionLevel::System: return L"SYSTEM";
    default:                      return L"UNKNOWN";
    }
}

// The same for the kind of confirmation. This one is only ever called with a constant, and
// it stays a lookup for the same reason as the one above.
const wchar_t* authUITypeName(AuthUIType type)
{
    switch(type) {
    case AuthUIType::NoRuleMatched:     return L"NORULEMATCHED";
    case AuthUIType::InsufficientLevel: return L"INSUFFICIENTLEVEL";
    default:                            return L"NORULEMATCHED";
    }
}

// One argument of a command line AuthUI will parse with CommandLineToArgvW: wrapped in
// quotes, with the quotes inside it and the backslashes in front of them escaped. A path or
// a message can end with a backslash, which would otherwise swallow the closing quote.
std::wstring quoteArgument(const std::wstring& argument)
{
    std::wstring quoted = L"\"";

    size_t backslashes = 0;
    for (const wchar_t c : argument) {
        if (c == L'\\') {
            ++backslashes;
            continue;
        }

        if (c == L'"') {
            quoted.append(backslashes * 2 + 1, L'\\');
            quoted += L'"';
        } else {
            quoted.append(backslashes, L'\\');
            quoted += c;
        }

        backslashes = 0;
    }

    quoted.append(backslashes * 2, L'\\');
    quoted += L'"';
    return quoted;
}

// The token AuthUI is started with. It is the administrator one: the dialog has to outrank
// the process it is asking about, and AuthUI refuses to run as anything else.
//
// getAdminToken() reads the session and the user out of the request, so a request-shaped
// placeholder is used when all that is known is a session.
HANDLE adminTokenForSession(DWORD sessionId)
{
    AutoSudoRequest placeholder;    // only the session matters to the token lookup
    placeholder.targetSessionId = sessionId;
    return wintoken::getAdminToken(placeholder);
}

// Start AuthUI with that command line, in that session.
//
// waitForExit turns it into a question: the exit code is what AuthUI answered with, and a
// dialog that never answers is ended and counted as a refusal.
bool launchInSession(DWORD sessionId, const std::wstring& commandLine,
                     bool waitForExit, DWORD* exitCode)
{
    LOGT_LOCAL("launchInSession");

    STARTUPINFO startup = {0};
    startup.cb = sizeof(STARTUPINFO);

    PROCESS_INFORMATION process = {0};
    BOOL started = FALSE;

    if (wintoken::isNonServiceMode()) {
        // A debug run is not a service: there is no session 0 to move a token into, and the
        // process already runs as the user, so there is nothing to hand over either. AuthUI
        // is started the ordinary way - which also means the isolation a service gives the
        // dialog is not in place, and that is worth saying out loud rather than leaving it
        // to be discovered.
        logt.warn() << "Starting AuthUI without a token: this is a debug run, so the UI "
                       "isolation a service gets is not in place.";

        started = CreateProcessW(nullptr, const_cast<LPWSTR>(commandLine.c_str()),
                                 nullptr, nullptr, FALSE, 0, nullptr, nullptr,
                                 &startup, &process);
    } else {
        HANDLE token = adminTokenForSession(sessionId);
        if (token == nullptr) {
            logt.error() << "Failed to get an administrator token for session " << sessionId << ".";
            return false;
        }

        if (!SetTokenInformation(token, TokenSessionId, &sessionId, sizeof(sessionId))) {
            logt.error() << "SetTokenInformation failed: " << platform::windows::TranslateLastError();
            CloseHandle(token);
            return false;
        }

        started = CreateProcessAsUser(token, nullptr, const_cast<LPWSTR>(commandLine.c_str()),
                                      nullptr, nullptr, FALSE, 0, nullptr, nullptr,
                                      &startup, &process);
        CloseHandle(token);
    }

    if (!started) {
        logt.error() << "Failed to start AuthUI: " << platform::windows::TranslateLastError();
        return false;
    }

    if (waitForExit) {
        if (WaitForSingleObject(process.hProcess, confirmationTimeoutMs) == WAIT_TIMEOUT) {
            // A dialog nobody answers is not a yes.
            logt.warn() << "The confirmation UI did not answer in time, ending it.";
            TerminateProcess(process.hProcess, 1);
            WaitForSingleObject(process.hProcess, 1000);
        }

        DWORD code = static_cast<DWORD>(AuthUIResult::Deny);
        GetExitCodeProcess(process.hProcess, &code);
        if (exitCode != nullptr) {
            *exitCode = code;
        }
    }

    CloseHandle(process.hProcess);
    CloseHandle(process.hThread);
    return true;
}

} // namespace

int confirm(const AutoSudoRequest& context, AuthUIType type)
{
    LOGT_LOCAL("confirm");

    const std::wstring commandLine = (platform::executable_dir() / L"AuthUI.exe").wstring()
        + L" " + authUITypeName(type)
        + L" " + levelName(context.requestedPermissionLevel)
        + L" " + quoteArgument(context.executableFullPath);

    logt.debug() << "Auth UI command: " << commandLine;

    DWORD exitCode = static_cast<DWORD>(AuthUIResult::Deny);
    if (!launchInSession(context.targetSessionId, commandLine, true, &exitCode)) {
        return static_cast<int>(AuthUIResult::Deny);
    }

    logt.info() << "Confirmation UI result: " << exitCode;
    return static_cast<int>(exitCode);
}

bool notify(const std::wstring& title, const std::wstring& body)
{
    const DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId == 0xFFFFFFFF) {
        logt.warn() << "There is no console session to notify, dropping: " << title;
        return false;
    }

    return notify(sessionId, title, body);
}

bool notify(DWORD sessionId, const std::wstring& title, const std::wstring& body)
{
    LOGT_LOCAL("notify");

    // Notifications belong to a session, and the service runs in session 0, which has none -
    // so AuthUI shows it where the user is. Nothing waits: the notification outlives both
    // processes.
    const std::wstring commandLine = (platform::executable_dir() / L"AuthUI.exe").wstring()
        + L" --toast " + quoteArgument(title) + L" " + quoteArgument(body);

    logt.debug() << "Notification command: " << commandLine;

    return launchInSession(sessionId, commandLine, false, nullptr);
}

} // namespace authui
