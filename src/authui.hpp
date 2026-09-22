/*
    Talking to AuthUI.exe.

    AuthUI is the part of AutoSudo that runs where the user is: the confirmation dialog, and
    the notifications. The service cannot do either itself - a dialog has to be in the
    session of the user it is asking, and a notification by definition belongs to a session,
    which session 0 does not have - so it starts AuthUI there and reads what it answered.

    Both entry points below start AuthUI with the administrator token on purpose. The
    confirmation dialog must not be answerable by a process running as the ordinary user -
    that is the whole point of asking an elevated process to ask the user - and AuthUI
    refuses to run without it.
*/

#pragma once

#include <string>

#include <windows.h>

#include "protocol.hpp"
#include "auth_ui.hpp"

namespace authui {

/// How long a confirmation dialog is given before it counts as a refusal.
inline constexpr unsigned long confirmationTimeoutMs = 10000;

/// Ask the user, in the session the request came from. The result is one of AuthUIResult.
int confirm(const AutoSudoRequest& context, AuthUIType type);

/// Tell the user something they did not ask for and have to know about: a rule database that
/// was refused, an execution that went through without asking. Shown in the session of the
/// console user, and nothing waits for them.
///
/// Returns whether AuthUI was started. A service cannot show a notification itself, so this
/// is it doing so on the service's behalf.
bool notify(const std::wstring& title, const std::wstring& body);

/// The same, in a session that is already known.
bool notify(DWORD sessionId, const std::wstring& title, const std::wstring& body);

} // namespace authui
