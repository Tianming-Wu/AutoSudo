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
#include "callerid.hpp"

namespace authui {

/// How long a confirmation dialog is given before it counts as a refusal.
inline constexpr unsigned long confirmationTimeoutMs = 10000;

/// Ask the user, in the session the request came from. The result is one of AuthUIResult.
///
/// `caller` is what the service read off the other end of the connection. It goes into the
/// dialog because the user is being asked to trust a program, and a dialog that names only
/// the program cannot answer "who wants this" - which is the question that decides it.
/// Null when there is nobody to name.
int confirm(const AutoSudoRequest& context, AuthUIType type,
            const callerid::CallerInfo* caller = nullptr);

/// Tell the user that a request went through without asking them: a rule allowed it, and no
/// dialog appeared. This is the one outcome they have no other way of hearing about, because
/// the process is already starting by the time anyone could look.
///
/// A refusal is deliberately not notified: whoever asked for it is already being told, and
/// turning refusals into notifications would let any local process put text on the user's
/// screen just by asking for something that will be denied.
bool notifyAutoApproved(const std::wstring& executable, PermissionLevel level,
                        const callerid::CallerInfo& caller);

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
