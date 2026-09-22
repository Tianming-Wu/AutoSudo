/*
    Who is on the other end of a pipe connection.

    On the execution channel any local process may be the client - that is what
    the product is for - so asking a client to prove who it is has no meaning.
    What has meaning is finding out: the kernel attaches the peer's token to the
    connection, and the client has no say in it.

    The token is read by impersonating the connection and asking for the thread's
    token, which ties the answer to this connection instead of to a process id
    that could be reused by the time anyone looks at it. The process id is read
    as well, for the log.

    Only the service can do this: it runs as SYSTEM, which holds
    SeImpersonatePrivilege.
*/

#pragma once

#include <cstdint>
#include <string>

namespace callerid {

struct CallerInfo {
    bool identified = false;    // whether the peer's token could be read at all
    bool elevated = false;      // the token holds an Administrators SID it may use
    bool isSystem = false;      // the token's user is LocalSystem
    uint32_t sessionId = 0xFFFFFFFF;
    uint32_t processId = 0;     // for the log: a pid can be reused, a token cannot
    std::string userSid;        // S-1-5-..., empty when it could not be read
    std::string userName;       // DOMAIN\user, best effort
    std::string imagePath;      // the peer's image, best effort

    /// Whether this caller may touch the approval rules.
    bool isPrivileged() const { return identified && (elevated || isSystem); }

    /// One line for the log.
    std::string describe() const;
};

/// Identify the process on the other end of a connected pipe.
/// nativeHandle is server_client::nativeHandle() of a connected instance.
CallerInfo identify(void* nativeHandle);

} // namespace callerid
