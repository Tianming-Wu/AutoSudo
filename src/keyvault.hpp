/*
    The secret the rule database is authenticated with.

    The rules decide what may run without asking the user, so whoever can change
    that file can change which requests pass. The file is authenticated with an
    HMAC, and this is where the key for it comes from.

    It is a key and not a password: nothing human types it, so it is 32 random
    bytes, kept in a file next to the service, protected with DPAPI in the machine
    scope, in a file that is created with a descriptor leaving it to SYSTEM and
    Administrators.

    What that buys is a local process that is not an administrator: it can write
    the database, but it cannot recompute the check over what it wrote. An
    administrator can replace the key and the database together, and no scheme
    that has to work unattended can prevent that - the key has to be on the machine
    that reads it.

    acquire() is an interface on purpose. Where the key comes from can change - a
    key held by a TPM, or an LSA secret - without the database noticing.
*/

#pragma once

#include <filesystem>

#include <SharedCppLib2/bytearray.hpp>

namespace keyvault {

/// The key for the rule database, created on first use.
///
/// Throws std::runtime_error when the key cannot be read or created. That is deliberate: a
/// caller that cannot get the key cannot check the database either, and finding out here
/// beats carrying on with something that is no longer verified.
scl2::secure_bytearray acquire(const std::filesystem::path& keyPath);

} // namespace keyvault
