#include "keyvault.hpp"

#include "buildflags.hpp"

#include <SharedCppLib2/platform.hpp>
#include <SharedCppLib2/platform_windows.hpp>
#include <SharedCppLib2/string.hpp>
#include <SharedCppLib2/logt.hpp>

#include <windows.h>
#include <dpapi.h>
#include <bcrypt.h>
#include <sddl.h>

#include <stdexcept>
#include <string>

// Logging is claimed per function, with LOGT_LOCAL naming it in full. A file-wide signature is
// constructed before main adds the channels, which is how it loses them.

namespace keyvault {

namespace {

constexpr size_t kKeyBytes = 32;

// Mixed into the DPAPI blob, so that a blob written by another application on this machine
// cannot be dropped in as ours.
constexpr char kEntropy[] = "AutoSudo/rules.db/v1";

// SYSTEM and Administrators, nobody else. The key is what decides whether the database is
// the one we wrote, so the file holding it is not for other users to read or copy.
//
// A debug build leaves the descriptor to the process instead (see buildflags.hpp): it runs
// as an ordinary user, and a key that its own service cannot read would leave the rule
// database unloadable, which is the opposite of helpful while the thing is being worked on.
// The default descriptor of a user token names SYSTEM, Administrators and that user, so a
// release service can still read a key a debug run created.
constexpr const wchar_t* kKeyFileSddl = L"D:(A;;GA;;;SY)(A;;GA;;;BA)";

std::string lastError()
{
    return platform::windows::TranslateLastError();
}

scl2::bytearray protect(const scl2::bytearray& key)
{
    DATA_BLOB input{};
    input.pbData = reinterpret_cast<BYTE*>(const_cast<std::byte*>(key.data()));
    input.cbData = static_cast<DWORD>(key.size());

    DATA_BLOB entropy{};
    entropy.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(kEntropy));
    entropy.cbData = static_cast<DWORD>(sizeof(kEntropy) - 1);

    DATA_BLOB output{};
    if (!CryptProtectData(&input, L"AutoSudo rule database key", &entropy, nullptr, nullptr,
                          CRYPTPROTECT_LOCAL_MACHINE, &output)) {
        throw std::runtime_error("keyvault: CryptProtectData failed: " + lastError());
    }

    const scl2::bytearray blob(reinterpret_cast<const std::byte*>(output.pbData), output.cbData);
    LocalFree(output.pbData);
    return blob;
}

scl2::secure_bytearray unprotect(const scl2::bytearray& blob)
{
    DATA_BLOB input{};
    input.pbData = reinterpret_cast<BYTE*>(const_cast<std::byte*>(blob.data()));
    input.cbData = static_cast<DWORD>(blob.size());

    DATA_BLOB entropy{};
    entropy.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(kEntropy));
    entropy.cbData = static_cast<DWORD>(sizeof(kEntropy) - 1);

    DATA_BLOB output{};
    if (!CryptUnprotectData(&input, nullptr, &entropy, nullptr, nullptr,
                            CRYPTPROTECT_LOCAL_MACHINE, &output)) {
        throw std::runtime_error("keyvault: CryptUnprotectData failed: " + lastError());
    }

    scl2::secure_bytearray key(reinterpret_cast<const std::byte*>(output.pbData), output.cbData);
    SecureZeroMemory(output.pbData, output.cbData);
    LocalFree(output.pbData);

    if (key.size() != kKeyBytes) {
        throw std::runtime_error("keyvault: the stored key is not " + std::to_string(kKeyBytes)
                                 + " bytes, so it is not ours");
    }

    return key;
}

// Write the key file with the descriptor in place from the moment it exists: creating it
// first and tightening it afterwards would leave it readable for that moment.
void writeKeyFile(const std::filesystem::path& path, const scl2::bytearray& blob)
{
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = FALSE;
    attributes.lpSecurityDescriptor = nullptr;   // the process default, in a debug build

    PSECURITY_DESCRIPTOR descriptor = nullptr;

    if (!allowUnelevatedRuleCallers) {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(kKeyFileSddl, SDDL_REVISION_1,
                                                                  &descriptor, nullptr)) {
            throw std::runtime_error("keyvault: could not build the key file descriptor: " + lastError());
        }
        attributes.lpSecurityDescriptor = descriptor;
    }

    const std::wstring widePath = path.wstring();
    HANDLE file = CreateFileW(widePath.c_str(), GENERIC_WRITE, 0, &attributes, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);

    if (descriptor != nullptr) {
        LocalFree(descriptor);
    }

    if (file == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("keyvault: could not create " + scl2::wstr_to_str(widePath)
                                 + ": " + lastError());
    }

    DWORD written = 0;
    const BOOL wrote = WriteFile(file, blob.data(), static_cast<DWORD>(blob.size()), &written, nullptr);
    const BOOL flushed = FlushFileBuffers(file);
    CloseHandle(file);

    if (!wrote || written != blob.size() || !flushed) {
        throw std::runtime_error("keyvault: could not write " + scl2::wstr_to_str(widePath)
                                 + ": " + lastError());
    }
}

scl2::bytearray readKeyFile(const std::filesystem::path& path)
{
    const std::wstring widePath = path.wstring();
    HANDLE file = CreateFileW(widePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("keyvault: could not open " + scl2::wstr_to_str(widePath)
                                 + ": " + lastError());
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 4096) {
        CloseHandle(file);
        throw std::runtime_error("keyvault: " + scl2::wstr_to_str(widePath)
                                 + " is not the size of a key file");
    }

    scl2::bytearray blob(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    const BOOL ok = ReadFile(file, blob.data(), static_cast<DWORD>(blob.size()), &read, nullptr);
    CloseHandle(file);

    if (!ok || read != blob.size()) {
        throw std::runtime_error("keyvault: could not read " + scl2::wstr_to_str(widePath)
                                 + ": " + lastError());
    }

    return blob;
}

scl2::secure_bytearray generateKey()
{
    scl2::secure_bytearray key;
    key.resize(kKeyBytes);

    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(key.data()),
                        static_cast<ULONG>(key.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        throw std::runtime_error("keyvault: could not generate a key: " + lastError());
    }

    return key;
}

} // namespace

scl2::secure_bytearray acquire(const std::filesystem::path& keyPath)
{
    LOGT_LOCAL("keyvault::acquire");
    if (fs::exists(keyPath)) {
        scl2::secure_bytearray key = unprotect(readKeyFile(keyPath));
        logt.debug() << "Using the rule database key from " << keyPath;
        return key;
    }

    scl2::secure_bytearray key = generateKey();
    writeKeyFile(keyPath, protect(key));
    logt.info() << "Created a rule database key at " << keyPath;
    return key;
}

} // namespace keyvault
