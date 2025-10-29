#pragma once
#include <string>

namespace authlib {

bool VerifyDigitalSignature(const std::wstring& filePath);

} // namespace authlib
