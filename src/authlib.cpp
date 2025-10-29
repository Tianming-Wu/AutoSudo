#include "authlib.hpp"

#include <wintrust.h>
#include <softpub.h>
#include <windows.h>

namespace authlib {

// bool VerifyDigitalSignature(const std::wstring& filePath) {
//     WINTRUST_FILE_INFO fileData = {0};
//     fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
//     fileData.pcwszFilePath = filePath.c_str();
//     fileData.hFile = nullptr;
//     fileData.pgKnownSubject = nullptr;
    
//     WINTRUST_DATA winTrustData = {0};
//     winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    
//     // 使用新版本的WINTRUST_DATA结构体成员
// #if defined(WINTRUST_DATA_ICC_VERSION) && (WINTRUST_DATA_ICC_VERSION >= 1)
//     winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
//     winTrustData.pFile = &fileData;
//     winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
//     winTrustData.dwUIContext = WTD_UI_NONE;
// #else
//     // 旧版本结构体支持
//     winTrustData.pPolicyCallbackData = nullptr;
//     winTrustData.pSIPClientData = nullptr;
//     winTrustData.dwUIChoice = WTD_UI_NONE;
//     winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
//     winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
//     winTrustData.pFile = &fileData;
//     winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
// #endif

//     winTrustData.hWVTStateData = nullptr;
//     winTrustData.pwszURLReference = nullptr;
    
//     // 使用GENERIC_VERIFY_V2动作
//     GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    
//     // 验证签名
//     LONG status = WinVerifyTrust(nullptr, &policyGuid, &winTrustData);
    
//     // 清理
//     winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
//     WinVerifyTrust(nullptr, &policyGuid, &winTrustData);
    
//     return status == ERROR_SUCCESS;
// }

bool VerifyDigitalSignature(const std::wstring& filePath) {
    WINTRUST_FILE_INFO fileData = { sizeof(WINTRUST_FILE_INFO) };
    fileData.pcwszFilePath = filePath.c_str();
    
    WINTRUST_DATA winTrustData = { sizeof(WINTRUST_DATA) };
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileData;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    
    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &policyGuid, &winTrustData);
    
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGuid, &winTrustData);
    
    return status == ERROR_SUCCESS;
}

} // namespace authlib