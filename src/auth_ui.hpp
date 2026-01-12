#pragma once

enum AuthUIType {
    ConfirmNew, ConfirmRaise, ConfirmHashRebuild, ConfirmDeletion,
    _sizetag
};

constexpr const wchar_t* AuthUITypeStr[] = {
    L"NEW",
    L"RAISE",
    L"HASHRB",
    L"DELETE"
};

enum class AuthUIResult {
    Allow = 0,      // 允许/确认
    Deny = 1,       // 拒绝/取消
    Delete = 2      // 删除
};