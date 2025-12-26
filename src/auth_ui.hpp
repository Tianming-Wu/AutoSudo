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