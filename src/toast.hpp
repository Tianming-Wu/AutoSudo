/*
    Toast Module for AutoSudo Project

    This module is responsible for showing the toast notifications
    for the requests, when it was automatically approved but the
    the user still want to be notified, or when the request was
    denied.

*/

#pragma once

#include <string>

namespace toast {


// This is required because on Windows, only registered AUMIDs can
// show toasts. This function registers the AUMID for AutoSudo.
void registerToast();

void pushToast(const std::wstring& title, const std::wstring& message);


} // namespace toast