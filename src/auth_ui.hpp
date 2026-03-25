/*
    This is the definition of Authentication UI related logic.

    The behavior is controlled by two separate policies in the rule
    engine. It is possible that the Auth UI won't show up at all.
*/
#pragma once

enum AuthUIType : int {
    NoRuleMatched = 0, InsufficientLevel = 1,
};

constexpr const wchar_t* AuthUITypeStr[] = {
    L"NORULEMATCHED", L"INSUFFICIENTLEVEL"
};

// 删除相关的逻辑已经移除，它们不会在 AuthUI 中处理。
// 这部分由 RuleEngine API 管理。

enum class AuthUIResult : int {
    Allow = 0,      // 允许/确认
    Deny = 1,       // 拒绝/取消

    Always = 11,    // 总是通过（后续会让这个返回自动添加一条规则）
    Never = 12,     // 永不通过（后续会让这个返回自动添加一条规则）
};