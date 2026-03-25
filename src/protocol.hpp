#pragma once
#include <string>
#include <vector>
#include <concepts>
#include <type_traits>

#include <SharedCppLib2/platform_windows.hpp>

#include <SharedCppLib2/stringlist.hpp>
#include <SharedCppLib2/bytearray.hpp>
#include <SharedCppLib2/logt.hpp>
#include <SharedCppLib2/api.hpp>

#include <libpipe.hpp>

#include "defs.hpp"

struct AutoSudoRequest {
    std::wstring executableFullPath;
    std::wstringlist arguments;
    std::wstring workingDirectory;
    std::wstring calledPath;  //客户端调用路径，就是 AutoSudo 命令执行时的当前工作路径

    DWORD targetSessionId = 0;  //目标会话ID
    bool useCurrentSession = true;  //是否使用当前会话
    // bool deleteAuth = false;  //是否删除授权

    PermissionLevel requestedPermissionLevel = PermissionLevel::Admin;

    // 这些字段仅在控制台客户端（AutoSudo）有效，在 AutoSudoW 中不使用。
    bool inheritConsole = false; // 是否继承控制台
    int ihConsoleX, ihConsoleY; // 控制台参数，用于 ConPTY 初始化

    // 可选环境变量参数（未完全实装）
    // std::vector<std::wstring> environmentVariables;

    static std::bytearray dump(const AutoSudoRequest& asr);
    static AutoSudoRequest load(const std::bytearray_view& data);
};

scl2_check_generic_dump_load(AutoSudoRequest);



// Single rule operation request
struct RuleEngineOperationRequest {
    RuleEngineOperation op;
    
    // Common fields
    uint16_t targetUid = 0;  // For Delete, Modify, Move operations
    
    // For Create/Modify: rule data
    uint16_t ruleType = 0;   // Corresponds to ApprovalRule::Type
    uint8_t ruleEType = 0;   // Corresponds to ApprovalRule::EType
    uint32_t ruleAction = 0; // Corresponds to ApprovalRule::Action
    PermissionLevel ruleAllowUpTo = PermissionLevel::User;
    std::bytearray payload;
    
    // Positions
    std::optional<uint16_t> insertAt;  // For Create: position to insert at
    std::optional<uint16_t> moveToOrder;  // For Modify/Move: target position
    
    // Serialization
    std::bytearray dump() const;
    static RuleEngineOperationRequest load(const std::bytearray_view& data);
};

scl2_check_generic_dump_load(RuleEngineOperationRequest);

// Single rule operation response
struct RuleEngineOperationResult {
    bool success;
    std::string message;
    uint16_t createdUid = 0;  // For Create: returns the newly created UID
    
    // Serialization
    std::bytearray dump() const;
    static RuleEngineOperationResult load(const std::bytearray_view& data);
};

scl2_check_generic_dump_load(RuleEngineOperationResult);

// For List operation response: a single rule entry
struct RuleEntry {
    uint16_t uid;
    uint16_t order;
    uint16_t type;
    uint8_t etype;
    uint32_t action;
    PermissionLevel allowUpTo;
    std::bytearray payload;
    
    std::bytearray dump() const;
    static RuleEntry load(const std::bytearray_view& data);
};

scl2_check_generic_dump_load(RuleEntry);

// List operation response: returns all current rules
struct RuleListResponse {
    std::vector<RuleEntry> rules;
    
    std::bytearray dump() const;
    static RuleListResponse load(const std::bytearray_view& data);
};

scl2_check_generic_dump_load(RuleListResponse);
