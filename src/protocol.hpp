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

#include <SharedCppLib2/pipe.hpp>

#include "defs.hpp"

struct AutoSudoRequest {
    std::wstring executableFullPath;
    scl2::wstringlist arguments;
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

    static scl2::bytearray dump(const AutoSudoRequest& asr);
    static AutoSudoRequest load(const scl2::bytearray& data);

    /// Whether this request is something the service is willing to act on. A request off the
    /// wire is untrusted input: the fields are checked against the known sets and the limits
    /// in defs.hpp, and a bad one is refused, never repaired. `reason` says why.
    bool validate(std::string& reason) const;
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
    scl2::bytearray payload;
    
    // Positions
    std::optional<uint16_t> insertAt;  // For Create: position to insert at
    std::optional<uint16_t> moveToOrder;  // For Modify/Move: target position
    
    // Serialization
    scl2::bytearray dump() const;
    static RuleEngineOperationRequest load(const scl2::bytearray& data);

    /// Whether the request is consistent enough to act on: a known operation, a level that
    /// can actually be requested, a payload within limits, and the fields the operation
    /// needs. See AutoSudoRequest::validate().
    bool validate(std::string& reason) const;
};

scl2_check_generic_dump_load(RuleEngineOperationRequest);

// Single rule operation response
struct RuleEngineOperationResult {
    bool success;
    std::string message;
    uint16_t createdUid = 0;  // For Create: returns the newly created UID
    
    // Serialization
    scl2::bytearray dump() const;
    static RuleEngineOperationResult load(const scl2::bytearray& data);
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
    scl2::bytearray payload;
    
    scl2::bytearray dump() const;
    static RuleEntry load(const scl2::bytearray& data);
};

scl2_check_generic_dump_load(RuleEntry);

// List operation response: returns all current rules
struct RuleListResponse {
    std::vector<RuleEntry> rules;
    
    scl2::bytearray dump() const;
    static RuleListResponse load(const scl2::bytearray& data);
};

scl2_check_generic_dump_load(RuleListResponse);

// The same shape in the other direction: an import carries the whole set of rules, and the
// fields are exactly the ones a list response has, so the type is shared instead of copied.
using RuleSet = RuleListResponse;


// ── The request frame ─────────────────────────────────────────────
//
// A client request on the wire is: the protocol version, the request type, then the payload.
// The version leads so that a service refuses a client it does not speak to before it reads
// anything else - a request that is one version off would otherwise be parsed into fields
// that mean something else.

/// Build the frame a client sends.
scl2::bytearray makeRequestFrame(ClientRequestType type, const scl2::bytearray& payload);

/// The service side of makeRequestFrame(). A frame that cannot be used - a different version,
/// an unknown type, an empty body - is refused with a reason, and none of it is interpreted.
bool parseRequestFrame(const scl2::bytearray& frame, ClientRequestType& type,
                       scl2::bytearray& payload, std::string& reason);
