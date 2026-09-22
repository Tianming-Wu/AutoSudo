/*
    Shared definitions for the project.
*/

#pragma once

#include <cstdint>

// This will later be used for compatibility check, and the server should
// reject any requests from clients with different protocol version.
// Version-wide protocol compatibility is not in the plan, and will not be
// the case under any circumstances.
// 3 -> 4: a request starts with this version byte, the length prefixes in a
//         request are explicit uint32_t (they used to follow the machine
//         word, so a 32-bit client and a 64-bit service disagreed), rule
//         operations moved to the control pipe, and rules.db grew a header.
#define PROTOCOL_VERSION (4)

enum class PermissionLevel : int {
    User = 0, Admin = 1, System = 2,
    Custom = 3,
    NotFound = -1
};

enum class ClientRequestType : uint8_t {
    ExecuteCommand = 0, // 执行命令请求
    ServiceMgrCommand = 1, // 服务管理请求（仅包含需要由服务处理的部分）
    RuleEngineCommand = 2, // 规则引擎相关
};

// The two channels of the service.
//
// The execution channel is what the product is for: it must accept requests from
// any process on the machine, and the approval that follows is the only gate.
// The control channel carries rule operations, which change that gate - so it is
// created for Administrators and LocalSystem only, and the service checks the
// caller's token again on every connection.
inline constexpr const char* execPipeName = R"(\\.\pipe\AutoSudoPipe)";
inline constexpr const char* controlPipeName = R"(\\.\pipe\AutoSudoPipeCtl)";

// Limits a message off the wire is held to. A sender that exceeds one is refused,
// not truncated: it is either not one of ours or broken, and guessing which is not
// worth the risk on a service that runs as SYSTEM.
namespace limits {
inline constexpr uint32_t maxRequestBytes = 64 * 1024;      // one message from a client
inline constexpr uint32_t maxRulePayloadBytes = 32 * 1024;  // the payload of one rule
inline constexpr uint32_t maxPathChars = 4096;              // a path or directory in a request
inline constexpr uint32_t maxArguments = 256;               // arguments in one execution request
inline constexpr uint32_t maxArgumentChars = 32 * 1024;     // one argument
inline constexpr uint32_t maxRules = 4096;                  // rules in one database or response
inline constexpr uint32_t maxRuleBytes = 48 * 1024;         // one serialized rule
}


// Service management operations
// (Relavant logic not implemented)
enum class ServiceMgrOperation : uint16_t {
    Stop = 1,
    StopServing = 150, // 临时禁止任何请求通过
    ResumeServing = 151, // 恢复服务
    GetStatus = 200,
};


// Rule engine operations
enum class RuleEngineOperation : uint16_t {
    Create = 0,
    Modify = 5,
    Delete = 10,
    Move = 15,
    List = 20
};