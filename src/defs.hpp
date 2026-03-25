/*
    Shared definitions for the project.
*/

#pragma once

#include <cstdint>

// This will later be used for compatibility check, and the server should
// reject any requests from clients with different protocol version.
// Version-wide protocol compatibility is not in the plan, and will not be
// the case under any circumstances.
#define PROTOCOL_VERSION (3)

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