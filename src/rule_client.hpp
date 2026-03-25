#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>

#include "protocol.hpp"

namespace AutoSudoSdk::Rule {
enum class Type : uint16_t;
enum class EType : uint8_t;
enum class Action : uint32_t;
}

// Client-side rule management interface
class RuleClient {
public:
    RuleClient();
    ~RuleClient();

    // Connect to the AutoSudo service
    bool connect();
    
    // Create a new rule
    // Returns the UID of the created rule, or 0 on failure
    uint16_t createRule(AutoSudoSdk::Rule::Type type, AutoSudoSdk::Rule::EType etype, AutoSudoSdk::Rule::Action action,
                        PermissionLevel allowUpTo,
                        const std::bytearray& payload, std::optional<uint16_t> insertAt = std::nullopt);
    
    // Modify an existing rule
    // Returns true on success
    bool modifyRule(uint16_t uid, AutoSudoSdk::Rule::Type type, AutoSudoSdk::Rule::EType etype, AutoSudoSdk::Rule::Action action,
                    PermissionLevel allowUpTo,
                    const std::bytearray& payload, std::optional<uint16_t> moveToOrder = std::nullopt);
    
    // Delete a rule
    // Returns true on success
    bool deleteRule(uint16_t uid);
    
    // Move a rule to a new position
    // Returns true on success
    bool moveRule(uint16_t uid, uint16_t targetOrder);
    
    // List all current rules
    // Returns the list of rules, or empty vector on failure
    std::vector<RuleEntry> listRules();
    bool listRules(std::vector<RuleEntry>& outRules);

private:
    // Helper to send an operation and receive result
    bool sendOperation(const RuleEngineOperationRequest& opreq, RuleEngineOperationResult& result);
    bool sendOperation(const RuleEngineOperationRequest& opreq, RuleListResponse& response);
    
    std::string pipeName;
    bool connected;
};
