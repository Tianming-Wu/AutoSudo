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
                        const scl2::bytearray& payload, std::optional<uint16_t> insertAt = std::nullopt);
    
    // Modify an existing rule
    // Returns true on success
    bool modifyRule(uint16_t uid, AutoSudoSdk::Rule::Type type, AutoSudoSdk::Rule::EType etype, AutoSudoSdk::Rule::Action action,
                    PermissionLevel allowUpTo,
                    const scl2::bytearray& payload, std::optional<uint16_t> moveToOrder = std::nullopt);
    
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

    // Replace every rule with these, uids and order included. Returns true on success.
    bool importRules(const std::vector<RuleEntry>& rules);

    // What the last operation ran into, so a caller can tell the two things a client is in a
    // position to know apart. The service does not send a reply when it refuses a caller - a write
    // to a client that is not reading would hold a service thread, which is not worth it for a
    // message - so a refusal arrives as a connection that was taken and then closed, and that is
    // a different state from a channel that could not be opened at all.
    enum class Failure {
        None,             // nothing has failed since this object was made
        NotReached,       // the control channel could not be opened: no service, or not let in
        SilentRefusal,    // the request was taken, then the connection closed with no answer
        UnreadableAnswer, // an answer arrived, but not one this build could read
    };

    // The kind of the last failure, for a caller that wants to say something different about each
    // kind. describeFailure() turns it into a sentence.
    Failure failure() const { return lastFailure; }

private:
    // Helper to send an operation and receive result
    bool sendOperation(const RuleEngineOperationRequest& opreq, RuleEngineOperationResult& result);
    bool sendOperation(const RuleEngineOperationRequest& opreq, RuleListResponse& response);
    
    std::string pipeName;
    bool connected;
    Failure lastFailure = Failure::None;
};
