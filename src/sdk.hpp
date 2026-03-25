/*
    SDK Header for AutoSudo Project.
*/

#pragma once

#include "protocol.hpp"
#include "rule_client.hpp"

namespace AutoSudoSdk {

// This part is synchronized with approval.hpp.
// For sdk use.
namespace Rule {

enum class Type : uint16_t {
    Constant = 1, // A constant rule that always returns the same result. (Not quite useful)
    DirectoryRule = 2, // Decide based on the directory of the executable.
    FullPathRule = 3, // Decide based on the full path of the executable.
    ExecutableNameRule = 4, // Decide based on the file name of the executable.
    StartupDirectoryRule = 5, // Decide based on the startup directory of the process.
    SidRule = 6, // Decide based on the user SID. (not implemented)
    SessionRule = 7, // Decide based on the session id. (not implemented)
    ParameterRule = 8, // Decide based on the parameters of the process. (not implemented)
    ParametersRule = 9, // Decide based on the parameters of the process. (not implemented)
    // EnvironmentVariableRule = 10, // Decide based on the environment variables of the process. (removed from plan)
    CustomScriptRule = 11, // Decide based on the result of a custom lua script. (not implemented)
    DateRule = 12, // Decide based on the current date and time.
    TimeRule = 13, // Decide based on the current time.
    DateTimeRule = 14, // Decide based on the current date and time.
    FileTimeRule = 15, // Decide based on the last modified time of the executable.
    HashRule = 16, // Decide based on the hash of the executable.
    VoteRule = 17, // This rule does not decide the result directly, but decide based on the score calculated by other rules.
    DigitalSignatureRule = 18, // Decide based on the digital signature of the executable.
};

enum class EType : uint8_t {
    Equal = 0, NotEqual = 1,
    Contains = 2, NotContains = 3,
    BeginWith = 4, NotBeginWith = 5,
    EndWith = 6, NotEndWith = 7,
    RegexMatch = 8, RegexNotMatch = 9,

    Greater = 10, GreaterEqual = 11, Less = 12, LessEqual = 13, // For numeric types only

    NoneMatches = 20, AllMatches = 21, AnyMatches = 22,  // For multiple-keys rules only, which only accepts regex.
};

enum class Action : uint32_t {
    Approve = 1,
    Deny = 2,
    Bypass = 3, // Ignore this rule, useful when you want to temporarily disable a rule without deleting it.
    VoteUp = 4, // This rule will add a score to the final decision
    VoteDown = 5, // This rule will subtract a score from the final decision
    RequestConfirmation = 6
};


} // namespace Rule


// Create helper functions

uint16_t CreateConstantRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo);
uint16_t CreateDirectoryRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, const fs::path& value);
uint16_t CreateFullPathRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, const fs::path& value);
uint16_t CreateExecutableNameRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, const std::string& value);
uint16_t CreateStartupDirectoryRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, const fs::path& value);
uint16_t CreateSidRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, const std::string& value);
uint16_t CreateSessionRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, unsigned int value);
uint16_t CreateParameterRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, const std::string& value);
uint16_t CreateParametersRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, const std::string& value);
// CreateEnvironmentVariableRule(); (removed from plan)
uint16_t CreateCustomScriptRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, const fs::path& value); // Note: this should point to a lua script. Check document.
// uint16_t CreateDateRule(Rule::Action action, PermissionLevel allowUpTo,  value);
// uint16_t CreateTimeRule(Rule::Action action, PermissionLevel allowUpTo,  value);
// uint16_t CreateDateTimeRule(Rule::Action action, PermissionLevel allowUpTo,  value);
// uint16_t CreateFileTimeRule(Rule::Action action, PermissionLevel allowUpTo,  value);
uint16_t CreateHashRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, const std::string& value);
uint16_t CreateVoteRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, int value);
uint16_t CreateDigitalSignatureRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo /*, no payload */);

bool IsServiceAvailable(uint32_t timeoutMs = 1000);
bool TryListRules(std::vector<RuleEntry>& outRules);

bool ModifyRule(uint16_t uid, Rule::Type type, Rule::EType etype, Rule::Action action,
                PermissionLevel allowUpTo, const std::bytearray& payload,
                std::optional<uint16_t> moveToOrder = std::nullopt);
bool ModifyConstantRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                        std::optional<uint16_t> moveToOrder = std::nullopt);
bool ModifyDirectoryRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                         const fs::path& value, std::optional<uint16_t> moveToOrder = std::nullopt);
bool ModifyFullPathRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                        const fs::path& value, std::optional<uint16_t> moveToOrder = std::nullopt);
bool ModifyExecutableNameRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                              const std::string& value, std::optional<uint16_t> moveToOrder = std::nullopt);
bool ModifyStartupDirectoryRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                                const fs::path& value, std::optional<uint16_t> moveToOrder = std::nullopt);
bool ModifySidRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                   const std::string& value, std::optional<uint16_t> moveToOrder = std::nullopt);
bool ModifySessionRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                       unsigned int value, std::optional<uint16_t> moveToOrder = std::nullopt);
bool ModifyParameterRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                         const std::string& value, std::optional<uint16_t> moveToOrder = std::nullopt);
bool ModifyParametersRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                          const std::string& value, std::optional<uint16_t> moveToOrder = std::nullopt);
bool ModifyCustomScriptRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                            const fs::path& value, std::optional<uint16_t> moveToOrder = std::nullopt);
bool ModifyHashRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                    const std::string& value, std::optional<uint16_t> moveToOrder = std::nullopt);
bool ModifyVoteRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                    int value, std::optional<uint16_t> moveToOrder = std::nullopt);
bool ModifyDigitalSignatureRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                                std::optional<uint16_t> moveToOrder = std::nullopt);

std::vector<RuleEntry> ListRules();
bool MoveRule(uint16_t uid, uint16_t targetOrder);
bool ReorderRulesByUidOrder(const std::vector<uint16_t>& orderedUids);


// Helper functions for Combobox usage
std::vector<std::pair<std::string, Rule::EType>> getAvailableETypes(Rule::Type type);


// Read helper functions to translate payload into human-readable format.
std::string ParseRulePayload(Rule::Type type, const std::bytearray& payload);
std::string ParseRulePayload(const RuleEntry& rule);

// Update helper functions


} // namespace AutoSudoSdk