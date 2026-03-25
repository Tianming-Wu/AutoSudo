/*
    SDK Implementation for AutoSudo Project.

    This module provides other programs with an interface to interact
    with the AutoSudo service.
*/

#include "protocol.hpp"
#include "rule_client.hpp"

#include "sdk.hpp"

#include <map>
#include <chrono>

#include <libpipe.hpp>

namespace AutoSudoSdk {


// These are the payload handlers for different types of rules.

uint16_t CreateConstantRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo){
    RuleClient client;
    // For constant rule, the payload is empty.
    std::bytearray payload;
    return client.createRule(Rule::Type::Constant, etype, action, allowUpTo, payload);
}

uint16_t CreateDirectoryRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, const fs::path& value){
    RuleClient client;

    std::bytearray payload = std::bytearray::fromStdString(value.string());

    return client.createRule(Rule::Type::DirectoryRule, etype, action, allowUpTo, payload);
}

uint16_t CreateFullPathRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, const fs::path& value){
    RuleClient client;

    std::bytearray payload = std::bytearray::fromStdString(value.string());

    return client.createRule(Rule::Type::FullPathRule, etype, action, allowUpTo, payload);
}

uint16_t CreateExecutableNameRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, const std::string& value){
    RuleClient client;

    std::bytearray payload = std::bytearray::fromStdString(value);

    return client.createRule(Rule::Type::ExecutableNameRule, etype, action, allowUpTo, payload);
}

uint16_t CreateStartupDirectoryRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, const fs::path& value){
    RuleClient client;

    std::bytearray payload = std::bytearray::fromStdString(value.string());

    return client.createRule(Rule::Type::StartupDirectoryRule, etype, action, allowUpTo, payload);
}

uint16_t CreateSidRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, const std::string& value){
    RuleClient client;

    std::bytearray payload = std::bytearray::fromStdString(value);

    return client.createRule(Rule::Type::SidRule, etype, action, allowUpTo, payload);
}

uint16_t CreateSessionRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, unsigned int value){
    RuleClient client;

    std::bytearray payload;
    payload.append(value);

    return client.createRule(Rule::Type::SessionRule, etype, action, allowUpTo, payload);
}

uint16_t CreateParameterRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, const std::string& value){
    RuleClient client;

    std::bytearray payload = std::bytearray::fromStdString(value);

    return client.createRule(Rule::Type::ParameterRule, etype, action, allowUpTo, payload);
}

uint16_t CreateParametersRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, const std::string& value){
    RuleClient client;

    // payload is a single regex that matches the parameters accroding to EType.
    std::bytearray payload = std::bytearray::fromStdString(value);

    return client.createRule(Rule::Type::ParametersRule, etype, action, allowUpTo, payload);
}

// CreateEnvironmentVariableRule(); (removed from plan)

// Note: this should point to a lua script. Check document.
// This does not have any effect for now, since the evaluation process is incomplete.
// Lua Engine is not yet inside this project.
uint16_t CreateCustomScriptRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, const fs::path& value) {
    RuleClient client;

    std::bytearray payload = std::bytearray::fromStdString(value.string()); // This is the script path.

    return client.createRule(Rule::Type::CustomScriptRule, etype, action, allowUpTo, payload);
}

// uint16_t CreateDateRule(Rule::Action action, PermissionLevel allowUpTo,  value);
// uint16_t CreateTimeRule(Rule::Action action, PermissionLevel allowUpTo,  value);
// uint16_t CreateDateTimeRule(Rule::Action action, PermissionLevel allowUpTo,  value);
// uint16_t CreateFileTimeRule(Rule::Action action, PermissionLevel allowUpTo,  value);

uint16_t CreateHashRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, const std::string& value){
    RuleClient client;

    // The value is expected to be a hex string representing the hash.
    // The payload is the raw bytes of the hash.
    std::bytearray payload = std::bytearray::fromHex(value);
    
    return client.createRule(Rule::Type::HashRule, etype, action, allowUpTo, payload);
}

uint16_t CreateVoteRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo, int value){
    RuleClient client;
    std::bytearray payload;
    payload.append(value);
    return client.createRule(Rule::Type::VoteRule, etype, action, allowUpTo, payload);
}

uint16_t CreateDigitalSignatureRule(Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo /*, no payload */){
    RuleClient client;
    std::bytearray payload; // No payload needed for this rule type.
    return client.createRule(Rule::Type::DigitalSignatureRule, etype, action, allowUpTo, payload);
}

bool IsServiceAvailable(uint32_t timeoutMs)
{
    libpipe::pipe_client client(R"(\\.\pipe\AutoSudoPipe)");
    return client.waitForConnection(std::chrono::milliseconds(timeoutMs));
}

bool TryListRules(std::vector<RuleEntry>& outRules)
{
    RuleClient client;
    return client.listRules(outRules);
}

bool ModifyRule(uint16_t uid, Rule::Type type, Rule::EType etype, Rule::Action action,
                PermissionLevel allowUpTo, const std::bytearray& payload,
                std::optional<uint16_t> moveToOrder)
{
    RuleClient client;
    return client.modifyRule(uid, type, etype, action, allowUpTo, payload, moveToOrder);
}

bool ModifyConstantRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                        std::optional<uint16_t> moveToOrder)
{
    std::bytearray payload;
    return ModifyRule(uid, Rule::Type::Constant, etype, action, allowUpTo, payload, moveToOrder);
}

bool ModifyDirectoryRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                         const fs::path& value, std::optional<uint16_t> moveToOrder)
{
    std::bytearray payload = std::bytearray::fromStdString(value.string());
    return ModifyRule(uid, Rule::Type::DirectoryRule, etype, action, allowUpTo, payload, moveToOrder);
}

bool ModifyFullPathRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                        const fs::path& value, std::optional<uint16_t> moveToOrder)
{
    std::bytearray payload = std::bytearray::fromStdString(value.string());
    return ModifyRule(uid, Rule::Type::FullPathRule, etype, action, allowUpTo, payload, moveToOrder);
}

bool ModifyExecutableNameRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                              const std::string& value, std::optional<uint16_t> moveToOrder)
{
    std::bytearray payload = std::bytearray::fromStdString(value);
    return ModifyRule(uid, Rule::Type::ExecutableNameRule, etype, action, allowUpTo, payload, moveToOrder);
}

bool ModifyStartupDirectoryRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                                const fs::path& value, std::optional<uint16_t> moveToOrder)
{
    std::bytearray payload = std::bytearray::fromStdString(value.string());
    return ModifyRule(uid, Rule::Type::StartupDirectoryRule, etype, action, allowUpTo, payload, moveToOrder);
}

bool ModifySidRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                   const std::string& value, std::optional<uint16_t> moveToOrder)
{
    std::bytearray payload = std::bytearray::fromStdString(value);
    return ModifyRule(uid, Rule::Type::SidRule, etype, action, allowUpTo, payload, moveToOrder);
}

bool ModifySessionRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                       unsigned int value, std::optional<uint16_t> moveToOrder)
{
    std::bytearray payload;
    payload.append(value);
    return ModifyRule(uid, Rule::Type::SessionRule, etype, action, allowUpTo, payload, moveToOrder);
}

bool ModifyParameterRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                         const std::string& value, std::optional<uint16_t> moveToOrder)
{
    std::bytearray payload = std::bytearray::fromStdString(value);
    return ModifyRule(uid, Rule::Type::ParameterRule, etype, action, allowUpTo, payload, moveToOrder);
}

bool ModifyParametersRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                          const std::string& value, std::optional<uint16_t> moveToOrder)
{
    std::bytearray payload = std::bytearray::fromStdString(value);
    return ModifyRule(uid, Rule::Type::ParametersRule, etype, action, allowUpTo, payload, moveToOrder);
}

bool ModifyCustomScriptRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                            const fs::path& value, std::optional<uint16_t> moveToOrder)
{
    std::bytearray payload = std::bytearray::fromStdString(value.string());
    return ModifyRule(uid, Rule::Type::CustomScriptRule, etype, action, allowUpTo, payload, moveToOrder);
}

bool ModifyHashRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                    const std::string& value, std::optional<uint16_t> moveToOrder)
{
    std::bytearray payload = std::bytearray::fromHex(value);
    return ModifyRule(uid, Rule::Type::HashRule, etype, action, allowUpTo, payload, moveToOrder);
}

bool ModifyVoteRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                    int value, std::optional<uint16_t> moveToOrder)
{
    std::bytearray payload;
    payload.append(value);
    return ModifyRule(uid, Rule::Type::VoteRule, etype, action, allowUpTo, payload, moveToOrder);
}

bool ModifyDigitalSignatureRule(uint16_t uid, Rule::EType etype, Rule::Action action, PermissionLevel allowUpTo,
                                std::optional<uint16_t> moveToOrder)
{
    std::bytearray payload;
    return ModifyRule(uid, Rule::Type::DigitalSignatureRule, etype, action, allowUpTo, payload, moveToOrder);
}

std::vector<RuleEntry> ListRules()
{
    RuleClient client;
    return client.listRules();
}

bool MoveRule(uint16_t uid, uint16_t targetOrder)
{
    RuleClient client;
    return client.moveRule(uid, targetOrder);
}

bool ReorderRulesByUidOrder(const std::vector<uint16_t>& orderedUids)
{
    RuleClient client;
    for (size_t i = 0; i < orderedUids.size(); ++i) {
        if (!client.moveRule(orderedUids[i], static_cast<uint16_t>(i + 1))) {
            return false;
        }
    }
    return true;
}

std::string ParseRulePayload(Rule::Type type, const std::bytearray& payload)
{
    try {
        switch(type) {
        case Rule::Type::DirectoryRule:
        case Rule::Type::FullPathRule:
        case Rule::Type::ExecutableNameRule:
        case Rule::Type::StartupDirectoryRule:
        case Rule::Type::SidRule:
        case Rule::Type::ParameterRule:
        case Rule::Type::ParametersRule:
        case Rule::Type::CustomScriptRule: {
            return payload.toStdString();
        }
        case Rule::Type::SessionRule:
            return std::to_string(payload.as<unsigned int>());
        case Rule::Type::VoteRule:
            return std::to_string(payload.as<int>());
        case Rule::Type::HashRule:
            return payload.toHex();
        case Rule::Type::DigitalSignatureRule:
            return "<no payload>";
        case Rule::Type::Constant:
            return payload.empty() ? "<no payload>" : payload.toHex();
        default:
            return payload.empty() ? "<no payload>" : payload.toHex();
        }
    } catch (const std::exception& e) {
        return std::string("<payload parse error: ") + e.what() + ">";
    }
}

std::string ParseRulePayload(const RuleEntry& rule)
{
    return ParseRulePayload(static_cast<Rule::Type>(rule.type), rule.payload);
}

std::vector<std::pair<std::string, Rule::EType>> getAvailableETypes(Rule::Type type)
{
    std::vector<std::pair<std::string, Rule::EType>> avtypes;

    static const std::map<Rule::EType, std::string> allTypes = {
        {Rule::EType::Equal, "Equal"},
        {Rule::EType::NotEqual, "NotEqual"},
        {Rule::EType::Contains, "Contains"},
        {Rule::EType::NotContains, "NotContains"},
        {Rule::EType::BeginWith, "BeginWith"},
        {Rule::EType::NotBeginWith, "NotBeginWith"},
        {Rule::EType::EndWith, "EndWith"},
        {Rule::EType::NotEndWith, "NotEndWith"},
        {Rule::EType::RegexMatch, "RegexMatch"},
        {Rule::EType::RegexNotMatch, "RegexNotMatch"},
        {Rule::EType::Greater, "Greater"},
        {Rule::EType::GreaterEqual, "GreaterEqual"},
        {Rule::EType::Less, "Less"},
        {Rule::EType::LessEqual, "LessEqual"},
        {Rule::EType::NoneMatches, "NoneMatches"},
        {Rule::EType::AllMatches, "AllMatches"},
        {Rule::EType::AnyMatches, "AnyMatches"}
    };

    enum TypeCategory {
        String = 0,
        Numeric = 1,
        MultipleKeys = 2,
        Bytes = 3
    };

    static const std::map<TypeCategory, std::vector<Rule::EType>> categoryMap = {
        {String, {Rule::EType::Equal, Rule::EType::NotEqual, Rule::EType::Contains, Rule::EType::NotContains,
                    Rule::EType::BeginWith, Rule::EType::NotBeginWith, Rule::EType::EndWith, Rule::EType::NotEndWith,
                    Rule::EType::RegexMatch, Rule::EType::RegexNotMatch}},
        {Numeric, {Rule::EType::Equal, Rule::EType::NotEqual, Rule::EType::Greater, Rule::EType::GreaterEqual,
                    Rule::EType::Less, Rule::EType::LessEqual}},
        {MultipleKeys, {Rule::EType::NoneMatches, Rule::EType::AllMatches, Rule::EType::AnyMatches}},
        {Bytes, {Rule::EType::Equal, Rule::EType::NotEqual}}
    };

    auto _get = [&](TypeCategory cat) {
        for (const auto& etype : categoryMap.at(cat)) {
            avtypes.emplace_back(allTypes.at(etype), etype);
        }
    };

    
    if ( // Numeric types
        type == Rule::Type::SidRule || type == Rule::Type::SessionRule ||
        (type >= Rule::Type::DateRule && type <= Rule::Type::FileTimeRule) ||
        type == Rule::Type::VoteRule
    ) {
        return _get(Numeric), avtypes;

    } else if ( // multiple-keys types, which only supports regex for now.
        type == Rule::Type::ParametersRule
    ) {
        return _get(MultipleKeys), avtypes; // This is not fully implemented.

    } else if ( // string-based types without evaluation-type
        type == Rule::Type::CustomScriptRule ||
        type == Rule::Type::DigitalSignatureRule ||
        type == Rule::Type::Constant
    ) {
        // These types does not have EType, since they have fixed behavior.
        // This would disable the EType selection in the UI.
        return avtypes; // Return empty list.

    } else if( // Bytes-based type, which only supports equal/not-equal.
        type == Rule::Type::HashRule
    ) {
        return _get(Bytes), avtypes;

    } else {
        // The rest are string-based types.
        return _get(String), avtypes;
    }
}

} // namespace AutoSudoSdk