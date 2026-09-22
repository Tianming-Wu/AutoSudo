#include "protocol.hpp"

#include <stdexcept>
#include <string>

namespace {

// The values a client may ask for. Everything on the wire is untrusted: a request
// carrying something outside these sets is refused, not repaired.

bool isKnownRuleOperation(RuleEngineOperation op)
{
    switch(op) {
    case RuleEngineOperation::Create:
    case RuleEngineOperation::Modify:
    case RuleEngineOperation::Delete:
    case RuleEngineOperation::Move:
    case RuleEngineOperation::List:
    case RuleEngineOperation::Import:
        return true;
    default:
        return false;
    }
}

// User, Admin and System are the levels a caller may ask for. Custom has no token
// behind it, and NotFound is what an evaluation reports - neither is a request.
bool isRequestableLevel(PermissionLevel level)
{
    switch(level) {
    case PermissionLevel::User:
    case PermissionLevel::Admin:
    case PermissionLevel::System:
        return true;
    default:
        return false;
    }
}

} // namespace

scl2::bytearray AutoSudoRequest::dump(const AutoSudoRequest &asr)
{
    scl2::bytearray data;

    data.append(asr.executableFullPath);
    data.append(asr.arguments.pack());
    data.append(asr.workingDirectory);
    data.append(asr.calledPath);

    data.append(asr.targetSessionId);
    data.append(asr.useCurrentSession);
    // data.append(asr.deleteAuth);
    data.append(asr.requestedPermissionLevel);

    data.append(asr.inheritConsole);
    data.append(asr.ihConsoleX);
    data.append(asr.ihConsoleY);

    // data.append<size_t>(asr.environmentVariables.size());
    // for (const auto& env : asr.environmentVariables) {
    //     data.append(env);
    // }

    return data;
}

AutoSudoRequest AutoSudoRequest::load(const scl2::bytearray &data)
{
    AutoSudoRequest req;

    req.executableFullPath = data.readWString();
    req.arguments = scl2::wstringlist::unpack(data.readWString());
    req.workingDirectory = data.readWString();
    req.calledPath = data.readWString();
    
    req.targetSessionId = data.read<unsigned long>();
    req.useCurrentSession = data.read<bool>();
    // req.deleteAuth = data.read<bool>();
    req.requestedPermissionLevel = data.read<PermissionLevel>();
    req.inheritConsole = data.read<bool>();
    req.ihConsoleX = data.read<long>();
    req.ihConsoleY = data.read<long>();

    // size_t envCount = data.read<size_t>();
    // req.environmentVariables.reserve(envCount);
    // for (size_t i = 0; i < envCount; ++i) {
    //     req.environmentVariables.push_back(data.readWString());
    // }

    return req;
}

bool AutoSudoRequest::validate(std::string &reason) const
{
    if (executableFullPath.empty() || executableFullPath.size() > limits::maxPathChars) {
        reason = "empty or oversized executable path";
        return false;
    }

    if (workingDirectory.size() > limits::maxPathChars || calledPath.size() > limits::maxPathChars) {
        reason = "oversized working directory or called path";
        return false;
    }

    if (arguments.size() > limits::maxArguments) {
        reason = "too many arguments";
        return false;
    }

    for (const auto& argument : arguments) {
        if (argument.size() > limits::maxArgumentChars) {
            reason = "an argument is too long";
            return false;
        }
    }

    // The level decides which token the service goes looking for, and it is compared
    // against what a rule allows, so an unknown one is not a value to carry on with.
    if (!isRequestableLevel(requestedPermissionLevel)) {
        reason = "unknown permission level " + std::to_string(static_cast<int>(requestedPermissionLevel));
        return false;
    }

    return true;
}



scl2::bytearray RuleEngineOperationRequest::dump() const {
    scl2::bytearray data;
    data.append(op);
    data.append(targetUid);
    data.append(ruleType);
    data.append(ruleEType);
    data.append(ruleAction);
    data.append(ruleAllowUpTo);
    data.append(static_cast<uint32_t>(payload.size()));
    data.append(payload);
    
    // Serialize optional values
    data.append(insertAt.has_value());
    if (insertAt.has_value()) {
        data.append(insertAt.value());
    }
    
    data.append(moveToOrder.has_value());
    if (moveToOrder.has_value()) {
        data.append(moveToOrder.value());
    }
    
    return data;
}

RuleEngineOperationRequest RuleEngineOperationRequest::load(const scl2::bytearray &data) {
    RuleEngineOperationRequest op;
    op.op = data.read<RuleEngineOperation>();
    op.targetUid = data.read<uint16_t>();
    op.ruleType = data.read<uint16_t>();
    op.ruleEType = data.read<uint8_t>();
    op.ruleAction = data.read<uint32_t>();
    op.ruleAllowUpTo = data.read<PermissionLevel>();
    
    const uint32_t payloadSize = data.read<uint32_t>();
    if(payloadSize > limits::maxRulePayloadBytes)
        throw std::runtime_error("RuleEngineOperationRequest::load: payload exceeds the limit");
    op.payload = data.readBytes(payloadSize);
    
    // Deserialize optional values
    bool hasInsertAt = data.read<bool>();
    if (hasInsertAt) {
        op.insertAt = data.read<uint16_t>();
    }
    
    bool hasMoveToOrder = data.read<bool>();
    if (hasMoveToOrder) {
        op.moveToOrder = data.read<uint16_t>();
    }
    
    return op;
}

bool RuleEngineOperationRequest::validate(std::string &reason) const
{
    if(!isKnownRuleOperation(op)) {
        reason = "unknown rule operation " + std::to_string(static_cast<uint16_t>(op));
        return false;
    }

    if(!isRequestableLevel(ruleAllowUpTo)) {
        reason = "unknown rule permission level " + std::to_string(static_cast<int>(ruleAllowUpTo));
        return false;
    }

    // An import carries a whole set of rules, so its payload is bounded by what one request
    // may carry rather than by what one rule may.
    const uint32_t payloadLimit = (op == RuleEngineOperation::Import)
        ? limits::maxRequestBytes : limits::maxRulePayloadBytes;

    if(payload.size() > payloadLimit) {
        reason = "rule payload is larger than the limit";
        return false;
    }

    // A rule is never created with uid 0: the engine hands out the smallest free number, and
    // 0 is what it reports when it runs out, so 0 is not a rule to act on. An import names
    // its own uids, and an empty set is a legitimate thing to import.
    const bool needsTarget = op == RuleEngineOperation::Modify
                          || op == RuleEngineOperation::Delete
                          || op == RuleEngineOperation::Move;

    if(needsTarget && targetUid == 0) {
        reason = "operation without a target rule";
        return false;
    }

    if(op == RuleEngineOperation::Move && !moveToOrder.has_value()) {
        reason = "move without a target order";
        return false;
    }

    return true;
}

scl2::bytearray RuleEngineOperationResult::dump() const {
    scl2::bytearray data;
    data.append(success);
    data.append(message);
    data.append(createdUid);
    return data;
}

RuleEngineOperationResult RuleEngineOperationResult::load(const scl2::bytearray &data) {
    RuleEngineOperationResult result;
    result.success = data.read<bool>();
    result.message = data.readString();
    result.createdUid = data.read<uint16_t>();
    return result;
}

scl2::bytearray RuleEntry::dump() const {
    scl2::bytearray data;
    data.append(uid);
    data.append(order);
    data.append(type);
    data.append(etype);
    data.append(action);
    data.append(allowUpTo);
    data.append(static_cast<uint32_t>(payload.size()));
    data.append(payload);
    return data;
}

RuleEntry RuleEntry::load(const scl2::bytearray &data) {
    RuleEntry entry;
    entry.uid = data.read<uint16_t>();
    entry.order = data.read<uint16_t>();
    entry.type = data.read<uint16_t>();
    entry.etype = data.read<uint8_t>();
    entry.action = data.read<uint32_t>();
    entry.allowUpTo = data.read<PermissionLevel>();
    
    const uint32_t payloadSize = data.read<uint32_t>();
    if(payloadSize > limits::maxRulePayloadBytes)
        throw std::runtime_error("RuleEntry::load: payload exceeds the limit");
    entry.payload = data.readBytes(payloadSize);
    
    return entry;
}

scl2::bytearray RuleListResponse::dump() const {
    scl2::bytearray data;
    data.append(static_cast<uint32_t>(rules.size()));
    for (const auto& rule : rules) {
        scl2::bytearray ruleData = rule.dump();
        data.append(static_cast<uint32_t>(ruleData.size()));
        data.append(ruleData);
    }
    return data;
}

RuleListResponse RuleListResponse::load(const scl2::bytearray &data) {
    RuleListResponse response;
    const uint32_t ruleCount = data.read<uint32_t>();
    if (ruleCount > limits::maxRules)
        throw std::runtime_error("RuleListResponse::load: more rules than the limit allows");

    response.rules.reserve(ruleCount);
    for (uint32_t i = 0; i < ruleCount; ++i) {
        const uint32_t ruleSize = data.read<uint32_t>();
        if (ruleSize > limits::maxRuleBytes)
            throw std::runtime_error("RuleListResponse::load: rule record exceeds the limit");
        response.rules.push_back(RuleEntry::load(data.readBytes(ruleSize)));
    }
    
    return response;
}


scl2::bytearray makeRequestFrame(ClientRequestType type, const scl2::bytearray &payload)
{
    scl2::bytearray frame;
    frame.append(static_cast<uint8_t>(PROTOCOL_VERSION));
    frame.append(type);
    frame.append(payload);
    return frame;
}

bool parseRequestFrame(const scl2::bytearray &frame, ClientRequestType &type,
                       scl2::bytearray &payload, std::string &reason)
{
    if (frame.size() < 2) {
        reason = "request frame is too short";
        return false;
    }

    const uint8_t version = frame.subarr(0, sizeof(uint8_t)).as<uint8_t>();
    if (version != PROTOCOL_VERSION) {
        reason = "protocol version mismatch, client " + std::to_string(version)
               + ", service " + std::to_string(PROTOCOL_VERSION);
        return false;
    }

    const uint8_t rawType = frame.subarr(sizeof(uint8_t), sizeof(uint8_t)).as<uint8_t>();
    switch (static_cast<ClientRequestType>(rawType)) {
    case ClientRequestType::ExecuteCommand:
    case ClientRequestType::ServiceMgrCommand:
    case ClientRequestType::RuleEngineCommand:
        type = static_cast<ClientRequestType>(rawType);
        break;
    default:
        reason = "unknown request type " + std::to_string(rawType);
        return false;
    }

    payload = frame.subarr(2 * sizeof(uint8_t));
    if (payload.empty()) {
        reason = "request frame has no body";
        return false;
    }

    return true;
}


// scl2::bytearray EnvironmentVariable::serialize()
// {
//     scl2::bytearray result;
//     result.append(name);
//     result.append(value);

//     return result;
// }

// EnvironmentVariable EnvironmentVariable::deserialize(const scl2::bytearray_view &view)
// {
//     std::wstring name = view.readWString();
//     std::wstring value = view.readWString();

//     return { .name = name, .value = value };
// }
