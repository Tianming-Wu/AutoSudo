#include "protocol.hpp"

std::bytearray AutoSudoRequest::dump(const AutoSudoRequest &asr)
{
    std::bytearray data;

    data.addWString(asr.executableFullPath);
    data.addWString(asr.arguments.pack());
    data.addWString(asr.workingDirectory);
    data.addWString(asr.calledPath);

    data.append(asr.targetSessionId);
    data.append(asr.useCurrentSession);
    // data.append(asr.deleteAuth);
    data.append(asr.requestedPermissionLevel);

    data.append(asr.inheritConsole);
    data.append(asr.ihConsoleX);
    data.append(asr.ihConsoleY);

    // data.appendSize(asr.environmentVariables.size());
    // for (const auto& env : asr.environmentVariables) {
    //     data.addWString(env);
    // }

    return data;
}

AutoSudoRequest AutoSudoRequest::load(const std::bytearray_view &data)
{
    AutoSudoRequest req;

    req.executableFullPath = data.readWString();
    req.arguments = std::wstringlist::unpack(data.readWString());
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



std::bytearray RuleEngineOperationRequest::dump() const {
    std::bytearray data;
    data.append(op);
    data.append(targetUid);
    data.append(ruleType);
    data.append(ruleEType);
    data.append(ruleAction);
    data.append(ruleAllowUpTo);
    data.appendSize(payload.size());
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

RuleEngineOperationRequest RuleEngineOperationRequest::load(const std::bytearray_view &data) {
    RuleEngineOperationRequest op;
    op.op = data.read<RuleEngineOperation>();
    op.targetUid = data.read<uint16_t>();
    op.ruleType = data.read<uint16_t>();
    op.ruleEType = data.read<uint8_t>();
    op.ruleAction = data.read<uint32_t>();
    op.ruleAllowUpTo = data.read<PermissionLevel>();
    
    size_t payloadSize = data.read<size_t>();
    if (payloadSize > 0) {
        // Read payload bytes
        std::bytearray tempPayload;
        for (size_t i = 0; i < payloadSize; ++i) {
            tempPayload.append(data.read<uint8_t>());
        }
        op.payload = tempPayload;
    }
    
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

std::bytearray RuleEngineOperationResult::dump() const {
    std::bytearray data;
    data.append(success);
    data.addString(message);
    data.append(createdUid);
    return data;
}

RuleEngineOperationResult RuleEngineOperationResult::load(const std::bytearray_view &data) {
    RuleEngineOperationResult result;
    result.success = data.read<bool>();
    result.message = data.readString();
    result.createdUid = data.read<uint16_t>();
    return result;
}

std::bytearray RuleEntry::dump() const {
    std::bytearray data;
    data.append(uid);
    data.append(order);
    data.append(type);
    data.append(etype);
    data.append(action);
    data.append(allowUpTo);
    data.appendSize(payload.size());
    data.append(payload);
    return data;
}

RuleEntry RuleEntry::load(const std::bytearray_view &data) {
    RuleEntry entry;
    entry.uid = data.read<uint16_t>();
    entry.order = data.read<uint16_t>();
    entry.type = data.read<uint16_t>();
    entry.etype = data.read<uint8_t>();
    entry.action = data.read<uint32_t>();
    entry.allowUpTo = data.read<PermissionLevel>();
    
    size_t payloadSize = data.read<size_t>();
    if (payloadSize > 0) {
        // Read payload bytes
        std::bytearray tempPayload;
        for (size_t i = 0; i < payloadSize; ++i) {
            tempPayload.append(data.read<uint8_t>());
        }
        entry.payload = tempPayload;
    }
    
    return entry;
}

std::bytearray RuleListResponse::dump() const {
    std::bytearray data;
    data.appendSize(rules.size());
    for (const auto& rule : rules) {
        std::bytearray ruleData = rule.dump();
        data.appendSize(ruleData.size());
        data.append(ruleData);
    }
    return data;
}

RuleListResponse RuleListResponse::load(const std::bytearray_view &data) {
    RuleListResponse response;
    size_t ruleCount = data.read<size_t>();
    
    for (size_t i = 0; i < ruleCount; ++i) {
        size_t ruleSize = data.read<size_t>();
        // Create a temporary bytearray containing the rule data
        std::bytearray ruleData;
        for (size_t j = 0; j < ruleSize; ++j) {
            ruleData.append(data.read<uint8_t>());
        }
        std::bytearray_view ruleView(ruleData);
        response.rules.push_back(RuleEntry::load(ruleView));
    }
    
    return response;
}


// std::bytearray EnvironmentVariable::serialize()
// {
//     std::bytearray result;
//     result.addWString(name);
//     result.addWString(value);

//     return result;
// }

// EnvironmentVariable EnvironmentVariable::deserialize(const std::bytearray_view &view)
// {
//     std::wstring name = view.readWString();
//     std::wstring value = view.readWString();

//     return { .name = name, .value = value };
// }
