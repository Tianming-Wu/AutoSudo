#include "protocol.hpp"

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



scl2::bytearray RuleEngineOperationRequest::dump() const {
    scl2::bytearray data;
    data.append(op);
    data.append(targetUid);
    data.append(ruleType);
    data.append(ruleEType);
    data.append(ruleAction);
    data.append(ruleAllowUpTo);
    data.append<size_t>(payload.size());
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
    
    size_t payloadSize = data.read<size_t>();
    if (payloadSize > 0) {
        // Read payload bytes
        scl2::bytearray tempPayload;
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
    data.append<size_t>(payload.size());
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
    
    size_t payloadSize = data.read<size_t>();
    if (payloadSize > 0) {
        // Read payload bytes
        scl2::bytearray tempPayload;
        for (size_t i = 0; i < payloadSize; ++i) {
            tempPayload.append(data.read<uint8_t>());
        }
        entry.payload = tempPayload;
    }
    
    return entry;
}

scl2::bytearray RuleListResponse::dump() const {
    scl2::bytearray data;
    data.append<size_t>(rules.size());
    for (const auto& rule : rules) {
        scl2::bytearray ruleData = rule.dump();
        data.append<size_t>(ruleData.size());
        data.append(ruleData);
    }
    return data;
}

RuleListResponse RuleListResponse::load(const scl2::bytearray &data) {
    RuleListResponse response;
    size_t ruleCount = data.read<size_t>();
    
    for (size_t i = 0; i < ruleCount; ++i) {
        size_t ruleSize = data.read<size_t>();
        // Create a temporary bytearray containing the rule data
        scl2::bytearray ruleData;
        for (size_t j = 0; j < ruleSize; ++j) {
            ruleData.append(data.read<uint8_t>());
        }
        response.rules.push_back(RuleEntry::load(ruleData));
    }
    
    return response;
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
