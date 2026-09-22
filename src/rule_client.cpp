#include "rule_client.hpp"

#include <SharedCppLib2/pipe.hpp>
#include <SharedCppLib2/logt.hpp>
#include <chrono>

// Rule operations change what may run without asking the user, so they go to the control
// channel: the one the service creates for administrators and checks the caller on.
RuleClient::RuleClient() : pipeName(controlPipeName), connected(false) {}

RuleClient::~RuleClient() {}

bool RuleClient::connect() {
    LOGT_LOCAL("RuleClient::connect");
    // Connection is established on-demand for each operation
    return true;
}

uint16_t RuleClient::createRule(AutoSudoSdk::Rule::Type type, AutoSudoSdk::Rule::EType etype, AutoSudoSdk::Rule::Action action,
                                 PermissionLevel allowUpTo,
                                 const scl2::bytearray& payload, std::optional<uint16_t> insertAt) {
    LOGT_LOCAL("RuleClient::createRule");
    
    RuleEngineOperationRequest op;
    op.op = RuleEngineOperation::Create;
    op.ruleType = static_cast<uint16_t>(type);
    op.ruleEType = static_cast<uint8_t>(etype);
    op.ruleAction = static_cast<uint32_t>(action);
    op.ruleAllowUpTo = allowUpTo;
    op.payload = payload;
    op.insertAt = insertAt;
    
    RuleEngineOperationResult result;
    if (sendOperation(op, result) && result.success) {
        return result.createdUid;
    }
    
    return 0;
}

bool RuleClient::modifyRule(uint16_t uid, AutoSudoSdk::Rule::Type type, AutoSudoSdk::Rule::EType etype, AutoSudoSdk::Rule::Action action,
                            PermissionLevel allowUpTo,
                            const scl2::bytearray& payload, std::optional<uint16_t> moveToOrder) {
    LOGT_LOCAL("RuleClient::modifyRule");
    
    RuleEngineOperationRequest op;
    op.op = RuleEngineOperation::Modify;
    op.targetUid = uid;
    op.ruleType = static_cast<uint16_t>(type);
    op.ruleEType = static_cast<uint8_t>(etype);
    op.ruleAction = static_cast<uint32_t>(action);
    op.ruleAllowUpTo = allowUpTo;
    op.payload = payload;
    op.moveToOrder = moveToOrder;
    
    RuleEngineOperationResult result;
    return sendOperation(op, result) && result.success;
}

bool RuleClient::deleteRule(uint16_t uid) {
    LOGT_LOCAL("RuleClient::deleteRule");
    
    RuleEngineOperationRequest op;
    op.op = RuleEngineOperation::Delete;
    op.targetUid = uid;
    
    RuleEngineOperationResult result;
    return sendOperation(op, result) && result.success;
}

bool RuleClient::moveRule(uint16_t uid, uint16_t targetOrder) {
    LOGT_LOCAL("RuleClient::moveRule");
    
    RuleEngineOperationRequest op;
    op.op = RuleEngineOperation::Move;
    op.targetUid = uid;
    op.moveToOrder = targetOrder;
    
    RuleEngineOperationResult result;
    return sendOperation(op, result) && result.success;
}

std::vector<RuleEntry> RuleClient::listRules() {
    LOGT_LOCAL("RuleClient::listRules");
    
    RuleEngineOperationRequest op;
    op.op = RuleEngineOperation::List;
    
    RuleListResponse response;
    if (sendOperation(op, response)) {
        return response.rules;
    }
    
    return std::vector<RuleEntry>();
}

bool RuleClient::listRules(std::vector<RuleEntry>& outRules) {
    LOGT_LOCAL("RuleClient::listRules(out)");

    RuleEngineOperationRequest op;
    op.op = RuleEngineOperation::List;

    RuleListResponse response;
    if (sendOperation(op, response)) {
        outRules = std::move(response.rules);
        return true;
    }

    outRules.clear();
    return false;
}

bool RuleClient::importRules(const std::vector<RuleEntry>& rules) {
    LOGT_LOCAL("RuleClient::importRules");

    RuleEngineOperationRequest op;
    op.op = RuleEngineOperation::Import;

    RuleSet set;
    set.rules = rules;
    op.payload = set.dump();

    RuleEngineOperationResult result;
    return sendOperation(op, result) && result.success;
}

bool RuleClient::sendOperation(const RuleEngineOperationRequest& opreq, RuleEngineOperationResult& result) {
    LOGT_LOCAL("RuleClient::sendOperation<RuleOpResult>");

    lastFailure = Failure::None;
    scl2::pipe::client client(pipeName);
    
    if (!client.waitForConnection(std::chrono::seconds(1))) {
        lastFailure = Failure::NotReached;
        logt.error() << "Failed to connect to the control channel. The service is either not "
                        "running, or it does not let this process in.";
        return false;
    }
    
    const scl2::bytearray request = makeRequestFrame(ClientRequestType::RuleEngineCommand, opreq.dump());

    if (client.write(request) == 0) {
        lastFailure = Failure::SilentRefusal;
        logt.error() << "Failed to send rule operation to service.";
        return false;
    }
    
    // Wait for response
    if (!client.waitForReadyRead(std::chrono::seconds(5))) {
        lastFailure = Failure::SilentRefusal;
        logt.error() << "The service closed the connection without answering the rule operation.";
        return false;
    }
    
    scl2::bytearray responseData = client.readAll();
    if (responseData.empty()) {
        lastFailure = Failure::SilentRefusal;
        logt.error() << "Empty response from service.";
        return false;
    }

    try {
        result = RuleEngineOperationResult::load(responseData);
        return true;
    } catch (const std::exception& e) {
        lastFailure = Failure::UnreadableAnswer;
        logt.error() << "Failed to parse rule operation response: " << e.what();
        return false;
    }
}

bool RuleClient::sendOperation(const RuleEngineOperationRequest& opreq, RuleListResponse& response) {
    LOGT_LOCAL("RuleClient::sendOperation<RuleListResponse>");

    lastFailure = Failure::None;
    scl2::pipe::client client(pipeName);
    
    if (!client.waitForConnection(std::chrono::seconds(1))) {
        lastFailure = Failure::NotReached;
        logt.error() << "Failed to connect to the control channel. The service is either not "
                        "running, or it does not let this process in.";
        return false;
    }
    
    // Send request type + operation data
    const scl2::bytearray requestData = makeRequestFrame(ClientRequestType::RuleEngineCommand, opreq.dump());
    
    if (client.write(requestData) == 0) {
        lastFailure = Failure::SilentRefusal;
        logt.error() << "Failed to send rule list operation to service.";
        return false;
    }
    
    // Wait for response
    if (!client.waitForReadyRead(std::chrono::seconds(5))) {
        lastFailure = Failure::SilentRefusal;
        logt.error() << "The service closed the connection without answering the rule list request.";
        return false;
    }
    
    scl2::bytearray responseData = client.readAll();
    if (responseData.empty()) {
        lastFailure = Failure::SilentRefusal;
        logt.error() << "Empty response from service.";
        return false;
    }

    try {
        response = RuleListResponse::load(responseData);
        logt.info() << "Parsed rule list response, count=" << response.rules.size();
        return true;
    } catch (const std::exception& e) {        lastFailure = Failure::UnreadableAnswer;        logt.error() << "Failed to parse rule list response: " << e.what();
        return false;
    }
}
