#include "rule_client.hpp"

#include <libpipe.hpp>
#include <SharedCppLib2/logt.hpp>
#include <chrono>

RuleClient::RuleClient() : pipeName(R"(\\.\pipe\AutoSudoPipe)"), connected(false) {}

RuleClient::~RuleClient() {}

bool RuleClient::connect() {
    LOGT_LOCAL("RuleClient::connect");
    // Connection is established on-demand for each operation
    return true;
}

uint16_t RuleClient::createRule(AutoSudoSdk::Rule::Type type, AutoSudoSdk::Rule::EType etype, AutoSudoSdk::Rule::Action action,
                                 PermissionLevel allowUpTo,
                                 const std::bytearray& payload, std::optional<uint16_t> insertAt) {
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
                            const std::bytearray& payload, std::optional<uint16_t> moveToOrder) {
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

bool RuleClient::sendOperation(const RuleEngineOperationRequest& opreq, RuleEngineOperationResult& result) {
    LOGT_LOCAL("RuleClient::sendOperation<RuleOpResult>");
    
    libpipe::pipe_client client(pipeName);
    
    if (!client.waitForConnection(std::chrono::seconds(1))) {
        logt.error() << "Failed to connect to AutoSudo service.";
        return false;
    }
    
    if (client.write(std::bytearray(ClientRequestType::RuleEngineCommand) + opreq.dump()) == 0) {
        logt.error() << "Failed to send rule operation to service.";
        return false;
    }
    
    // Wait for response
    if (!client.waitForReadyRead(std::chrono::seconds(5))) {
        logt.error() << "Timeout waiting for rule operation response.";
        return false;
    }
    
    std::bytearray responseData = client.readAll();
    if (responseData.empty()) {
        logt.error() << "Empty response from service.";
        return false;
    }

    client.acknowledge();
    
    try {
        std::bytearray_view view(responseData);
        result = RuleEngineOperationResult::load(view);
        return true;
    } catch (const std::exception& e) {
        logt.error() << "Failed to parse rule operation response: " << e.what();
        return false;
    }
}

bool RuleClient::sendOperation(const RuleEngineOperationRequest& opreq, RuleListResponse& response) {
    LOGT_LOCAL("RuleClient::sendOperation<RuleListResponse>");
    
    libpipe::pipe_client client(pipeName);
    
    if (!client.waitForConnection(std::chrono::seconds(1))) {
        logt.error() << "Failed to connect to AutoSudo service.";
        return false;
    }
    
    // Send request type + operation data
    std::bytearray requestData;
    requestData.append(ClientRequestType::RuleEngineCommand);
    requestData.append(opreq.dump());
    
    if (client.write(requestData) == 0) {
        logt.error() << "Failed to send rule list operation to service.";
        return false;
    }
    
    // Wait for response
    if (!client.waitForReadyRead(std::chrono::seconds(5))) {
        logt.error() << "Timeout waiting for rule list response.";
        return false;
    }
    
    std::bytearray responseData = client.readAll();
    if (responseData.empty()) {
        logt.error() << "Empty response from service.";
        return false;
    }

    client.acknowledge();
    
    try {
        std::bytearray_view view(responseData);
        response = RuleListResponse::load(view);
        logt.info() << "Parsed rule list response, count=" << response.rules.size();
        return true;
    } catch (const std::exception& e) {
        logt.error() << "Failed to parse rule list response: " << e.what();
        return false;
    }
}
