#include "protocol.hpp"

std::wstring ProcessContext::Serialize() const {
    std::wstring result = 
        commandLine + L"\n" + 
        workingDirectory + L"\n" +
        std::to_wstring(sessionId) + L"\n" +
        std::to_wstring(useCurrentSession) + L"\n";
    
    for (const auto& env : environmentVariables) {
        result += env + L"\n";
    }
    return result;
}

ProcessContext ProcessContext::Deserialize(const std::wstring& data) {
    ProcessContext context;
    size_t pos = 0;
    size_t nextPos;
    
    // 解析命令行
    nextPos = data.find(L'\n', pos);
    context.commandLine = data.substr(pos, nextPos - pos);
    pos = nextPos + 1;
    
    // 解析工作目录
    nextPos = data.find(L'\n', pos);
    context.workingDirectory = data.substr(pos, nextPos - pos);
    pos = nextPos + 1;
    
    // 解析会话ID
    nextPos = data.find(L'\n', pos);
    std::wstring sessionIdStr = data.substr(pos, nextPos - pos);
    context.sessionId = std::stoul(sessionIdStr);
    pos = nextPos + 1;
    
    // 解析useCurrentSession
    nextPos = data.find(L'\n', pos);
    std::wstring useSessionStr = data.substr(pos, nextPos - pos);
    context.useCurrentSession = (useSessionStr == L"1");
    pos = nextPos + 1;
    
    // 解析环境变量
    while (pos < data.size()) {
        nextPos = data.find(L'\n', pos);
        if (nextPos == std::wstring::npos) break;
        
        std::wstring env = data.substr(pos, nextPos - pos);
        if (!env.empty()) {
            context.environmentVariables.push_back(env);
        }
        pos = nextPos + 1;
    }
    
    return context;
}