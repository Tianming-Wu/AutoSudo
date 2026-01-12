#include "protocol.hpp"

std::wstring ProcessContext::Serialize() const {
    std::wstring result = 
        program + L"\n" + 
        arguments.pack() + L"\n" + 
        workingDirectory + L"\n" +
        calledPath + L"\n" +
        std::to_wstring(sessionId) + L"\n" +
        std::to_wstring(useCurrentSession) + L"\n" +
        std::to_wstring(deleteAuth) + L"\n" +
        std::to_wstring(static_cast<int>(requestedAuthLevel)) + L"\n";
    
    for (const auto& env : environmentVariables) {
        result += env + L"\n";
    }
    return result;
}

ProcessContext ProcessContext::Deserialize(const std::wstring& data) {
    ProcessContext context;
    
    // 使用 stringlist 分割数据，更优雅且安全
    std::wstringlist content(data, L"\n");
    
    // 检查最小字段数量
    if (content.size() < 8) {
        throw std::runtime_error("Invalid serialized data: insufficient fields");
    }
    
    size_t index = 0;
    
    // 解析程序路径
    context.program = content.vat(index++);
    
    // 解析参数
    context.arguments = std::wstringlist::unpack(content.vat(index++));
    
    // 解析工作目录
    context.workingDirectory = content.vat(index++);
    
    // 解析调用路径
    context.calledPath = content.vat(index++);
    
    // 解析会话ID
    try {
        context.sessionId = std::stoul(content.vat(index++));
    } catch (...) {
        context.sessionId = 0;
    }
    
    // 解析useCurrentSession
    std::wstring useSessionStr = content.vat(index++);
    context.useCurrentSession = (useSessionStr == L"1");
    
    // 解析deleteAuth
    std::wstring deleteAuthStr = content.vat(index++);
    context.deleteAuth = (deleteAuthStr == L"1");
    
    // 解析认证级别
    try {
        context.requestedAuthLevel = static_cast<AuthLevel>(std::stoi(content.vat(index++)));
    } catch (...) {
        context.requestedAuthLevel = AuthLevel::Admin; // 默认值
    }
    
    // 解析环境变量（剩余的所有行）
    while (index < content.size()) {
        std::wstring env = content.vat(index++);
        if (!env.empty()) {
            context.environmentVariables.push_back(env);
        }
    }
    
    return context;
}