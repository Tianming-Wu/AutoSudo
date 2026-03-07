#pragma once
#include <string>
#include <vector>
#include <SharedCppLib2/platform_windows.hpp>

#include <SharedCppLib2/stringlist.hpp>
#include <SharedCppLib2/bytearray.hpp>
#include <SharedCppLib2/logt.hpp>

#include <libpipe.hpp>

#include <concepts>
#include <type_traits>

// These macros are no longer used, now the ones in libpipe are used.
// #define AUTOSUDO_PIPE_NAME R"(\\.\pipe\AutoSudoPipe)"
// #define BUFFER_SIZE 4096

enum class AuthLevel {
    NotFound = -4,          // 不在允许列表中
    InsufficientLevel = -3, // 允许级别不足
    HashMismatch = -2,      // 文件哈希不匹配
    Invalid = -1,           // 无效的权限级别码

    User = 0,
    Admin = 1,
    System = 2
};

typedef int qpack_id_t; // For multiquery packages (reserved)

// Note (about multiquery / multiresponse):
// If it is a normal query, the qid is always 0.
// If the query has multiple entries, the qid starts by 1, and the
// last package's qid should be zero.
// For example, there is 3 packeges to send, the qid will be {1, 2, 0}.
// The same for response.
// This is for simplicity in deserialization process, since decoding
// dynamic lists for non-plain (non trivially copyable) types is hard.

struct ProcessContext {
    std::wstring program;
    std::wstringlist arguments;
    std::wstring workingDirectory;
    std::wstring calledPath;  //客户端调用路径

    DWORD sessionId = 0;  //目标会话ID
    bool useCurrentSession = true;  //是否使用当前会话
    bool deleteAuth = false;  //是否删除授权

    AuthLevel requestedAuthLevel = AuthLevel::Admin;

    bool inheritConsole = false; // 是否继承控制台
    int ConsoleX, ConsoleY; // 控制台参数，用于 ConPTY

    // Dynamic member
    std::vector<std::wstring> environmentVariables;

    std::wstring Serialize() const;
    static ProcessContext Deserialize(const std::wstring& data);
};

///TODO: Change serializing pattern to bytearray instead of wstring,
// so I can easily encrypt the data in the future if needed.
// We had a mature system of bytearray for encoding and decoding.

// Environment variables are just string pairs.
struct EnvironmentVariable {
    std::wstring name;
    std::wstring value;

    std::bytearray serialize();
    static EnvironmentVariable deserialize(const std::bytearray_view& view);
};


typedef enum class ProtocolMessageType {
    Null, 

    QueryEntry,
    QueryStatus, // 客户端查询服务状态
    QueryVersion, // 客户端查询服务版本

    ListEntry,
} PMType;

struct ProtocolMessage {
    ProtocolMessageType type;
    std::bytearray payload;
};

// Here's the naming rule for protocol module:
// PMQ - Request, PMS - Response

// Basic message type that only contains qid field,
// for a unified api.
struct PM_Message {
    qpack_id_t qid;

    template<typename T>
        requires std::derived_from<T, PM_Message>
    T convert_to () const { return *(dynamic_cast<const T*>(this)); }
};


// QueryStatus
struct PMS_QueryStatus : PM_Message {
    // serviceRunning is not needed.
    std::chrono::system_clock::time_point startTime;
    std::chrono::milliseconds upTime;

    // Do we want to include the entry list?
    // Well, I'd like to say no for now.
};


// QueryVersion
struct PMS_QueryVersion : PM_Message {
    std::wstring versionString;
};


// QueryEntry
struct PMQ_QueryEntry : PM_Message {
    enum class Type {
        Null, ByFullName, ByName, ByHash
    } type;

    bool reverse = false; // For multiquery (filtering) query mode

    std::string query; // The content of the query, meaning depends on the Type field.
};

struct PMS_QueryEntry : PM_Message {
    AuthLevel authLevel;
    std::wstring fullPath; // The full path of the matched entry, only valid when authLevel is not NotFound.
};


struct PMQ_ListEntry : PM_Message {
    // list filter is only permission level. For other things, use query instead.
    AuthLevel minAuthLevel, maxAuthLevel;
};

struct PMS_ListEntry : PM_Message {
    // List is by packid, so a package is a single entry.
    std::wstring fullPath;
    AuthLevel authLevel;
};




// Helper function for multiquery (server side)
// Accepts multiple queries into a vector.
// Note that it is impossible to get the first query together.

template<typename T>
    requires std::derived_from<T, PM_Message> &&
    requires(T t) { T::deserialize(std::declval<std::bytearray_view>()); }
std::vector<T> multiquery_accept(libpipe::pipe_server_client &client, const T& firstQuery)
{
    LOGT_LOCAL("multiquery_accept<" + std::string(typeid(T).name()) + ">");

    std::vector<T> result;
    result.push_back(firstQuery); // add the first query
    bool lastPackage = false;

    while(true) {
        if(client.waitForReadyRead(std::chrono::seconds(1))) {
            std::bytearray msg = client.readAll();

            PM_Message* baseMsg = reinterpret_cast<PM_Message*>(msg.data());
            
            if(baseMsg->qid != 0 && baseMsg->qid != result.size()) {
                logt.error() << "Received out-of-order multiquery package. Expected qid " << result.size() << ", got " << baseMsg->qid;
                break; // out-of-order package, stop waiting for moreages
            }

            std::bytearray_view msg_view(msg);
            T query = T::deserialize(msg_view);

            result.push_back(query);

            if(baseMsg->qid == 0) break; // last package received, stop waiting for more packages

        } else {
            logt.error() << "Timeout while waiting for multiquery package " << result.size() + 1;
            break; // timeout, stop waiting for more packages
        }
    }
    
    return result;
}

template<typename T>
    requires std::derived_from<T, PM_Message> &&
    requires(T t) { T::serialize(); }
bool multiquery_respond(libpipe::pipe_server_client &client, const std::vector<T>& responses)
{
    LOGT_LOCAL("multiquery_respond<" + std::string(typeid(T).name()) + ">");

    for(size_t i = 0; i < responses.size(); i++) {
        const T& response = responses[i];
        std::bytearray payload = response.serialize();

        PM_Message* baseMsg = reinterpret_cast<PM_Message*>(payload.data());
        baseMsg->qid = (i == responses.size() - 1) ? 0 : (i + 1); // set qid, starts with 1, last package is 0

        if(client.write(payload) == 0) {
            logt.error() << "Failed to send multiquery response package " << (i + 1);
            return false; // failed to send, stop sending more packages
        }
    }

    return true;

}