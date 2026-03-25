/*
    Approval module (RuleEngine) for AutoSudo project.

    This module provides an uniform interface for approval system,
    which is responsible for deciding whether a given process
    creation request should be automatically approved, denied, or
    require user confirmation.

    It supports complex template matching rules, and combination of
    multiple rules.

    Rules:
        This is the really new thing in the major update. It features
        a rule engine that can be applied to any executable, and the
        rules can be defined in a very flexible way. For example, you
        can define a rule that approves any executable in C:\Windows,
        or any executable that has "chrome" in its name, etc. The 
        rules can also be combined in a flexible way, for example,
        you can define a rule that approves any executable in
        C:\Windows except those that have "update" in their name.

        The rules are applied in a specific order, and the first rule
        that matched will decide the result. However, there are also
        some special rules that will decide the result as the
        combination of other rules.

        The logical definition system is not complete yet, and it is
        currently waiting for the upstream SharedCppLib2 project to
        complete the condition module, which will be a powerful
        system that allow conditions to be stored on disk.

    Although I do use a adapable layout for the rules, they are still
    pretty specific to the current use case. However, all it need to
    be adapted is to change some enums and evaluating logic.

*/

#pragma once

#include <stdint.h>
#include <filesystem>
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <regex>
#include <limits>

#include <SharedCppLib2/api.hpp>
#include <SharedCppLib2/bytearray.hpp>
#include <SharedCppLib2/stringlist.hpp>
#include <SharedCppLib2/platform.hpp>
#include <SharedCppLib2/singleinst.hpp>

#include <SharedCppLib2/typemask.hpp>

#include "protocol.hpp"
#include "defs.hpp"

namespace fs = std::filesystem;

// This can support up to 65535 rules.
// Before we ever get to that, we would have met severe performance
// issues.
typedef uint16_t apprule_uid_t;
typedef uint16_t order_t; // For rule ordering

// Top-level approval rule
enum class Approval : uint8_t {
    Discard = 0,    // Always deny
    Rule = 1,       // Apply rule-based approval
    UserConfirmation = 2,  // Always request user confirmation.
    Lenient = 3,    // Automatically approve most of the safe requests, deny only the obviously dangerous ones.
    Bypass = 4,     // Automatically approve all requests (really dangerous)
};

enum class ApprovalResultId : uint8_t {
    Denied = 0, Approved = 1, RequestConfirmation = 2,
    Fail = 255 // Evaluation failed (e.g. due to invalid rule configuration), treated as Denied by the caller.
};

struct ApprovalRequest {
    fs::path executable;
    fs::path startupDirectory;
    std::wstringlist arguments;
    PermissionLevel perm; // The permission level requested by this process creation request.

    dword_t session_id; // Session id
    dword_t user_sid; // User SID

    // std::vector<std::wstring> environmentVariables; // Environment variables in the form of "KEY=VALUE"

};

struct ApprovalResult {
    ApprovalResultId result;
    PermissionLevel allowUpTo;
    std::optional<std::string> reason; // Optional reason for the decision, useful for logging and debugging.
};

// A single rule object.
class ApprovalRule {
    friend class ApprovalEngine; // Only the engine can create and modify rules.
public:
    ApprovalRule() = default;
    ~ApprovalRule() = default;

    enable_copy_move(ApprovalRule)

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

    using AllowUpTo = PermissionLevel;

    // The actual rule data, which is interpreted according to the type.
    bool evaluate(const ApprovalRequest& request) const;


    bool operator==(const ApprovalRule& other) const;

private:
    // helper functions to simplify the evaluate() function

    bool __str_e_evaluate(const std::string& str) const; // generic evaluate (handles EType for string-type rules)
    bool __val_e_evaluate(int val) const; // generic evaluate for numeric-type rules
    bool __regex_evaluate(const std::string& str) const;

    bool __hash_fs_evaluate(const fs::path& path) const;
    // bool __env_evaluate(const ApprovalRequest& request) const;

    bool __time_evaluate() const;
    bool __filetime_evaluate(const fs::path& path) const;

    bool __digsig_evaluate(const fs::path& path) const; // If the file is digitally signed and the signature is valid. Has no payload.


    static ApprovalRule create(Type type, EType etype, Action action, AllowUpTo allowUpTo, const std::bytearray& payload);

    static ApprovalRule load(const std::bytearray_view& data);
    static std::bytearray dump(const ApprovalRule& rule);

private:
    Type type;
    EType etype;
    Action action; // If matched, the action is taken.
    AllowUpTo allowUpTo; // The permission level that this rule can approve up to. Only meaningful when action is Approve or RequestConfirmation.
    apprule_uid_t uid;
    order_t order; // The order of this rule in the evaluation. Lower order means higher priority.

    std::bytearray payload; // The actual rule data, which is interpreted according to the type.
};


// Rule engine (2nd layer approval model), which contains multiple rules and a combination logic.
class ApprovalEngine {
    friend class ApprovalRule;
public:
    SINGLE_INSTANCE(ApprovalEngine)

    ApprovalEngine(bool autosave = true);
    ~ApprovalEngine();

    bool loadFile();
    bool save() const;

    si_static_access(evaluate, _evaluate)

    inline bool isAutoSave() const { return autosave; }
    inline void setAutoSave(bool enable) { autosave = enable; }

    apprule_uid_t create(ApprovalRule::Type type, ApprovalRule::EType etype, ApprovalRule::Action action,
                         PermissionLevel allowUpTo, const std::bytearray& payload,
                         std::optional<order_t> insertAt = std::nullopt);
    bool modify(apprule_uid_t uid, ApprovalRule::Type type, ApprovalRule::EType etype,
                ApprovalRule::Action action, PermissionLevel allowUpTo, const std::bytearray& payload,
                std::optional<order_t> moveToOrder = std::nullopt);
    bool remove(apprule_uid_t uid);

    bool moveTo(apprule_uid_t uid, order_t targetOrder);
    bool moveUp(apprule_uid_t uid);
    bool moveDown(apprule_uid_t uid);

    std::vector<RuleEntry> listRules() const;

private:
    std::map<order_t, ApprovalRule> rules; // The actual rules, indexed by order.

    bool autosave; // Trigger save() after every modification, to avoid data loss. Can be turned off for batch modifications.
    bool manageSingleInstanceLifecycle;

private:
    ApprovalEngine(bool autosave, bool manageSingleInstanceLifecycle);

    using RuleMap = std::map<order_t, ApprovalRule>;
    RuleMap::iterator findByUid(apprule_uid_t uid);
    RuleMap::const_iterator findByUid(apprule_uid_t uid) const;
    apprule_uid_t nextAvailableUid() const;
    void normalizeOrder();

private:
    ApprovalResult _evaluate(const ApprovalRequest& request) const;

public:
    static ApprovalEngine load(const std::bytearray_view& data);
    static std::bytearray dump(const ApprovalEngine& engine);
};


ApprovalRequest protToRequest(const AutoSudoRequest& request);