#include "approval.hpp"

#include <algorithm>
#include <functional>
#include <fstream>
#include <chrono>
#include <cstring>
#include <set>
#include <stdexcept>
#include <string_view>

// Thanks to the single-instance design of logt, this is as easy as including the header here.
#include <SharedCppLib2/logt.hpp>
#include <SharedCppLib2/basics.hpp>
#include <SharedCppLib2/sha256.hpp>
#include <SharedCppLib2/string.hpp>
#include <SharedCppLib2/xkeydb.hpp>

#include "authlib.hpp"
#include "keyvault.hpp"

SINGLE_INSTANCE_IMPL(ApprovalEngine);

namespace {

// The field values the engine defines. A rule arrives from outside either way - off the
// control channel, or out of the database - so both paths are checked against these.
// An unchecked value is not harmless: evaluate() throws on an unknown type, and a rule
// that allows a level with no token behind it decides who may run as what.

bool isKnownRuleType(ApprovalRule::Type type)
{
    switch(type) {
    case ApprovalRule::Type::Constant:
    case ApprovalRule::Type::DirectoryRule:
    case ApprovalRule::Type::FullPathRule:
    case ApprovalRule::Type::ExecutableNameRule:
    case ApprovalRule::Type::StartupDirectoryRule:
    case ApprovalRule::Type::SidRule:
    case ApprovalRule::Type::SessionRule:
    case ApprovalRule::Type::ParameterRule:
    case ApprovalRule::Type::ParametersRule:
    case ApprovalRule::Type::CustomScriptRule:
    case ApprovalRule::Type::DateRule:
    case ApprovalRule::Type::TimeRule:
    case ApprovalRule::Type::DateTimeRule:
    case ApprovalRule::Type::FileTimeRule:
    case ApprovalRule::Type::HashRule:
    case ApprovalRule::Type::VoteRule:
    case ApprovalRule::Type::DigitalSignatureRule:
        return true;
    default:
        return false;
    }
}

bool isKnownRuleEType(ApprovalRule::EType etype)
{
    switch(etype) {
    case ApprovalRule::EType::Equal:
    case ApprovalRule::EType::NotEqual:
    case ApprovalRule::EType::Contains:
    case ApprovalRule::EType::NotContains:
    case ApprovalRule::EType::BeginWith:
    case ApprovalRule::EType::NotBeginWith:
    case ApprovalRule::EType::EndWith:
    case ApprovalRule::EType::NotEndWith:
    case ApprovalRule::EType::RegexMatch:
    case ApprovalRule::EType::RegexNotMatch:
    case ApprovalRule::EType::Greater:
    case ApprovalRule::EType::GreaterEqual:
    case ApprovalRule::EType::Less:
    case ApprovalRule::EType::LessEqual:
    case ApprovalRule::EType::NoneMatches:
    case ApprovalRule::EType::AllMatches:
    case ApprovalRule::EType::AnyMatches:
        return true;
    default:
        return false;
    }
}

bool isKnownRuleAction(ApprovalRule::Action action)
{
    switch(action) {
    case ApprovalRule::Action::Approve:
    case ApprovalRule::Action::Deny:
    case ApprovalRule::Action::Bypass:
    case ApprovalRule::Action::VoteUp:
    case ApprovalRule::Action::VoteDown:
    case ApprovalRule::Action::RequestConfirmation:
        return true;
    default:
        return false;
    }
}

// Only the levels that have a token behind them can be allowed.
bool isKnownAllowUpTo(PermissionLevel level)
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

// The first bytes of a rule database, followed by the format version and the rule count.
// Without it, a file written by an older service would be read as if the current layout
// applied, and every field after the first would mean something else.
constexpr char databaseMagic[] = "ASRD";
constexpr uint16_t databaseFormatVersion = 2;

// The file the rules live in, and the file holding the key that authenticates it. Both sit
// next to the service.
constexpr const char* kDatabaseFileName = "rules.db";
constexpr const char* kKeyFileName = "rules.key";

// The database holds one entry: the engine, exactly as ApprovalEngine::dump() writes it.
// Rules are a policy as a whole - half of one is not a policy - so the whole thing is
// authenticated and replaced together.
constexpr std::string_view kEngineKey = "engine";

// lock() derives its keys with PBKDF2. This secret is 32 random bytes rather than something
// a person chose, so there is no guessing to slow down; the rounds would only cost the
// service time on every start.
constexpr uint32_t kKdfIterations = 1000;

// Move a file that could not be parsed out of the way, so a later save does not write
// over it, and so it is still there for whoever wants to look at it.
void quarantineFile(const fs::path &filePath)
{
    LOGT_LOCAL("quarantineFile");

    const fs::path target = filePath.wstring() + L".invalid";

    std::error_code ec;
    fs::remove(target, ec);
    ec.clear();

    fs::rename(filePath, target, ec);
    if(ec) {
        logt.error() << "Failed to move the unreadable file aside: " << target << ", " << ec.message();
        return;
    }

    logt.warn() << "The unreadable file was kept as: " << target;
}

} // namespace

bool ApprovalRule::evaluate(const ApprovalRequest &request) const
{
    LOGT_LOCAL("ApprovalRule::evaluate");

    switch(type) {
    case Type::Constant:                return true; // Always matches
    case Type::DirectoryRule:           return __str_e_evaluate(scl2::wstr_to_str(request.executable.parent_path().wstring()));
    case Type::FullPathRule:            return __str_e_evaluate(scl2::wstr_to_str(request.executable.wstring()));
    case Type::ExecutableNameRule:      return __str_e_evaluate(scl2::wstr_to_str(request.executable.filename().wstring()));
    case Type::StartupDirectoryRule:    return __str_e_evaluate(scl2::wstr_to_str(request.startupDirectory.wstring()));
    case Type::HashRule:                return __hash_fs_evaluate(request.executable);
    case Type::SidRule:                 return false;
    case Type::SessionRule:             return false;
    case Type::ParameterRule:           return false;
    case Type::ParametersRule:          return false;
    // case Type::EnvironmentVariableRule: // Removed support
    case Type::CustomScriptRule:        return __time_evaluate();
    case Type::DateRule:                return __time_evaluate();
    case Type::TimeRule:                return __time_evaluate();
    case Type::DateTimeRule:            return __time_evaluate();
    case Type::FileTimeRule:            return __filetime_evaluate(request.executable);
    case Type::DigitalSignatureRule:    return __digsig_evaluate(request.executable);

    case Type::VoteRule: // Voterule should not be here.
    default: {
        logt.error() << "Unknown rule type: " << static_cast<int>(type);
        throw std::logic_error("Unknown rule type");
    }
    }
}

bool ApprovalRule::operator==(const ApprovalRule &other) const
{
    return type == other.type && etype == other.etype && action == other.action && payload == other.payload;
}

bool ApprovalRule::__str_e_evaluate(const std::string &str) const
{
    LOGT_LOCAL("ApprovalRule::__str_e_evaluate");

    switch(etype) {
    case EType::Equal:
        return str == payload.toStdString();
    case EType::NotEqual:
        return str != payload.toStdString();
    case EType::Contains:
        return str.find(payload.toStdString()) != std::string::npos;
    case EType::NotContains:
        return str.find(payload.toStdString()) == std::string::npos;
    case EType::BeginWith:
        return str.rfind(payload.toStdString(), 0) == 0;
    case EType::NotBeginWith:
        return str.rfind(payload.toStdString(), 0) != 0;
    case EType::EndWith: {
        if(str.size() < payload.size()) return false;
        return str.compare(str.size() - payload.size(), payload.size(), payload.toStdString()) == 0;
    }
    case EType::NotEndWith: {
        if(str.size() < payload.size()) return true;
        return str.compare(str.size() - payload.size(), payload.size(), payload.toStdString()) != 0;
    }
    case EType::RegexMatch:
        return __regex_evaluate(str);
    case EType::RegexNotMatch:
        return !__regex_evaluate(str);
    default:
        logt.error() << "__str_e_evaluate called with invalid etype: " << static_cast<int>(etype);
        throw std::logic_error("__str_e_evaluate called with non-string etype");
    }
}

bool ApprovalRule::__val_e_evaluate(int val) const
{
    LOGT_LOCAL("ApprovalRule::__val_e_evaluate");

    int pval = payload.as<int>();
    switch(etype) {
    case EType::Greater:
        return val > pval;
    case EType::GreaterEqual:
        return val >= pval;
    case EType::Less:
        return val < pval;
    case EType::LessEqual:
        return val <= pval;
    case EType::Equal: // Reused
        return val == pval;
    case EType::NotEqual:
        return val != pval;
    default:
        logt.error() << "__val_e_evaluate called with invalid etype: " << static_cast<int>(etype);
        throw std::logic_error("__val_e_evaluate called with non-numeric etype");
    }
}

bool ApprovalRule::__regex_evaluate(const std::string &str) const
{
    LOGT_LOCAL("__regex_evaluate");

    std::regex re(payload.toStdString());
    if(etype == EType::RegexMatch) {
        return std::regex_match(str, re);
    } else if(etype == EType::RegexNotMatch) {
        return !std::regex_match(str, re);
    } else {
        logt.error() << "__regex_evaluate called with invalid etype: " << static_cast<int>(etype);
        throw std::logic_error("__regex_evaluate called with non-regex etype"); // fail the top-level evaluation.
    }
}

bool ApprovalRule::__hash_fs_evaluate(const fs::path &path) const
{
    if(!fs::exists(path)) return false; // If the file doesn't exist, we can't say it matches the hash.
    
    std::ifstream ifs(path, std::ios::binary);
    if(!ifs.is_open()) return false;

    scl2::bytearray content;
    if(!content.readAllFromStream(ifs)) return false;
    
    scl2::bytearray actualSha = scl2::sha256::hash(content);
    return actualSha == payload;
}

bool ApprovalRule::__time_evaluate() const
{
    LOGT_LOCAL("ApprovalRule::__time_evaluate");

    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    // Payload is also a time_point
    std::chrono::system_clock::time_point target = payload.as<std::chrono::system_clock::time_point>();

    switch(type) {
    case Type::DateRule:
        // Compare only the date part
        {
            std::time_t now_c = std::chrono::system_clock::to_time_t(now);
            std::tm now_tm;
            localtime_s(&now_tm, &now_c);

            std::time_t target_c = std::chrono::system_clock::to_time_t(target);
            std::tm target_tm;
            localtime_s(&target_tm, &target_c);

            int now_date = now_tm.tm_year * 10000 + now_tm.tm_mon * 100 + now_tm.tm_mday;
            int target_date = target_tm.tm_year * 10000 + target_tm.tm_mon * 100 + target_tm.tm_mday;

            return __val_e_evaluate(now_date - target_date);
        }
    case Type::TimeRule:
        // Compare only the time part
        {
            std::time_t now_c = std::chrono::system_clock::to_time_t(now);
            std::tm now_tm;
            localtime_s(&now_tm, &now_c);

            std::time_t target_c = std::chrono::system_clock::to_time_t(target);
            std::tm target_tm;
            localtime_s(&target_tm, &target_c);

            int now_time = now_tm.tm_hour * 10000 + now_tm.tm_min * 100 + now_tm.tm_sec;
            int target_time = target_tm.tm_hour * 10000 + target_tm.tm_min * 100 + target_tm.tm_sec;

            return __val_e_evaluate(now_time - target_time);
        }
    case Type::DateTimeRule:
        // Compare the full datetime
        return __val_e_evaluate(static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count() - std::chrono::duration_cast<std::chrono::seconds>(target.time_since_epoch()).count()));

    default: {
        logt.error() << "__time_evaluate called with invalid type: " << static_cast<int>(type);
        throw std::logic_error("__time_evaluate called with non-time type");
    }
    }
}

bool ApprovalRule::__filetime_evaluate(const fs::path& path) const
{
    LOGT_LOCAL("ApprovalRule::__filetime_evaluate");
    // check the executable's last modified time against the target time in payload

    if(!fs::exists(path)) return false; // If the file doesn't exist, we can't say it matches the time.

    std::error_code ec;
    auto ftime = fs::last_write_time(path, ec);
    if(ec) {
        logt.error() << "Failed to get last write time for path: " << path << ", error: " << ec.message();
        return false;
    }

    // Payload is a time_point
    std::chrono::system_clock::time_point target = payload.as<std::chrono::system_clock::time_point>();
    // They look almost the same, why the hell can't there be an conversion at all?
    std::chrono::system_clock::time_point fileTime = *reinterpret_cast<std::chrono::system_clock::time_point*>(&ftime);
    return __val_e_evaluate(static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(fileTime.time_since_epoch()).count()
                            - std::chrono::duration_cast<std::chrono::seconds>(target.time_since_epoch()).count()));
}

bool ApprovalRule::__digsig_evaluate(const fs::path &path) const
{
    // In this case payload does nothing.

    ///TODO: Later we might want to specific which signature is used.
    return authlib::VerifyDigitalSignature(path);
}

// bool ApprovalRule::__env_evaluate(const ApprovalRequest& request) const
// {
//     LOGT_LOCAL("ApprovalRule::__env_evaluate");
//     // This requires some special treatment.
//     // This rule type only accepts regex as matching pattern.

//     // struct env_var {
//     //     std::string name;
//     //     std::string value;
//     // };

//     std::regex pattern(payload.toStdString());

//     // auto __match = [&](const env_var& ev) {
//     //     std::string env_str = ev.name + "=" + ev.value;
//     //     return std::regex_match(env_str, pattern);
//     // };

//     auto __match = [&](const std::wstring& ev) {
//         return std::regex_match(platform::wstringToString(ev), pattern);
//     };

//     switch(etype) {
//     case EType::NoneMatches:
//         return std::none_of(request.environmentVariables.begin(), request.environmentVariables.end(), __match);
//     case EType::AllMatches:
//         return std::all_of(request.environmentVariables.begin(), request.environmentVariables.end(), __match);
//     case EType::AnyMatches:
//         return std::any_of(request.environmentVariables.begin(), request.environmentVariables.end(), __match);
//     default:
//         logt.error() << "__env_evaluate called with invalid etype: " << static_cast<int>(etype);
//         throw std::logic_error("__env_evaluate called with non-env etype");
//     }
// }

ApprovalRule ApprovalRule::create(Type type, EType etype, Action action, AllowUpTo allowUpTo, const scl2::bytearray &payload)
{
    // A rule carrying a value the engine does not define is a rule it cannot honour.
    // Refusing here covers every way in, the control channel included.
    if(!isKnownRuleType(type) || !isKnownRuleEType(etype) || !isKnownRuleAction(action)
       || !isKnownAllowUpTo(allowUpTo)) {
        throw std::invalid_argument("ApprovalRule::create: unknown rule field value");
    }

    if(payload.size() > limits::maxRulePayloadBytes) {
        throw std::invalid_argument("ApprovalRule::create: payload exceeds the limit");
    }

    ApprovalRule rule;

    rule.type = type;
    rule.etype = etype;
    rule.action = action;
    rule.allowUpTo = allowUpTo;

    rule.uid = 0; // uid will be assigned by the engine
    rule.order = 0;
    rule.payload = payload;

    return rule;
}

ApprovalRule ApprovalRule::load(const scl2::bytearray &data)
{
    LOGT_LOCAL("ApprovalRule::load");
    ApprovalRule rule;

    // No read-pointer manipulation here, since we might just want to
    // read a single chunk and leave the rest for other rules.
    // In this way, a single file can be read in a row.

    rule.type = data.read<Type>();
    rule.etype = data.read<EType>();
    rule.action = data.read<Action>();
    rule.allowUpTo = data.read<AllowUpTo>();
    rule.uid = data.read<apprule_uid_t>();
    rule.order = data.read<order_t>();

    // Explicit width: the payload length used to follow the machine word, so a database
    // written by a 32-bit service could not be read by a 64-bit one.
    const uint32_t payloadSize = data.read<uint32_t>();
    if(payloadSize > limits::maxRulePayloadBytes)
        throw std::runtime_error("ApprovalRule::load: payload exceeds the limit");
    rule.payload = data.readBytes(payloadSize);

    return rule;
}

scl2::bytearray ApprovalRule::dump(const ApprovalRule &rule)
{
    LOGT_LOCAL("ApprovalRule::dump");
    scl2::bytearray data;

    data.append(rule.type);
    data.append(rule.etype);
    data.append(rule.action);
    data.append(rule.allowUpTo);
    data.append(rule.uid);
    data.append(rule.order);

    // We haven't add the nested bytearray handling, so we need to
    // manually append the size and content of the payload.
    data.append(static_cast<uint32_t>(rule.payload.size()));
    data.append(rule.payload);

    return data;
}

ApprovalEngine::ApprovalEngine(bool autosave)
    : ApprovalEngine(autosave, true)
{}

ApprovalEngine::ApprovalEngine(bool autosave, bool manageSingleInstanceLifecycle)
    : autosave(autosave), manageSingleInstanceLifecycle(manageSingleInstanceLifecycle)
{
    if (this->manageSingleInstanceLifecycle) {
        s_single_instance.onCreate(this); // Mark the single instance
    }
}

ApprovalEngine::~ApprovalEngine()
{
    LOGT_LOCAL("ApprovalEngine::~ApprovalEngine");
    if(autosave) {
        if(!save()) {
            logt.error() << "Failed to save ApprovalEngine data on destruction. Data may be lost.";
        }
    }

    if (manageSingleInstanceLifecycle) {
        s_single_instance.onDestroy(); // Destroy the single instance
    }
}

ApprovalEngine::RuleMap::iterator ApprovalEngine::findByUid(apprule_uid_t uid)
{
    return std::find_if(rules.begin(), rules.end(), [uid](const auto& pair) {
        return pair.second.uid == uid;
    });
}

ApprovalEngine::RuleMap::const_iterator ApprovalEngine::findByUid(apprule_uid_t uid) const
{
    return std::find_if(rules.begin(), rules.end(), [uid](const auto& pair) {
        return pair.second.uid == uid;
    });
}

apprule_uid_t ApprovalEngine::nextAvailableUid() const
{
    apprule_uid_t uid = 1;
    while (uid != 0) {
        bool used = false;
        for (const auto& [_, rule] : rules) {
            if (rule.uid == uid) {
                used = true;
                break;
            }
        }

        if (!used) {
            return uid;
        }

        ++uid;
    }

    return 0;
}

void ApprovalEngine::normalizeOrder()
{
    RuleMap normalized;
    order_t order = 1;

    for (auto& [_, rule] : rules) {
        rule.order = order;
        normalized.emplace(order, std::move(rule));
        ++order;
    }

    rules = std::move(normalized);
}

bool ApprovalEngine::loadFile()
{
    LOGT_LOCAL("ApprovalEngine::loadFile");

    const fs::path filePath = platform::executable_dir() / "rules.db";

    if(!fs::exists(filePath)) {
        logt.info() << "Loaded 0 rules, rules.db not initialized.";
        rules.clear();
        return true;
    }

    // The database is authenticated, and it has to be opened as one before a single rule is
    // read from it. Everything that can go wrong lands in the same place: a file that is not
    // ours, one from an older build, one that somebody edited, a key that no longer matches.
    // The file is kept aside and the service carries on with no rules, which asks the user
    // about everything - the safe end of the scale.
    try {
        scl2::xkeydb::database db(filePath);

        if(!db.valid()) {
            logt.error() << "The rules database cannot be used: "
                         << scl2::xkeydb::database::describe(db.status());
            quarantineFile(filePath);
            rules.clear();
            return false;
        }

        // This service always writes it with a secret, so a file without one is not ours,
        // however valid it looks.
        if(!db.needsSecret()) {
            logt.error() << "The rules database is not authenticated, refusing it.";
            quarantineFile(filePath);
            rules.clear();
            return false;
        }

        db.unlock(keyvault::acquire(platform::executable_dir() / kKeyFileName));
        db.open();

        scl2::variant stored;
        if(!db.get(kEngineKey, stored)) {
            logt.info() << "Loaded 0 rules, the database holds none.";
            rules.clear();
            return true;
        }

        ApprovalEngine loaded = ApprovalEngine::load(stored.as_bytearray());
        rules = std::move(loaded.rules);
    } catch (const std::exception& ex) {
        logt.error() << "Failed to load " << filePath << ": " << ex.what();
        quarantineFile(filePath);
        rules.clear();
        return false;
    }

    return true;
}

bool ApprovalEngine::save() const
{
    LOGT_LOCAL("ApprovalEngine::save");

    const fs::path filePath = platform::executable_dir() / "rules.db";
    const fs::path bakPath = filePath.wstring() + L".bak";

    if(rules.empty()) {
        // No rules, remove the file.
        std::error_code ec;

        if(fs::exists(filePath)) {
            fs::copy_file(filePath, bakPath, fs::copy_options::overwrite_existing, ec);
            if(ec) {
                logt.warn() << "Failed to backup approval rules file before remove: " << bakPath << ", error: " << ec.message();
                ec.clear();
            }
        }

        fs::remove(filePath, ec);
        if(ec) {
            logt.error() << "Failed to remove approval rules file: " << filePath << ", error: " << ec.message();
            return false;
        }
        return true;   
    }

    try {
        const scl2::bytearray data = ApprovalEngine::dump(*this);
        const scl2::secure_bytearray key = keyvault::acquire(platform::executable_dir() / kKeyFileName);

        // A file that cannot be built on is moved aside first: initialize() refuses to write
        // over anything, and that is the behaviour worth keeping - only a file that is
        // already the shape of an empty database gets written to.
        {
            scl2::xkeydb::database probe(filePath);
            if(probe.exists() && (!probe.valid() || !probe.needsSecret())) {
                logt.error() << "Replacing an unusable rules database: "
                             << scl2::xkeydb::database::describe(probe.status());
                quarantineFile(filePath);
            }
        }

        scl2::xkeydb::database db(filePath);
        if(!db.exists()) {
            db.initialize();
        }

        if(!db.needsSecret()) {
            // Only lock() brings a secret, and a database without one is one the next start
            // has to refuse - so a new one gets its key before anything is written to it.
            // cipher_algo::none is the point: the rules are authenticated, not encrypted.
            db.lock(key, scl2::xkeydb::cipher_algo::none, kKdfIterations);
        } else {
            db.unlock(key);
        }

        db.open();
        db.clear();

        const scl2::xkeydb::xkeydb_error set = db.setValue(kEngineKey, scl2::variant(data));
        if(set != scl2::xkeydb::xkeydb_error::None) {
            logt.error() << "Failed to store the rules: " << scl2::xkeydb::database::describe(set);
            return false;
        }

        // save() replaces the file through a temporary one, so a failure here leaves the
        // previous database in place rather than half of a new one.
        db.save();
    } catch (const std::exception& ex) {
        logt.error() << "Failed to save " << filePath << ": " << ex.what();
        return false;
    }

    return true;
}

ApprovalResult ApprovalEngine::_evaluate(const ApprovalRequest& request) const
{
    LOGT_LOCAL("ApprovalEngine::evaluate");

    // This is the core function that evaluates all the rules and returns the final result.

    // Default to RequestConfirmation
    ApprovalResult result;
    result.result = ApprovalResultId::RequestConfirmation;
    result.allowUpTo = PermissionLevel::User;
    result.reason = std::nullopt;

    // Note: Combinition logic is currently available in the form of VoteRule.

    // Default is bypass and allow up to administrator.
    if(rules.empty()) {
        logt.info() << "No rules defined, default to approve with admin permission.";

        result.result = ApprovalResultId::Approved;
        result.allowUpTo = PermissionLevel::Admin;
        return result;
    }

    // Update: check the request.requestedPermissionLevel, and treat the rules with insufficient allowUpTo as not matched.

    std::map<apprule_uid_t, bool> ruleResults; // Cache the results of rules
    int voteScore = 0; // For VoteRules
    bool complete = false; // Whether we have a complete decision (Approve/Deny/RequestConfirmation)

    auto _action = [&](const ApprovalRule& rule) {
        switch(rule.action) {
        case ApprovalRule::Action::Approve:
            result.result = ApprovalResultId::Approved;
            result.allowUpTo = rule.allowUpTo;
            complete = true; break; // Approve/Deny comes with highest proiority
        case ApprovalRule::Action::Deny:
            result.result = ApprovalResultId::Denied;
            result.allowUpTo = PermissionLevel::NotFound;
            complete = true; break;
        case ApprovalRule::Action::RequestConfirmation:
            // Keep the default result, which is RequestConfirmation
            result.allowUpTo = rule.allowUpTo;
            complete = true; break;
        case ApprovalRule::Action::VoteUp:
            voteScore += 1;
            break;
        case ApprovalRule::Action::VoteDown:
            voteScore -= 1;
            break;
        case ApprovalRule::Action::Bypass:
            // Do nothing, just ignore this rule.
            break;
        default:
            logt.warn() << "Invalid action in rule uid " << rule.uid << ": " << static_cast<int>(rule.action);
            // throw std::logic_error("Invalid action in rule"); // fail the top-level evaluation.
            break; // Ignore invalid action, treat it as Bypass.
        }
    };

    try {

        for(const auto &[order, rule] : rules) {
            bool ruleMatch = rule.evaluate(request);

            // If the rule's allowUpTo is less than the requested level, we treat it as not matched.
            ruleMatch = ruleMatch && (rule.allowUpTo >= request.perm);

            ruleResults[rule.uid] = ruleMatch;

            if(ruleMatch) {
                // Special treatment for VoteRule:
                if(rule.type == ApprovalRule::Type::VoteRule) {
                    // Note: It is user's responsibility to set all
                    // the VoteUp/VoteDown in front of the VoteRule
                    // In order for them to work.

                    bool result = rule.__val_e_evaluate(voteScore);

                    if(result) {
                        _action(rule);
                        complete = true;
                    }
                } else {
                    _action(rule);  
                }
    
                if(complete) break; // If we already have a complete decision, no need to evaluate further rules.
            }
        }

    } catch(const std::exception &ex) {
        logt.error() << "Exception during approval evaluation: " << ex.what();
        result.result = ApprovalResultId::Fail;
        result.allowUpTo = PermissionLevel::NotFound;
        result.reason = std::string("Exception during evaluation: ") + ex.what();
    }

    if(!complete) {
        // If we do not have a complete decision after evaluating all rules
        // We will later have a policy to determine the default behavior.
        // For now, treat it as RequestConfirmation.
        result.result = ApprovalResultId::RequestConfirmation;
    }

    logt.debug() << "Approval evaluation result: " << static_cast<int>(result.result) << ", allowUpTo: " << static_cast<int>(result.allowUpTo) << ", reason: " << (result.reason.has_value() ? *result.reason : "None");

    return result;
}

apprule_uid_t ApprovalEngine::create(ApprovalRule::Type type, ApprovalRule::EType etype,
                            ApprovalRule::Action action, PermissionLevel allowUpTo, const scl2::bytearray &payload,
                            std::optional<order_t> insertAt)
{
    LOGT_LOCAL("ApprovalEngine::create");
    ApprovalRule rule = ApprovalRule::create(type, etype, action, allowUpTo, payload);

    // Assign a uid to the rule. We simply use the smallest available integer.
    // We will switch to a distrubution-based uid assignment if we are going
    // to have hundreds of rules, but now just scan.

    apprule_uid_t uid = nextAvailableUid();

    // Uid is 0 means that it overflowed and we have no available uid to assign.
    // This is pretty unlikely to happen, but we should have a check just in case.
    if(uid == 0) {
        logt.error() << "Failed to create rule: no available uid";
        throw std::runtime_error("Failed to create rule: no available uid");
    }

    rule.uid = uid;

    normalizeOrder();

    order_t targetOrder;
    if (insertAt.has_value()) {
        targetOrder = *insertAt;
        order_t maxInsert = static_cast<order_t>(rules.size() + 1);
        if (targetOrder < 1) targetOrder = 1;
        if (targetOrder > maxInsert) targetOrder = maxInsert;
    } else {
        targetOrder = static_cast<order_t>(rules.size() + 1);
    }

    RuleMap rebuilt;
    order_t outOrder = 1;
    bool inserted = false;

    for (auto& [_, existing] : rules) {
        if (!inserted && outOrder == targetOrder) {
            rule.order = outOrder;
            rebuilt.emplace(outOrder, std::move(rule));
            ++outOrder;
            inserted = true;
        }

        existing.order = outOrder;
        rebuilt.emplace(outOrder, std::move(existing));
        ++outOrder;
    }

    if (!inserted) {
        rule.order = outOrder;
        rebuilt.emplace(outOrder, std::move(rule));
    }

    rules = std::move(rebuilt);

    if(autosave && !save()) logt.error() << "Failed to save approval rules after creation. Data may be lost.";
    
    return uid;
}

bool ApprovalEngine::modify(apprule_uid_t uid, ApprovalRule::Type type, ApprovalRule::EType etype,
                            ApprovalRule::Action action, PermissionLevel allowUpTo, const scl2::bytearray &payload,
                            std::optional<order_t> moveToOrder)
{
    LOGT_LOCAL("ApprovalEngine::modify");
    ApprovalRule newRule = ApprovalRule::create(type, etype, action, allowUpTo, payload);

    auto it = findByUid(uid);
    if(it == rules.end()) {
        return false; // No such rule
    }

    order_t oldOrder = it->second.order;
    newRule.uid = uid;
    newRule.order = oldOrder;
    rules[oldOrder] = std::move(newRule);

    if (moveToOrder.has_value()) {
        if (!moveTo(uid, *moveToOrder)) {
            return false;
        }
    }

    if(autosave && !save()) logt.error() << "Failed to save approval rules after modification. Data may be lost.";
    return true;
}

bool ApprovalEngine::remove(apprule_uid_t uid)
{
    LOGT_LOCAL("ApprovalEngine::remove");

    auto it = findByUid(uid);
    if(it == rules.end()) {
        return false; // No such rule
    }
    rules.erase(it);
    normalizeOrder();

    if(autosave && !save()) logt.error() << "Failed to save approval rules after removal. Data may be lost.";
    return true;
}

bool ApprovalEngine::moveTo(apprule_uid_t uid, order_t targetOrder)
{
    LOGT_LOCAL("ApprovalEngine::moveTo");

    auto it = findByUid(uid);
    if (it == rules.end()) {
        return false;
    }

    normalizeOrder();
    it = findByUid(uid);

    order_t currentOrder = it->second.order;
    order_t maxOrder = static_cast<order_t>(rules.size());

    if (targetOrder < 1) targetOrder = 1;
    if (targetOrder > maxOrder) targetOrder = maxOrder;

    if (targetOrder == currentOrder) {
        return true;
    }

    ApprovalRule movingRule = std::move(it->second);
    rules.erase(it);

    RuleMap rebuilt;
    order_t outOrder = 1;
    bool inserted = false;

    for (auto& [_, rule] : rules) {
        if (!inserted && outOrder == targetOrder) {
            movingRule.order = outOrder;
            rebuilt.emplace(outOrder, std::move(movingRule));
            ++outOrder;
            inserted = true;
        }

        rule.order = outOrder;
        rebuilt.emplace(outOrder, std::move(rule));
        ++outOrder;
    }

    if (!inserted) {
        movingRule.order = outOrder;
        rebuilt.emplace(outOrder, std::move(movingRule));
    }

    rules = std::move(rebuilt);
    if(autosave && !save()) logt.error() << "Failed to save approval rules after move. Data may be lost.";
    return true;
}

bool ApprovalEngine::moveUp(apprule_uid_t uid)
{
    auto it = findByUid(uid);
    if (it == rules.end()) return false;
    if (it->second.order <= 1) return true;
    return moveTo(uid, static_cast<order_t>(it->second.order - 1));
}

bool ApprovalEngine::moveDown(apprule_uid_t uid)
{
    auto it = findByUid(uid);
    if (it == rules.end()) return false;
    order_t maxOrder = static_cast<order_t>(rules.size());
    if (it->second.order >= maxOrder) return true;
    return moveTo(uid, static_cast<order_t>(it->second.order + 1));
}

bool ApprovalEngine::importRules(const std::vector<RuleEntry> &incoming, std::string &reason)
{
    LOGT_LOCAL("ApprovalEngine::importRules");

    if(incoming.size() > limits::maxRules) {
        reason = "more rules than the limit allows";
        return false;
    }

    // The order the file lists them in is the order they end up in: the numbers are ours to
    // hand out, and the map the engine keeps is keyed by them.
    std::vector<RuleEntry> ordered = incoming;
    std::stable_sort(ordered.begin(), ordered.end(),
                     [](const RuleEntry& left, const RuleEntry& right) { return left.order < right.order; });

    RuleMap imported;
    std::set<apprule_uid_t> seenUids;
    order_t order = 1;

    try {
        for(const RuleEntry& entry : ordered) {
            if(entry.uid == 0) {
                reason = "a rule without a uid";
                return false;
            }

            if(!seenUids.insert(entry.uid).second) {
                reason = "two rules with uid " + std::to_string(entry.uid);
                return false;
            }

            // create() checks the field values against the ones this build defines and the
            // payload against the limit - the same checks a rule arriving over the control
            // channel goes through, because this is another way to put one there.
            ApprovalRule rule = ApprovalRule::create(
                static_cast<ApprovalRule::Type>(entry.type),
                static_cast<ApprovalRule::EType>(entry.etype),
                static_cast<ApprovalRule::Action>(entry.action),
                entry.allowUpTo,
                entry.payload);

            rule.uid = entry.uid;
            rule.order = order;
            imported.emplace(order, std::move(rule));
            ++order;
        }
    } catch(const std::exception& ex) {
        reason = ex.what();
        return false;
    }

    rules = std::move(imported);

    logt.info() << "Imported " << rules.size() << " rules, replacing what was there.";

    if(autosave) {
        save();
    }

    reason.clear();
    return true;
}

std::vector<RuleEntry> ApprovalEngine::listRules() const
{
    std::vector<RuleEntry> output;
    output.reserve(rules.size());

    for (const auto& [order, rule] : rules) {
        RuleEntry entry;
        entry.uid = rule.uid;
        entry.order = order;
        entry.type = static_cast<uint16_t>(rule.type);
        entry.etype = static_cast<uint8_t>(rule.etype);
        entry.action = static_cast<uint32_t>(rule.action);
        entry.allowUpTo = rule.allowUpTo;
        entry.payload = rule.payload;
        output.push_back(std::move(entry));
    }

    return output;
}

ApprovalEngine ApprovalEngine::load(const scl2::bytearray &data)
{
    LOGT_LOCAL("ApprovalEngine::load");
    ApprovalEngine engine(false, false);

    scl2::bytearray header = data.readBytes(sizeof(databaseMagic) - 1);
    if(std::memcmp(header.data(), databaseMagic, sizeof(databaseMagic) - 1) != 0) {
        throw std::runtime_error("not an AutoSudo rule database, or an older format");
    }

    const uint16_t formatVersion = data.read<uint16_t>();
    if(formatVersion != databaseFormatVersion) {
        throw std::runtime_error("rule database format " + std::to_string(formatVersion)
                                 + ", this build writes " + std::to_string(databaseFormatVersion));
    }

    const uint32_t ruleCount = data.read<uint32_t>();
    if(ruleCount > limits::maxRules) {
        throw std::runtime_error("rule database holds more rules than the limit allows");
    }

    logt.debug() << "Loading ApprovalEngine, expecting " << ruleCount << " rules";

    for(uint32_t i = 0; i < ruleCount; ++i) {
        ApprovalRule rule = ApprovalRule::load(data);

        // A rule the engine cannot interpret is dropped rather than carried: it would
        // either be ignored at evaluation time, or take the whole evaluation down.
        if(!isKnownRuleType(rule.type) || !isKnownRuleEType(rule.etype)
           || !isKnownRuleAction(rule.action) || !isKnownAllowUpTo(rule.allowUpTo)) {
            logt.error() << "Dropping rule uid " << rule.uid << ": it carries a field value this build does not define.";
            continue;
        }

        engine.rules.emplace(rule.order, std::move(rule));
    }

    logt.debug() << "Loaded " << engine.rules.size() << " rules";

    // Post a warning if there are still remaining data.
    if(data.remaining() > 0) {
        logt.warn() << "ApprovalEngine::load: " << data.remaining() << " bytes of data remaining after loading all rules. This may indicate malformed data.";
    }

    return engine;
}

scl2::bytearray ApprovalEngine::dump(const ApprovalEngine &engine)
{
    LOGT_LOCAL("ApprovalEngine::dump");
    scl2::bytearray data;

    // The engine header.
    data.append(reinterpret_cast<const std::byte*>(databaseMagic), sizeof(databaseMagic) - 1);
    data.append<uint16_t>(databaseFormatVersion);

    data.append(static_cast<uint32_t>(engine.rules.size()));

    for(const auto &[order, rule] : engine.rules)
        {
            data.append(ApprovalRule::dump(rule));
        }

    logt.debug() << "Dumped ApprovalEngine, " << engine.rules.size()
        << " rules, total " << prettySize(data.size());

    return data;
}

ApprovalRequest protToRequest(const AutoSudoRequest &ctx)
{
    ApprovalRequest req;

    req.executable = ctx.executableFullPath;
    req.startupDirectory = ctx.workingDirectory;
    req.arguments = ctx.arguments;

    req.perm = ctx.requestedPermissionLevel;

    req.session_id = ctx.targetSessionId;
    // req.user_sid = ctx.useCurrentSession ? ctx.userSid : 0; // If use current session, we can get the user SID from the system. Otherwise, we set it to 0, which is a special value that means "unknown user".

    // req.environmentVariables = ctx.environmentVariables;

    return req;
}
