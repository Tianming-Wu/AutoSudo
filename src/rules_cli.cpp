/*
    A rules CLI for debug runs.

    The GUI is how a rule set is meant to be handled, but a GUI is a poor place to test the
    machinery underneath it - every step costs a click and a window, and the interesting failures
    are in the protocol. This drives the same control channel with the same requests from a shell,
    so a set can be listed, edited, exported and imported without a window in the way.

    It works in JSON, in the shape the exported file carries but in the clear: an export is base64
    of one compact document and is deliberately not meant to be edited by hand, while what is
    written here is meant to be read and written by a person.

        rules_cli list [file]         the whole set
        rules_cli show <uid>          one rule
        rules_cli add <file>          add the rule in <file>
        rules_cli set <uid> <file>    replace the rule with that uid with the one in <file>
        rules_cli del <uid>           remove a rule
        rules_cli move <uid> <order>  move a rule
        rules_cli apply <file>        replace the whole set with the rules in <file>
        rules_cli export <file>       write the file the GUI's export writes
        rules_cli import <file>       read the file the GUI's import reads

    A rule looks like this:

        { "uid": 1, "order": 1, "type": 18, "etype": 0, "action": 1, "allowUpTo": 1,
          "payload": "base64:..." }

    `payload` is what the service stores, byte for byte. `payloadUtf8` is accepted in its place
    for the rules whose payload is text (a path, a name), because writing base64 by hand is not
    reasonable. `payloadText` in the output is for reading, and is ignored on input: it is the
    SDK's own rendering of the payload, so it is a good way to check that what was sent is what
    the service understood.

    `apply` takes the array, or an object with a "rules" array, or a single rule object. `list`
    prints the object form, so the output can be edited and fed straight back in.

    A file of "-" means standard input for input, standard output for output. Output to a file is
    the exact bytes (UTF-8); output to a console is at the mercy of its code page.

    Debug runs only in the sense that it is not part of any normal build, and it reaches the debug
    channel whatever configuration it was built in: the pipe names are pinned by a define this
    target sets, and the client side of the SDK is compiled into it so that the define reaches the
    code that picks the name. A tool that takes raw JSON should not be able to end up pointed at
    the installed service, which runs as LocalSystem and holds a policy that matters. The check in
    wmain is the same statement made at runtime, for the case of a build that lost the define.
*/

#include "sdk.hpp"
#include "rule_client.hpp"

#include <SharedCppLib2/bytearray.hpp>
#include <SharedCppLib2/json.hpp>
#include <SharedCppLib2/logt.hpp>
#include <SharedCppLib2/string.hpp>

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr int kExitOk = 0;
constexpr int kExitFailed = 1;

constexpr const char* kExitHelp =
    "usage: rules_cli list [file] | show <uid> | add <file> | set <uid> <file> | del <uid>\n"
    "       rules_cli move <uid> <order> | apply <file> | export <file> | import <file>\n";

int fail(const std::string& message)
{
    std::cerr << "rules_cli: " << message << "\n";
    return kExitFailed;
}

// ---------------------------------------------------------------- json

int64_t numberField(const scl2::json_value& node, const char* key, int64_t fallback)
{
    return node.has_key(key) ? node.at(key).as_int() : fallback;
}

scl2::json_value ruleToJson(const RuleEntry& rule)
{
    scl2::json_value entry;
    entry.clear_as_object();

    entry["uid"] = scl2::json_value(static_cast<int64_t>(rule.uid));
    entry["order"] = scl2::json_value(static_cast<int64_t>(rule.order));
    entry["type"] = scl2::json_value(static_cast<int64_t>(rule.type));
    entry["etype"] = scl2::json_value(static_cast<int64_t>(rule.etype));
    entry["action"] = scl2::json_value(static_cast<int64_t>(rule.action));
    entry["allowUpTo"] = scl2::json_value(static_cast<int64_t>(static_cast<int>(rule.allowUpTo)));
    entry["payload"] = scl2::json_value(scl2::bytearray(rule.payload));
    // For reading only. The payload is bytes and the bytes are what gets sent.
    entry["payloadText"] = scl2::json_value(AutoSudoSdk::ParseRulePayload(rule));

    return entry;
}

scl2::json rulesToJson(const std::vector<RuleEntry>& rules)
{
    scl2::json_value list;
    list.clear_as_array();
    for (const RuleEntry& rule : rules) {
        list.push_back(ruleToJson(rule));
    }

    scl2::json document;
    document.clear_as_object();
    document["kind"] = scl2::json_value(std::string("AutoSudo rules"));
    document["format"] = scl2::json_value(static_cast<int64_t>(1));
    document["rules"] = std::move(list);

    return document;
}

bool ruleFromJson(const scl2::json_value& node, RuleEntry& rule, std::string& error)
{
    if (!node.is_object()) {
        error = "a rule has to be a json object";
        return false;
    }

    if (!node.has_key("uid")) {
        error = "a rule has to carry a uid";
        return false;
    }

    // allowUpTo defaults to Admin: a rule someone wrote by hand is more likely to be about an
    // application than about the whole machine.
    rule.uid = static_cast<uint16_t>(numberField(node, "uid", 0));
    rule.order = static_cast<uint16_t>(numberField(node, "order", 0));
    rule.type = static_cast<uint16_t>(numberField(node, "type", 0));
    rule.etype = static_cast<uint8_t>(numberField(node, "etype", 0));
    rule.action = static_cast<uint32_t>(numberField(node, "action", 0));
    rule.allowUpTo = static_cast<PermissionLevel>(numberField(node, "allowUpTo", 1));

    if (node.has_key("payload")) {
        rule.payload = node.at("payload").as_bytearray();
    } else if (node.has_key("payloadUtf8")) {
        rule.payload = scl2::bytearray::fromStdString(node.at("payloadUtf8").as_string());
    }
    // A rule can legitimately have no payload - DigitalSignatureRule is decided by the signature
    // itself - so an absent payload is left empty rather than refused.

    return true;
}

// Accepts the three shapes `list`, `show` and a hand-written file can be in.
bool rulesFromJson(const scl2::json& document, std::vector<RuleEntry>& rules, std::string& error)
{
    const scl2::json_value* list = nullptr;

    if (document.is_array()) {
        list = &document;
    } else if (document.is_object() && document.has_key("rules")) {
        list = &document.at("rules");
    }

    if (list == nullptr) {
        RuleEntry rule;
        if (!ruleFromJson(document, rule, error)) {
            return false;
        }
        rules.push_back(std::move(rule));
        return true;
    }

    if (!list->is_array()) {
        error = "\"rules\" has to be an array";
        return false;
    }

    for (const scl2::json_value& entry : list->as_array()) {
        RuleEntry rule;
        if (!ruleFromJson(entry, rule, error)) {
            return false;
        }
        rules.push_back(std::move(rule));
    }

    return true;
}

// ---------------------------------------------------------------- files

bool readText(const std::wstring& source, std::string& text, std::string& error)
{
    if (source == L"-") {
        text.assign(std::istreambuf_iterator<char>(std::cin), std::istreambuf_iterator<char>());
        return true;
    }

    std::ifstream in(fs::path(source), std::ios::binary);
    if (!in.is_open()) {
        error = "could not open " + scl2::wstr_to_str(source);
        return false;
    }

    text.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

bool writeText(const std::wstring& target, const std::string& text, std::string& error)
{
    if (target == L"-") {
        std::cout << text << "\n";
        return true;
    }

    std::ofstream out(fs::path(target), std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        error = "could not open " + scl2::wstr_to_str(target) + " for writing";
        return false;
    }

    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    out.flush();

    if (!out.good()) {
        error = "could not write " + scl2::wstr_to_str(target);
        return false;
    }

    return true;
}

bool readRules(const std::wstring& source, std::vector<RuleEntry>& rules, std::string& error)
{
    std::string text;
    if (!readText(source, text, error)) {
        return false;
    }

    if (text.empty()) {
        error = "the input is empty";
        return false;
    }

    try {
        return rulesFromJson(scl2::json::fromString(text), rules, error);
    } catch (const std::exception& ex) {
        error = std::string("could not read the input: ") + ex.what();
        return false;
    }
}

bool parseUid(const std::wstring& text, uint16_t& uid)
{
    try {
        const unsigned long value = std::stoul(text);
        if (value == 0 || value > 0xFFFF) {
            return false;
        }
        uid = static_cast<uint16_t>(value);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

// ---------------------------------------------------------------- commands

int listRules(const std::wstring& target)
{
    std::vector<RuleEntry> rules;
    RuleClient client;
    if (!client.listRules(rules)) {
        return fail(AutoSudoSdk::describeFailure(client.failure()));
    }

    std::string error;
    if (!writeText(target, rulesToJson(rules).toString(), error)) {
        return fail(error);
    }

    return kExitOk;
}

int showRule(uint16_t uid)
{
    std::vector<RuleEntry> rules;
    RuleClient client;
    if (!client.listRules(rules)) {
        return fail(AutoSudoSdk::describeFailure(client.failure()));
    }

    for (const RuleEntry& rule : rules) {
        if (rule.uid == uid) {
            scl2::json_value value = ruleToJson(rule);
            std::cout << scl2::json(std::move(value)).toString() << "\n";
            return kExitOk;
        }
    }

    return fail("no rule with uid " + std::to_string(uid));
}

int addRule(const std::wstring& source)
{
    std::vector<RuleEntry> rules;
    std::string error;
    if (!readRules(source, rules, error)) {
        return fail(error);
    }

    if (rules.size() != 1) {
        return fail("add takes exactly one rule, this file holds " + std::to_string(rules.size()));
    }

    const RuleEntry& rule = rules.front();
    RuleClient client;
    const uint16_t uid = client.createRule(static_cast<AutoSudoSdk::Rule::Type>(rule.type),
                                           static_cast<AutoSudoSdk::Rule::EType>(rule.etype),
                                           static_cast<AutoSudoSdk::Rule::Action>(rule.action),
                                           rule.allowUpTo, rule.payload, rule.order);

    if (uid == 0) {
        return fail(AutoSudoSdk::describeFailure(client.failure()));
    }

    std::cout << "created uid " << uid << "\n";
    return kExitOk;
}

int setRule(uint16_t uid, const std::wstring& source)
{
    std::vector<RuleEntry> rules;
    std::string error;
    if (!readRules(source, rules, error)) {
        return fail(error);
    }

    if (rules.size() != 1) {
        return fail("set takes exactly one rule, this file holds " + std::to_string(rules.size()));
    }

    const RuleEntry& rule = rules.front();
    RuleClient client;
    if (!client.modifyRule(uid, static_cast<AutoSudoSdk::Rule::Type>(rule.type),
                           static_cast<AutoSudoSdk::Rule::EType>(rule.etype),
                           static_cast<AutoSudoSdk::Rule::Action>(rule.action),
                           rule.allowUpTo, rule.payload, rule.order)) {
        return fail(AutoSudoSdk::describeFailure(client.failure()));
    }

    std::cout << "uid " << uid << " updated\n";
    return kExitOk;
}

int deleteRule(uint16_t uid)
{
    RuleClient client;
    if (!client.deleteRule(uid)) {
        return fail(AutoSudoSdk::describeFailure(client.failure()));
    }

    std::cout << "uid " << uid << " deleted\n";
    return kExitOk;
}

int moveRule(uint16_t uid, uint16_t order)
{
    RuleClient client;
    if (!client.moveRule(uid, order)) {
        return fail(AutoSudoSdk::describeFailure(client.failure()));
    }

    std::cout << "uid " << uid << " moved to order " << order << "\n";
    return kExitOk;
}

int applyRules(const std::wstring& source)
{
    std::vector<RuleEntry> rules;
    std::string error;
    if (!readRules(source, rules, error)) {
        return fail(error);
    }

    // One request and one save on the service side, so a refusal cannot leave half a set behind.
    RuleClient client;
    if (!client.importRules(rules)) {
        return fail(AutoSudoSdk::describeFailure(client.failure()));
    }

    std::cout << "applied " << rules.size() << " rule(s)\n";
    return kExitOk;
}

int exportRules(const std::wstring& target)
{
    if (target == L"-") {
        std::cout << "export writes a file; give it a name\n";
        return kExitFailed;
    }

    std::string error;
    if (!AutoSudoSdk::ExportRules(fs::path(target), &error)) {
        return fail(error);
    }

    std::cout << "exported to " << scl2::wstr_to_str(target) << "\n";
    return kExitOk;
}

int importRules(const std::wstring& source)
{
    if (source == L"-") {
        std::cout << "import reads a file; give it a name\n";
        return kExitFailed;
    }

    std::string error;
    if (!AutoSudoSdk::ImportRules(fs::path(source), &error)) {
        return fail(error);
    }

    std::cout << "imported from " << scl2::wstr_to_str(source) << "\n";
    return kExitOk;
}

// The tool must never reach the installed service, whatever it was built with. The forced debug
// channel above should make this impossible to fail - it is here to catch the build that lost the
// define, by accident or by someone linking the SDK instead of compiling it in, because the
// consequence would be a rule editor pointed at a service holding a policy nobody asked it to
// touch.
bool debugChannelOnly()
{
    return std::string(controlPipeName).find("__dbg__") != std::string::npos;
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    // The SDK logs while it works, and the logging system has to be closed before the process
    // leaves, whichever way this returns. The guard is here so every return below is covered.
    logt_guard guard;

    if (!debugChannelOnly()) {
        return fail("this tool only talks to the debug channel, and this build is pointed elsewhere");
    }

    if (argc < 2) {
        std::cout << kExitHelp;
        return kExitFailed;
    }

    const std::wstring command = argv[1];

    if (command == L"list") {
        return listRules(argc > 2 ? argv[2] : L"-");
    }

    if (command == L"show" && argc == 3) {
        uint16_t uid = 0;
        return parseUid(argv[2], uid) ? showRule(uid) : fail("that is not a uid: " + scl2::wstr_to_str(argv[2]));
    }

    if (command == L"add" && argc == 3) {
        return addRule(argv[2]);
    }

    if (command == L"set" && argc == 4) {
        uint16_t uid = 0;
        return parseUid(argv[2], uid) ? setRule(uid, argv[3])
                                      : fail("that is not a uid: " + scl2::wstr_to_str(argv[2]));
    }

    if (command == L"del" && argc == 3) {
        uint16_t uid = 0;
        return parseUid(argv[2], uid) ? deleteRule(uid) : fail("that is not a uid: " + scl2::wstr_to_str(argv[2]));
    }

    if (command == L"move" && argc == 4) {
        uint16_t uid = 0;
        uint16_t order = 0;
        if (!parseUid(argv[2], uid) || !parseUid(argv[3], order)) {
            return fail("move takes a uid and an order");
        }
        return moveRule(uid, order);
    }

    if (command == L"apply" && argc == 3) {
        return applyRules(argv[2]);
    }

    if (command == L"export" && argc == 3) {
        return exportRules(argv[2]);
    }

    if (command == L"import" && argc == 3) {
        return importRules(argv[2]);
    }

    std::cout << kExitHelp;
    return kExitFailed;
}
