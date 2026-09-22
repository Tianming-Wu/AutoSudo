/*
    Whole-set import and export of the approval rules.

    The caller - the GUI, or anything else using the SDK - hands over a path and nothing else,
    and the file work happens here, in the process the user is running. The service is never
    asked to touch a path: it runs as LocalSystem, and writing wherever a client pointed would
    be an arbitrary file write as LocalSystem.

    The file is one opaque blob: base64 of the compact JSON. Two reasons for that shape:

      * the enum values in it are numbers and a payload is base64, so nothing in it invites
        being edited by hand - the policy is edited where it is checked
      * a rule's payload is bytes (a path in whatever encoding it was written in, a hash), and
        base64 is what keeps them intact through a text file

    Import replaces the whole set in one request, and the service applies it with one save, so
    a failure part way through cannot leave half a policy behind.

    The layout, for anyone who has to look at one:

      { "kind": "AutoSudo rules", "format": 1,
        "rules": [ { "uid": 1, "order": 1, "type": 18, "etype": 0, "action": 1,
                     "allowUpTo": 1, "payload": "base64:..." }, ... ] }
*/

#include "sdk.hpp"

#include <SharedCppLib2/bytearray.hpp>
#include <SharedCppLib2/json.hpp>
#include <SharedCppLib2/string.hpp>
#include <SharedCppLib2/logt.hpp>

#include <fstream>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

namespace AutoSudoSdk {

namespace {

constexpr const char* kRulesKind = "AutoSudo rules";
constexpr int64_t kRulesFormat = 1;

std::string pathText(const fs::path& file)
{
    return scl2::wstr_to_str(file.wstring());
}

} // namespace

std::string describeFailure(RuleClient::Failure failure)
{
    switch (failure) {
    case RuleClient::Failure::NotReached:
        return "the service did not answer on its control channel: it is either not running, or it "
               "does not let this process in (that channel is created for administrators)";
    case RuleClient::Failure::SilentRefusal:
        return "the service took the request and closed the connection without answering it: it "
               "refused it, which is what its control channel does for a caller it does not count "
               "as an administrator";
    case RuleClient::Failure::UnreadableAnswer:
        return "the answer from the service could not be read";
    case RuleClient::Failure::None:
    default:
        return "the operation failed";
    }
}

namespace {

scl2::json rulesToDocument(const std::vector<RuleEntry>& rules)
{
    scl2::json_value list;
    list.clear_as_array();

    for (const RuleEntry& rule : rules) {
        scl2::json_value entry;
        entry.clear_as_object();

        entry["uid"] = scl2::json_value(static_cast<int64_t>(rule.uid));
        entry["order"] = scl2::json_value(static_cast<int64_t>(rule.order));
        entry["type"] = scl2::json_value(static_cast<int64_t>(rule.type));
        entry["etype"] = scl2::json_value(static_cast<int64_t>(rule.etype));
        entry["action"] = scl2::json_value(static_cast<int64_t>(rule.action));
        entry["allowUpTo"] = scl2::json_value(static_cast<int64_t>(rule.allowUpTo));
        // The json extension's "base64:..." string: a payload is bytes, not text.
        entry["payload"] = scl2::json_value(scl2::bytearray(rule.payload));

        list.push_back(std::move(entry));
    }

    scl2::json document;
    document.clear_as_object();
    document["kind"] = scl2::json_value(std::string(kRulesKind));
    document["format"] = scl2::json_value(kRulesFormat);
    document["rules"] = std::move(list);

    return document;
}

bool documentToRules(const scl2::json& document, std::vector<RuleEntry>& out, std::string& error)
{
    if (!document.is_object() || !document.has_key("kind") || !document.has_key("rules")) {
        error = "this is not a rules file";
        return false;
    }

    if (document.at("kind").as_string() != kRulesKind) {
        error = "this file was written by something else: " + document.at("kind").as_string();
        return false;
    }

    const int64_t format = document.has_key("format") ? document.at("format").as_int() : 0;
    if (format != kRulesFormat) {
        error = "rules file format " + std::to_string(format) + ", this build reads "
              + std::to_string(kRulesFormat);
        return false;
    }

    const std::vector<scl2::json_value>& list = document.at("rules").as_array();
    if (list.size() > limits::maxRules) {
        error = "the file holds more rules than the limit allows";
        return false;
    }

    for (const scl2::json_value& entry : list) {
        if (!entry.is_object()) {
            error = "a rule in the file is not an object";
            return false;
        }

        RuleEntry rule;
        rule.uid = static_cast<uint16_t>(entry.at("uid").as_int());
        rule.order = static_cast<uint16_t>(entry.at("order").as_int());
        rule.type = static_cast<uint16_t>(entry.at("type").as_int());
        rule.etype = static_cast<uint8_t>(entry.at("etype").as_int());
        rule.action = static_cast<uint32_t>(entry.at("action").as_int());
        rule.allowUpTo = static_cast<PermissionLevel>(entry.at("allowUpTo").as_int());

        if (entry.has_key("payload")) {
            rule.payload = entry.at("payload").as_bytearray();
        }

        out.push_back(std::move(rule));
    }

    return true;
}

} // namespace

bool ExportRules(const fs::path& file, std::string* error)
{
    LOGT_LOCAL("AutoSudoSdk::ExportRules");

    std::vector<RuleEntry> rules;
    RuleClient client;
    if (!client.listRules(rules)) {
        if (error != nullptr) {
            *error = describeFailure(client.failure());
        }
        return false;
    }

    const std::string compact = rulesToDocument(rules).toCompactString();
    const std::string blob = scl2::bytearray(compact).toBase64();
    const std::string path = pathText(file);

    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        if (error != nullptr) {
            *error = "could not open " + path + " for writing";
        }
        return false;
    }

    out.write(blob.data(), static_cast<std::streamsize>(blob.size()));
    out.flush();
    const bool written = out.good();
    out.close();

    if (!written) {
        if (error != nullptr) {
            *error = "could not write " + path;
        }
        return false;
    }

    logt.info() << "Exported " << rules.size() << " rule(s) to " << path;
    return true;
}

bool ImportRules(const fs::path& file, std::string* error)
{
    LOGT_LOCAL("AutoSudoSdk::ImportRules");

    const std::string path = pathText(file);

    std::ifstream in(file, std::ios::binary);
    if (!in.is_open()) {
        if (error != nullptr) {
            *error = "could not open " + path;
        }
        return false;
    }

    const std::string blob((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    if (blob.empty()) {
        if (error != nullptr) {
            *error = path + " is empty";
        }
        return false;
    }

    std::vector<RuleEntry> rules;

    try {
        const scl2::json document =
            scl2::json::fromString(scl2::bytearray::fromBase64(blob).toStdString());

        std::string parseError;
        if (!documentToRules(document, rules, parseError)) {
            if (error != nullptr) {
                *error = parseError;
            }
            return false;
        }
    } catch (const std::exception& ex) {
        if (error != nullptr) {
            *error = "could not read " + path + ": " + ex.what();
        }
        return false;
    }

    // One request, so the service replaces the set in one go rather than rule by rule.
    RuleClient client;
    if (!client.importRules(rules)) {
        if (error != nullptr) {
            *error = describeFailure(client.failure());
        }
        return false;
    }

    logt.info() << "Imported " << rules.size() << " rule(s) from " << path;
    return true;
}

} // namespace AutoSudoSdk
