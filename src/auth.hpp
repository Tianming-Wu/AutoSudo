#pragma once

#include <filesystem>
#include <SharedCppLib2/logt.hpp>
#include <SharedCppLib2/bytearray.hpp>
#include <SharedCppLib2/stringlist.hpp>
#include <unordered_map>

namespace fs = std::filesystem;

namespace auth {

class list {
    LOGT_DECLARE
public:
    list();

    enum authLevel {
        invalid = -1, user = 0, admin = 1, system = 2
    };

    struct authdat {
        fs::path targetPath;
        std::bytearray sha;
        authLevel level;
    };

    void load();
    void save();

    void insert(const fs::path &path, authLevel al);
    void remove(const fs::path &path);

    authLevel test(const fs::path &path);

protected:
    void insert(const authdat &dat);
    bool verifyHash(const fs::path& path, const std::bytearray& expected);

private:
    std::unordered_map<fs::path, authdat> m_authlist;
    fs::path filePath;
};

extern list authlist;

} // namespace auth