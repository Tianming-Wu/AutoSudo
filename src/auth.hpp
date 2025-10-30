#pragma once

#include <filesystem>
#include <SharedCppLib2/logt.hpp>
#include <SharedCppLib2/bytearray.hpp>
#include <SharedCppLib2/stringlist.hpp>
#include <unordered_map>

#include "protocol.hpp"

namespace fs = std::filesystem;

namespace auth {

class list {
    LOGT_DECLARE
public:
    list();

    struct authdat {
        fs::path targetPath;
        std::bytearray sha;
        AuthLevel level;
    };

    void load();
    void save();

    void insert(const fs::path &path, AuthLevel al);
    void remove(const fs::path &path);

    AuthLevel test(const fs::path &path, AuthLevel requestedLevel);

protected:
    void insert(const authdat &dat);
    bool verifyHash(const fs::path& path, const std::bytearray& expected);

private:
    std::unordered_map<fs::path, authdat> m_authlist;
    fs::path filePath;
};

extern list authlist;

} // namespace auth