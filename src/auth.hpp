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

    struct authdat {
        fs::path targetPath;
        std::bytearray sha;
    };

    void load();
    void save();

    void insert(const fs::path &path);
    void remove(const fs::path &path);

    bool test(const fs::path &path);

protected:
    void insert(const authdat &dat);
    bool verifyHash(const fs::path& path, const std::bytearray& expected);

private:
    std::unordered_map<fs::path, authdat> m_authlist;
    fs::path filePath;
};

extern list authlist;

} // namespace auth