#include "auth.hpp"

#include <fstream>
#include <string>
#include <SharedCppLib2/platform.hpp>
#include <SharedCppLib2/sha256.hpp>
#include <SharedCppLib2/stringlist.hpp>

namespace auth {

LOGT_DEFINE(list, "auth::list");
list authlist;

list::list()
    : filePath(platform::executable_dir()/".authlist")
{}

void list::load() {
    m_authlist.clear();

    if(!fs::exists(filePath)) {
        // Create an empty list
        std::ofstream ofs(filePath);
        if(!ofs.is_open() || ofs.bad()) {
            logt.fatal() << "Unable to create allow list at: " << filePath;
            logt::shutdown();
            exit(1);
        }
        ofs.close();
        return;
    }


    std::ifstream ifs(filePath);
    if(!ifs.is_open() || ifs.bad()) {
        logt.error() << "Failed to open allow list.";
        return;
    }

    std::string line;
    int lineNumber = 0;
    int loadedCount = 0;
        
    while(std::getline(ifs, line)) {
        lineNumber++;
        
        // 跳过空行和注释
        if(line.empty() || line[0] == '#') {
            continue;
        }
        
        // 解析格式: 文件路径|权限级别|SHA256哈希
        std::stringlist sl(line, "|");
        if(!sl.size()==3) {
            logt.warn() << "Invalid authlist format at line " << lineNumber;
            continue;
        }

        std::string &pathStr = sl[0];
        authLevel al;
        std::string &shaStr = sl[2];

        try {
            al = static_cast<authLevel>(std::stoi(sl[1]));
        } catch(...) {
            logt.warn() << "Invalid allow level found at line " << lineNumber << ", fallback to user.";
            al = authLevel::user;
        }
        
        // 验证SHA256格式（64个十六进制字符）
        if(shaStr.length() != 64) {
            logt.warn() << "Invalid SHA256 format at line " << lineNumber;
            continue;
        }
        
        authdat ad;
        ad.targetPath = fs::path(pathStr);
        ad.level = al;
        ad.sha = std::bytearray::fromHex(shaStr);
        
        if(ad.sha.empty()) {
            logt.warn() << "Failed to parse SHA256 at line " << lineNumber;
            continue;
        }
        
        m_authlist[ad.targetPath] = ad;
        loadedCount++;
    }
    
    ifs.close();
    logt.info() << "Loaded " << loadedCount << " entries from allow list";
}

void list::save() {
    std::ofstream ofs(filePath);
    if(!ofs.is_open() || ofs.bad()) {
        logt.error() << "Failed to save allow list: " << filePath;
        return;
    }
    
    // 添加文件头注释
    ofs << "# AutoSudo Allow List" << std::endl;
    ofs << "# Format: file_path|level|sha256_hash" << std::endl;
    ofs << "# Generated automatically - do not edit manually" << std::endl;
    ofs << std::endl;
    
    for(const auto& [path, data] : m_authlist) {
        ofs << path.string() << "|" << std::to_string(data.level) << "|" << data.sha.tohex() << std::endl;
    }
    
    ofs.close();
    logt.info() << "Saved " << m_authlist.size() << " entries to allow list";
}

void list::insert(const list::authdat &dat) {
    logt.info() << "Inserting new entry to allow list: " << dat.targetPath;
    m_authlist.insert(std::make_pair(dat.targetPath, dat));
    save();
}

void list::insert(const fs::path &path, authLevel al) {
    if(!fs::exists(path)) {
        logt.error() << "File does not exist: " << path;
        return;
    }

    authdat ad;
    ad.targetPath = path;
    ad.level = al;

    std::ifstream ifs(path);
    if(!ifs.is_open() || ifs.bad()) {
        logt.error() << "Failed to open file while attempting to calcutate sha256 for " << path;
        return;
    }

    std::bytearray content;
    if(content.readAllFromStream(ifs)) {
        ad.sha = sha256::getMessageDigest(content);
        ifs.close();

        insert(ad);
    } else {
        logt.error() << "Failed to load file while attempting to calcutate sha256 for " << path;
    }
}

void list::remove(const fs::path &path) {
    auto it = m_authlist.find(path);
    if(it != m_authlist.end()) {
        logt.info() << "Removing entry from allow list: " << path;
        m_authlist.erase(it);
        save(); // 自动保存
    } else {
        logt.warn() << "Attempted to remove non-existent entry: " << path;
    }
}


list::authLevel list::test(const fs::path &path) {
    auto it = m_authlist.find(path);
    if(it != m_authlist.end()) {
        // 可选：验证文件哈希是否仍然匹配
        if(verifyHash(path, it->second.sha)) {
            logt.info() << "Request authorized: " << path;
            return it->second.level;
        } else {
            logt.warn() << "File hash mismatch for: " << path;
            return invalid;
        }
    }

    logt.warn() << "Request blocked unauthorized: " << path;
    return invalid;
}

bool list::verifyHash(const fs::path &path, const std::bytearray &expected)
{
    if(!fs::exists(path)) {
        return false;
    }
    
    std::ifstream ifs(path, std::ios::binary);
    if(!ifs.is_open()) {
        return false;
    }
    
    std::bytearray content;
    if(!content.readAllFromStream(ifs)) {
        return false;
    }
    
    std::bytearray actualSha = sha256::getMessageDigest(content);
    return actualSha == expected;
}

} // namespace auth