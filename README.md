# AutoSudo - Windows 权限提升工具

一个类似 Linux `sudo` 的 Windows 权限提升工具，允许在用户会话中以不同权限级别运行应用程序。

## 功能特性

- 🚀 **多权限级别支持**：用户权限、管理员权限、SYSTEM 权限
- 🔐 **允许列表机制**：基于 SHA256 哈希的可执行文件认证
- 💬 **交互式确认**：首次运行或权限提升时请求用户确认
- 🛡️ **会话隔离**：在用户桌面会话中正确显示 GUI 应用程序
- 📝 **完整日志**：详细的运行日志和审计跟踪

## 权限级别

| 级别 | 描述 | 使用示例 |
|------|------|----------|
| `--user` | 当前用户权限 | `autosudo --user notepad` |
| `--admin` | 管理员权限（默认） | `autosudo --admin cmd` |
| `--system` | SYSTEM 权限 | `autosudo --system powershell` |

## 安装和使用

### 安装服务
```bash
autosudo --install
```

### 执行命令
```bash
# 默认管理员权限
autosudo notepad.exe
autosudo "C:\Program Files\MyApp\app.exe"

# 指定权限级别
autosudo --user notepad.exe
autosudo --admin cmd.exe
autosudo --system powershell.exe
```

### 服务管理
```bash
autosudo --start      # 启动服务
autosudo --stop       # 停止服务  
autosudo --status     # 检查状态（暂未支持）
autosudo --uninstall  # 卸载服务
```

## 工作原理

1. **客户端**解析命令行参数并构建进程上下文
2. 通过**命名管道**将请求发送到服务端
3. **服务端**检查允许列表和权限级别
4. 需要时显示**用户确认对话框**
5. 使用相应权限令牌**创建目标进程**

## 构建要求

- CMake 3.10+
- C++23 兼容编译器
- Windows SDK
- SharedCppLib2 库

## 构建步骤

```bash
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

## 安全机制

- SHA256 文件完整性验证
- 命名管道通信
- 基于令牌的权限控制
- 用户交互确认

> [!WARNING]
> **安全警告**
> 
> 此项目的安全措施目前还不完备，**仅作为实验和教育用途**，不建议在生产环境中使用。
> 
> **已知安全问题**：
> - 管道通信缺乏加密
> - 允许列表文件未加密存储
> - 没有防止重放攻击的机制
> - 服务权限配置可能需要进一步加固
> 
> 使用前请评估安全风险，并考虑在隔离的测试环境中运行。

## 开发状态

🚧 **实验阶段** - 核心功能基本完成，但需要进一步的安全加固和测试。

## 许可证

暂无

## 贡献

欢迎提交 Issue 和 Pull Request 来帮助改进这个项目。