# AutoSudo - Windows 权限提升工具

一个类似 Linux `sudo` 的 Windows 权限提升工具，允许在用户会话中以不同权限级别运行应用程序。

## 功能特性

- 🚀 **多权限级别支持**：用户权限、管理员权限、SYSTEM 权限
- 🔐 **灵活的规则引擎**：支持路径、文件名、哈希、数字签名等多种规则模式
- 💬 **交互式确认**：可配置的情况下请求用户确认
- 🛡️ **会话隔离**：在用户桌面会话中正确显示 GUI 应用程序
- 📝 **完整日志**：详细的运行日志和审计跟踪
- 🎨 **GUI 管理界面**：通过 [AutoSudoGUI](https://github.com/Tianming-Wu/AutoSudoGUI) 项目管理规则

## 权限级别

| 级别 | 描述 | 使用示例 |
|------|------|----------|
| `--user` | 当前用户权限 | `autosudo --user notepad` |
| `--admin` | 管理员权限（默认） | `autosudo --admin cmd` |
| `--system` | SYSTEM 权限 | `autosudo --system powershell` |

## 规则引擎

AutoSudo 2.0 使用强大的规则引擎替代了旧的允许列表机制。规则引擎支持多种匹配条件：

### 支持的规则类型

- **路径匹配**：目录、完整路径、文件名、启动目录
- **文件验证**：SHA256 哈希、数字签名、文件修改时间
- **用户验证**：会话 ID、用户 SID
- **时间控制**：按日期、时间、日期时间限制
- **高级匹配**：自定义脚本、正则表达式
- **投票规则**：通过多规则组合的复杂决策逻辑

### 评估类型

每个规则可配置以下评估方式：

- **字符串**：等于、包含、以…开始/结尾、正则表达式
- **数值**：大于、小于、等于等比较
- **多项匹配**：全部匹配、任意匹配、无匹配

### 规则操作

- **Approve**：直接批准请求
- **Deny**：拒绝请求
- **RequestConfirmation**：请求用户确认
- **VoteUp/VoteDown**：为投票规则加分或减分
- **Bypass**：忽略规则

### GUI 管理工具

使用 [AutoSudoGUI](https://github.com/Tianming-Wu/AutoSudoGUI) 项目提供的图形界面轻松管理和编辑规则：

```
https://github.com/Tianming-Wu/AutoSudoGUI
```

## 安装和使用

### 安装服务
需以管理员权限执行：
```bash
AutoSudo --install
```

### 执行命令
```bash
# 默认管理员权限
AutoSudo notepad.exe
AutoSudo "C:\Program Files\MyApp\app.exe"

# 指定权限级别
AutoSudo --user notepad.exe
AutoSudo --admin cmd.exe
AutoSudo --system powershell.exe
```

也支持在非命令行环境启用，使用 AutoSudoW:
```bash
AutoSudoW --system notepad.exe
```

### 规则管理

通过 SDK 或 GUI 工具（[AutoSudoGUI](https://github.com/Tianming-Wu/AutoSudoGUI)）管理规则：

```bash
# 通过 GUI 管理界面
AutoSudoGUI.exe
```

### 服务管理
注：这些功能需要管理员权限执行
```bash
AutoSudo --start      # 启动服务
AutoSudo --stop       # 停止服务  
AutoSudo --status     # 检查状态（暂未支持）
AutoSudo --install    # 安装服务
AutoSudo --uninstall  # 卸载服务
```

## 工作原理

### 核心流程

1. **客户端**解析命令行参数并构建进程上下文
2. 通过**命名管道**将请求发送到服务端
3. **服务端**使用规则引擎评估请求
4. 根据规则结果：
   - 自动批准：直接创建进程
   - 自动拒绝：返回错误
   - 请求确认：显示**用户确认对话框**
5. 使用相应权限令牌**创建目标进程**

### 规则评估流程

1. 规则引擎依次评估规则（按配置的优先级）
2. 根据规则的 EType 进行匹配（字符串对比、正则表达式等）
3. 若匹配，执行规则的 Action（批准、拒绝、投票等）
4. 累积投票结果，最终决策：
   - **投票分数 > 0**：批准请求
   - **投票分数 < 0**：拒绝请求
   - **分数 = 0**：请求用户确认

### 通信方式

通过命名管道实现本地进程通信：

- **管道名称**：`\\.\pipe\AutoSudoPipe`
- **协议**：二进制 bytearray 格式（支持规则管理、进程执行等）
- **ConPTY 支持**：通过 Broker 进程转发标准输入/输出

### Broker 进程（ConPTY 支持）

命令行模式下，AutoSudo 使用 Broker 进程（AutoSudoBroker.exe）来处理 Windows 伪控制台 (ConPTY) 的转发：

1. 服务端启动 Broker，服务端分配一个唯一的管道名称
2. 客户端连接到该管道，进行双向通信
3. 进程输出通过该管道传回客户端

## 构建要求

- CMake 3.10+ （推荐 3.18+）
- C++23 兼容编译器（推荐使用 MSVC 2022 版本，因为这个项目是在这个版本上开发的）
- Windows SDK （10.0.19041.0 或更高版本）
- [SharedCppLib2 库](https://github.com/Tianming-Wu/SharedCppLib2) 兼容版本（一般保持最新即可，会同步更新）
- [LibPipe 库](https://github.com/Tianming-Wu/LibPipe) 兼容版本（一般保持最新即可，会同步更新）

## 项目结构

### 核心组件

- **AutoSudoSvc**：Windows 服务程序，运行规则引擎和进程管理
- **AutoSudo**：命令行客户端工具
- **AutoSudoW**：GUI 客户端（隐藏控制台窗口）
- **AutoSudoBroker**：ConPTY 管道转发进程
- **AutoSudoSdk**：库文件，供第三方（如 GUI 管理工具）使用
- **AuthUI**：用户确认对话框程序

### 关键模块

| 模块 | 位置 | 说明 |
|------|------|------|
| 协议定义 | `src/protocol.hpp/cpp` | 请求/响应序列化（二进制格式） |
| 规则引擎 | `src/approval.hpp/cpp` | 核心规则评估和管理逻辑 |
| SDK | `src/sdk.hpp/cpp` | 供 GUI 和第三方使用的接口 |
| 规则客户端 | `src/rule_client.hpp/cpp` | 规则 CRUD 操作的客户端 |
| Token 管理 | `src/wintoken.hpp/cpp` | Windows 令牌获取和管理 |
| 身份验证库 | `src/authlib.hpp/cpp` | 数字签名验证等 |

```bash
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

## 安全机制

- SHA256 文件完整性验证
- 命名管道通信（无法从外部直接访问）
- 基于令牌的权限控制
- 用户交互确认

> [!WARNING]
> **安全警告**
> 
> 此项目的安全措施目前还不完备，**仅作为实验和教育用途**，不应在生产环境中使用。
> 
> **已知安全问题**：
> - 管道通信缺乏加密
> - 规则数据库文件未加密存储 (rules.db)
> - 没有防止重放攻击的机制
> - 没有对可执行文件的参数校验规则
> - 用户确认对话框可能被钓鱼利用
> 
> **安全最佳实践**：
> - 仅在受信任的机器上使用
> - 定期审计规则配置
> - 限制规则管理权限
> - 监控 rules.db 文件的变化
>
> 使用前请评估安全风险，并自行承担遭受攻击的风险。

## 开发状态

🚧 **规则引擎实现阶段** - 核心规则引擎完成，正在完善 GUI 管理工具和高级特性。

## 开发计划

### 已完成

- [x] 基本功能实现
- [x] 多权限级别支持
- [x] **规则引擎系统** - 替代旧的允许列表
- [x] 用户交互确认
- [x] **AutoSudoSdk 库** - 供第三方工具使用
- [x] 规则 CRUD 操作
- [x] 规则排序和管理
- [x] 多种规则类型（路径、哈希、签名等）

### 进行中

- [ ] GUI 管理工具（[AutoSudoGUI](https://github.com/Tianming-Wu/AutoSudoGUI) 项目）
- [ ] 投票规则的完整实现

### 计划中

- [ ] 加密管道通信
- [ ] 添加参数安全控制规则
- [ ] 加密配置文件
- [ ] 加密凭据使用系统密钥存储（最大的后果只是丢失允许列表）
- [ ] 完善日志和审计功能
- [ ] 允许自定义 session ID（支持在其他激活用户会话中运行）
- [ ] 自动审计规则
- [ ] 防止重放攻击
- [ ] 支持对信任的数字签名可执行文件自动审计
- [ ] Lua 脚本规则引擎
- [ ] REST API 接口

## 相关项目

- **[AutoSudoGUI](https://github.com/Tianming-Wu/AutoSudoGUI)** - AutoSudo 的 GUI 管理工具，用于创建和编辑规则
- **[SharedCppLib2](https://github.com/Tianming-Wu/SharedCppLib2)** - 项目依赖的 C++ 工具库
- **[LibPipe](https://github.com/Tianming-Wu/LibPipe)** - 项目依赖的命名管道库

## 许可证

```
Tianming Wu <https://github.com/Tianming-Wu> 2023-2026

此软件是自由软件，但作者没有义务保证其适用性或安全性。
你可以自由地修改，复制，分发此软件的源代码或二进制文件，但必须随附作者信息和项目源地址。
你可以将此软件或修改后的此软件用于商业用途，无需授权。
你可以附加自己的作者信息，但不得删除原有的作者信息。
你可以在自己的项目中参考此软件的部分源代码，此种情况下不需要附带作者信息和项目源地址，但不得声称此部分代码是你原创的。
你不可以将此软件用于恶意用途，包括但不限于攻击他人计算机系统，散布恶意软件等。
你不可以发布修改后的此软件作为闭源软件。
你可以自行附加条款，但是不得与上述条款冲突。

This is free software, but the author has no obligation to guarantee its suitability or security.
You are free to modify, copy, and distribute the source code or binary files of this software, but you must include the author's information and the project source address.
You can use this software or modified versions of it for commercial purposes without authorization.
You can add your own author information, but you must not remove the original author's information.
You can reference parts of the source code of this software in your own projects, in which case you do not need to include the author's information and project source address, but you must not claim that this part of the code is your original work.
You may not use this software for malicious purposes, including but not limited to attacking other computer systems, spreading malware, etc.
You may not release modified versions of this software as closed source software.
You can add your own terms, but they must not conflict with the above terms.

```

## 贡献

欢迎提交 Issue 和 Pull Request 来帮助改进这个项目。但进行较大范围改动或主要功能开发前务必通知原作者，以免与现有的未完成开发路径冲突导致无法合并。