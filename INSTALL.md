# Verix 安装与使用指南（LLM 版）

> 本文面向负责安装、配置和使用 Verix 的 LLM。请先阅读本文，再执行命令或修改 MCP 配置。

## 1. 项目是什么

Verix 是一个 Go MCP Server，仓库地址：

```text
https://github.com/Rankgice/Verix
```

它通过 stdio 提供 MCP 能力，主要包含：

- TestSpec 校验和执行：支持 HTTP、gRPC。
- 数据库工具：支持 MySQL、SQLite。
- 插件宿主：发现并启动独立的 Verix 插件。
- `com.verix.dao` DAO Generator：读取数据库表结构，生成 GORM model/DAO 代码。

### 两个必须编译的可执行文件

安装时必须从仓库编译：

1. **Verix 主程序**：MCP 客户端实际启动它。
2. **DAO Generator 插件**：主程序按 `plugin.json` 自动发现并启动它。

不要只编译 DAO 插件，也不要把 MCP 客户端直接配置到 DAO 插件。

## 2. 先让用户选择安装目录

如果用户没有指定目录，LLM 应先询问用户选择以下目录之一；用户也可以提供自定义绝对路径。

### macOS

推荐：

```text
~/Applications/Verix
```

也可以使用：

```text
~/Library/Application Support/Verix
~/Library/Application Support/Claude/Verix
```

### Linux

推荐：

```text
~/.local/share/verix
```

也可以使用：

```text
~/Applications/verix
/opt/verix
```

`/opt/verix` 通常需要管理员权限。

### Windows

推荐：

```text
%LOCALAPPDATA%\\Verix
```

也可以使用：

```text
%USERPROFILE%\\Applications\\Verix
C:\\Tools\\Verix
```

### 选择规则

- 个人安装：选择用户目录，通常不需要管理员权限。
- 多用户安装：选择系统目录，但可能需要管理员权限。
- 不要把可执行文件散落到多个目录；主程序和 `plugins/dao-plugin` 应放在同一个安装根目录下。
- 如果用户有自定义路径，使用用户给出的路径，不要擅自改写。

下文将安装目录记为 `<VERIX_HOME>`。

## 3. 临时拉取仓库

先确认已安装 Go，版本应满足仓库 `go.mod` 的要求（当前目标版本为 Go 1.25.6）。

仓库只用于编译，安装完成后不保留 Git 仓库。建议将仓库克隆到临时目录，并记下该目录，后续验证成功后删除。

```bash
mkdir -p /tmp/verix-install
git clone https://github.com/Rankgice/Verix.git /tmp/verix-install/Verix
cd /tmp/verix-install/Verix
```

如果用户已经提供本地仓库，可以使用该仓库编译；但安装成功并验证完成后，仍应根据用户要求删除该仓库。不要删除用户明确需要继续开发的仓库。

检查项目结构：

```text
Verix/
├── main.go
├── go.mod
├── sdk/
├── tools/
├── engine/
├── db/
└── plugins/dao-plugin/
    ├── main.go
    ├── database.go
    ├── generator.go
    ├── model.go.tmpl
    └── plugin.json
```

## 4. 编译两个可执行文件

在仓库根目录执行：

### macOS / Linux

```bash
mkdir -p "<VERIX_HOME>/plugins/dao-plugin"

go build -o "<VERIX_HOME>/verix" .
go build -o "<VERIX_HOME>/plugins/dao-plugin/dao-plugin.exe" ./plugins/dao-plugin
chmod +x "<VERIX_HOME>/verix" "<VERIX_HOME>/plugins/dao-plugin/dao-plugin.exe"
cp plugins/dao-plugin/plugin.json "<VERIX_HOME>/plugins/dao-plugin/plugin.json"
```

### Windows PowerShell

```powershell
New-Item -ItemType Directory -Force "$env:LOCALAPPDATA\Verix\plugins\dao-plugin" | Out-Null

go build -o "$env:LOCALAPPDATA\Verix\verix.exe" .
go build -o "$env:LOCALAPPDATA\Verix\plugins\dao-plugin\dao-plugin.exe" .\plugins\dao-plugin
Copy-Item .\plugins\dao-plugin\plugin.json "$env:LOCALAPPDATA\Verix\plugins\dao-plugin\plugin.json" -Force
```

如果用户选择了自定义目录，把示例中的路径全部替换为 `<VERIX_HOME>`。不要把 `plugin.json` 留在源码目录而把插件二进制放到安装目录；二者必须位于同一个 `dao-plugin` 目录。

最终布局必须类似：

```text
<VERIX_HOME>/
├── verix                 # Windows 为 verix.exe
└── plugins/
    └── dao-plugin/
        ├── plugin.json
        └── dao-plugin.exe
```

当前 Manifest 中的 `runtime.command` 是 `dao-plugin.exe`。Unix 系统也请保持这个文件名，以保证跨平台布局一致。

### 安装完成后清理旧代码文件（必须）

编译、复制并验证成功后，LLM 必须执行两项清理：

1. 删除安装目录中误复制的旧源码和旧构建文件。
2. 删除本次临时拉取的 Git 仓库，安装结果不保留源码仓库。

安装目录最终只保留：

```text
<VERIX_HOME>/verix              # 或 verix.exe
<VERIX_HOME>/plugins/dao-plugin/plugin.json
<VERIX_HOME>/plugins/dao-plugin/dao-plugin.exe
```

清理前必须：

1. 先确认主程序和 DAO 插件已经能够启动，并完成 `plugin_list`、`plugin_describe` 验证。
2. 列出待删除文件并向用户确认；不要静默删除用户文件。
3. 只删除安装目录中的旧源码、临时文件、旧二进制备份和构建产物，例如 `.go`、`.tmpl`、`go.mod`、`go.sum`、`*.tmp`、`*.bak`、旧的 `verix*` 或 `dao-plugin*` 文件。
4. 保留 `plugin.json`、当前两个可执行文件和用户明确要求保留的文件。

macOS / Linux 示例（确认列表后执行）：

```bash
find "<VERIX_HOME>" -type f \
  \( -name '*.go' -o -name '*.tmpl' -o -name 'go.mod' -o -name 'go.sum' \
  -o -name '*.tmp' -o -name '*.bak' \) -print
```

Windows PowerShell 示例（确认列表后执行）：

```powershell
Get-ChildItem -Path '<VERIX_HOME>' -Recurse -File |
  Where-Object { $_.Extension -in '.go', '.tmpl', '.tmp', '.bak' -or $_.Name -in 'go.mod', 'go.sum' } |
  Select-Object -ExpandProperty FullName
```

如果旧安装目录中存在不确定用途的文件，先移动到备份目录，不要直接删除。

删除临时 Git 仓库（确认主程序和插件验证通过后执行）：

macOS / Linux：

```bash
rm -rf /tmp/verix-install/Verix
```

Windows PowerShell：

```powershell
Remove-Item -Recurse -Force '<临时目录>\Verix'
```

如果仓库不是临时目录，删除前必须向用户确认；不要删除用户明确要保留的开发仓库。

## 5. 配置 MCP 客户端

MCP 客户端的 `command` 指向主程序，并通过 `VERIX_PLUGIN_DIR` 告诉主程序插件目录。

### macOS / Linux 配置片段

```json
{
  "mcpServers": {
    "verix": {
      "command": "/绝对路径/<VERIX_HOME>/verix",
      "args": [],
      "env": {
        "VERIX_PLUGIN_DIR": "/绝对路径/<VERIX_HOME>/plugins"
      }
    }
  }
}
```

### Windows 配置片段

```json
{
  "mcpServers": {
    "verix": {
      "command": "C:\\绝对路径\\Verix\\verix.exe",
      "args": [],
      "env": {
        "VERIX_PLUGIN_DIR": "C:\\绝对路径\\Verix\\plugins"
      }
    }
  }
}
```

注意：不同 MCP 客户端的配置文件位置不同。LLM 不应假定唯一位置；应先询问用户使用的客户端，再按照该客户端的配置格式写入。不要把 `dao-plugin.exe` 作为 MCP Server 的 `command`。

配置完成后重启 MCP 客户端。

## 6. 安装两个 Verix Skill

仓库当前已有一个项目级插件开发 skill：

```text
.claude/skills/verix-plugin/SKILL.md
```

本次新增 MCP 使用 skill：

```text
.claude/skills/verix-mcp-usage/SKILL.md
```

### 先让用户选择安装范围

LLM 应询问用户：Skill 安装到：

1. **当前项目**：只对当前 Verix 仓库生效，推荐用于项目开发。
2. **全局目录**：对用户所有项目生效，推荐用于经常使用 Verix 的用户。

如果用户不希望覆盖已有 skill，先备份同名目录。

### 安装到当前项目

在仓库根目录执行：

```bash
mkdir -p .claude/skills
cp -R .claude/skills/verix-plugin .claude/skills/verix-mcp-usage <目标项目>/.claude/skills/
```

当前仓库本身已经包含这两个目录，因此在当前项目使用时无需复制；确认文件存在即可：

```bash
ls .claude/skills/verix-plugin/SKILL.md
ls .claude/skills/verix-mcp-usage/SKILL.md
```

### 安装到全局

不同 LLM 工具使用的全局 skill 根目录可能不同。LLM 应优先使用用户指定的平台目录；没有指定时先询问宿主工具。

常见目录：

```text
Claude Code：~/.claude/skills/
Codex：      ~/.codex/skills/
```

复制示例：

```bash
mkdir -p ~/.claude/skills
cp -R .claude/skills/verix-plugin ~/.claude/skills/
cp -R .claude/skills/verix-mcp-usage ~/.claude/skills/
```

如果用户使用 Codex，则将 `~/.claude/skills` 换成 `~/.codex/skills`。不要把项目 skill 自动复制到全局，除非用户明确选择全局安装。

### Skill 使用职责

- `verix-plugin`：开发新的 Verix 独立插件，维护 `cmd/<name>-plugin/main.go` 和 `plugins/<name>/plugin.json`。
- `verix-mcp-usage`：安装、配置、调用和排查 Verix MCP、数据库工具和 DAO Generator。

## 7. 安装验证

### 验证主程序可以启动

```bash
"<VERIX_HOME>/verix" --help
```

如果程序没有 `--help` 输出，不要据此判定失败；stdio MCP 程序通常会等待协议输入。此时至少确认文件可执行，并使用 MCP 客户端连接测试。

### 验证插件文件

```bash
ls -l "<VERIX_HOME>/plugins/dao-plugin/plugin.json"
ls -l "<VERIX_HOME>/plugins/dao-plugin/dao-plugin.exe"
```

### 通过 MCP 验证

依次调用：

```text
plugin_list
plugin_describe({"plugin":"com.verix.dao"})
```

然后测试 SQLite：

```text
plugin_call({
  "plugin": "com.verix.dao",
  "method": "list_tables",
  "arguments": {
    "db_type": "sqlite",
    "dsn": "file:local.db"
  }
})
```

## 8. 常用调用

### DAO Generator

```json
{
  "plugin": "com.verix.dao",
  "method": "generate",
  "arguments": {
    "db_type": "mysql",
    "dsn": "root:pass@tcp(127.0.0.1:3306)/mydb?parseTime=true",
    "tables": ["user", "user_group"],
    "package_name": "model",
    "mode": "code"
  }
}
```

SQLite：

```json
{
  "plugin": "com.verix.dao",
  "method": "generate",
  "arguments": {
    "db_type": "sqlite",
    "dsn": "file:local.db",
    "tables": ["user_profile"],
    "package_name": "model"
  }
}
```

### TestSpec

- `validate_testspec`：只校验，不执行请求。
- `run_testspec`：执行 HTTP/gRPC 测试并返回 diff 风格诊断。
- `initialize_testspec`：初始化 TestSpec 示例或工作区。

HTTP 相对路径需要 `meta.protocol_defaults.http.base_url`；gRPC 需要 `grpcurl` 在 `PATH` 中。

### 数据库工具

数据库工具支持 MySQL 和 SQLite。先调用 `initialize_db`，再按需调用 `list_tables`、`describe_table`、`get_schema`、`execute_sql` 或 `analyze_query`。SQL 工具仍受项目安全规则约束，不要绕过安全校验。

## 9. 重要排错规则

| 现象 | 检查项 |
|---|---|
| 找不到 `com.verix.dao` | `VERIX_PLUGIN_DIR` 是否指向 `<VERIX_HOME>/plugins` |
| 插件启动失败 | `plugin.json` 与 `dao-plugin.exe` 是否位于同一目录 |
| Windows 找不到文件 | 是否使用了绝对路径、反斜杠是否正确转义 |
| Unix 无法启动插件 | 是否执行 `chmod +x` |
| SQLite 找不到表 | DSN 是否指向正确数据库文件；相对路径取决于进程工作目录 |
| MCP 无响应 | 是否有日志写到了 stdout；stdout 只能用于协议通信 |
| 参数错误 | 先执行 `plugin_describe`，严格遵守 Schema |
| gRPC 失败 | `grpcurl` 是否安装并在 `PATH` 中 |

## 10. 给 LLM 的执行原则

1. 先识别操作系统、MCP 客户端、仓库是否已存在。
2. 安装目录没有明确时，先给出本文第 2 节的候选路径，让用户选择。
3. Skill 范围没有明确时，先让用户选择当前项目或全局。
4. 用户自定义路径优先于本文推荐路径。
5. 从 GitHub 临时拉取源码后，必须同时编译主程序和 DAO Generator。
6. 主程序配置到 MCP 客户端；DAO Generator 只放在 `plugins/dao-plugin/` 下，由主程序发现。
7. 安装验证成功后，必须按第 4 节清理安装目录中的旧源码和旧构建文件，并删除临时 Git 仓库；删除前先确认路径。
8. 修改插件时同时更新 `plugin.json` 和 `plugin.Options.Manifest`，保持 Schema 一致。
9. 不要向 stdout 添加调试输出。
10. 完成安装后必须执行 `plugin_list`、`plugin_describe` 和至少一次 SQLite 或 MySQL 调用验证。
