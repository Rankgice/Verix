---
name: verix-mcp-usage
description: 使用 Verix MCP 主程序、数据库工具、TestSpec 工具和 dao-plugin 代码生成插件。当用户要求安装、配置、调用或排查 Verix 时使用本 skill。
---

# Verix MCP 使用说明

## 你需要先理解的项目

Verix 是一个 Go 编写的 MCP Server，运行方式是 **stdio**，不是 HTTP 服务。
它包含两部分：

1. **Verix 主程序**：提供 TestSpec 执行、校验、数据库操作和插件宿主能力。
2. **dao-plugin**：独立进程插件，根据 MySQL 或 SQLite 表结构生成 GORM DAO/model 代码。

主程序不会直接 import DAO 插件。主程序通过 `plugin.json` 发现插件，并通过 stdin/stdout RPC 启动和调用插件。

## 推荐目录布局

安装后必须保持主程序和插件目录的相对关系：

```text
<安装目录>/
├── verix                 # Linux/macOS 主程序；Windows 可为 verix.exe
└── plugins/
    └── dao-plugin/
        ├── plugin.json
        └── dao-plugin.exe
```

当前 `plugin.json` 声明的插件命令是 `dao-plugin.exe`，因此构建时请使用这个文件名；Unix 系统使用该文件名也可以正常作为可执行文件运行。

如果使用其他目录，设置：

```text
VERIX_PLUGIN_DIR=<安装目录>/plugins
```

## MCP 配置

MCP 客户端配置中的 `command` 指向主程序，不要直接指向 `dao-plugin.exe`。

示例：

```json
{
  "mcpServers": {
    "verix": {
      "command": "/绝对路径/verix",
      "args": [],
      "env": {
        "VERIX_PLUGIN_DIR": "/绝对路径/plugins"
      }
    }
  }
}
```

Windows 示例：

```json
{
  "mcpServers": {
    "verix": {
      "command": "C:\\Tools\\Verix\\verix.exe",
      "args": [],
      "env": {
        "VERIX_PLUGIN_DIR": "C:\\Tools\\Verix\\plugins"
      }
    }
  }
}
```

配置后重启 MCP 客户端。不要向 stdout 写调试日志，因为 stdout 被 MCP 协议占用。

## 工具使用顺序

### 1. 查看插件

```text
plugin_list
```

确认 `com.verix.dao` 已被发现。

### 2. 查看插件方法

```text
plugin_describe({"plugin":"com.verix.dao"})
```

先读取方法 Schema，再调用 `plugin_call`。DAO 插件有两个业务方法：

- `list_tables`：列出数据库表。
- `generate`：根据表结构生成 GORM 代码。

### 3. 列出表

MySQL：

```json
{
  "plugin": "com.verix.dao",
  "method": "list_tables",
  "arguments": {
    "db_type": "mysql",
    "dsn": "root:pass@tcp(127.0.0.1:3306)/mydb?parseTime=true"
  }
}
```

SQLite：

```json
{
  "plugin": "com.verix.dao",
  "method": "list_tables",
  "arguments": {
    "db_type": "sqlite",
    "dsn": "file:local.db"
  }
}
```

`db_type` 省略时默认 `mysql`，用于兼容旧调用。SQLite DSN 支持文件路径、`:memory:` 和 `file:` URI。

### 4. 生成代码

```json
{
  "plugin": "com.verix.dao",
  "method": "generate",
  "arguments": {
    "db_type": "sqlite",
    "dsn": "file:local.db",
    "tables": ["user_profile"],
    "package_name": "model",
    "mode": "code"
  }
}
```

- `mode=code`：返回 `files[].code`。
- `mode=file`：必须提供 `output_dir`，插件直接写入 `<output_dir>/<table>.go`。

## 主程序工具

优先使用 `plugin_describe`、`plugin_list`、`plugin_call` 了解插件能力。主程序还提供：

- `run_testspec`：执行 HTTP/gRPC TestSpec。
- `validate_testspec`：校验 TestSpec。
- `initialize_testspec`：生成或初始化 TestSpec 工作区。
- `initialize_db`：初始化 MySQL/SQLite 数据库连接。
- `list_tables`、`describe_table`、`get_schema`：读取数据库结构。
- `execute_sql`、`analyze_query`：执行或分析受安全规则约束的 SQL。

数据库工具支持运行时连接和命名连接。命名连接来自 `VERIX_DB_CONNECTIONS`；未指定连接名时使用 `initialize_db` 初始化的连接。

## TestSpec 最小认知

- TestSpec 的字段和执行规则以 `engine/types.go`、`engine/runner.go`、`设计方案.md` 为准。
- HTTP 相对路径必须配置 `meta.protocol_defaults.http.base_url`。
- gRPC 执行依赖环境中的 `grpcurl`。
- 占位符格式是 `{{vars.key}}` 和 `{{timestamp}}`。
- HTTP 和 gRPC 共用统一的 expect/extract/diff 报告结构。

## 故障排查

1. `plugin_list` 找不到 DAO：检查 `VERIX_PLUGIN_DIR`、`plugins/dao-plugin/plugin.json` 和插件可执行文件是否同目录。
2. 插件启动失败：检查 `plugin.json.runtime.command` 是否仍为 `dao-plugin.exe`，并确认文件有执行权限。
3. 调用参数错误：先执行 `plugin_describe`，严格按照 `input_schema` 传参。
4. SQLite 找不到表：确认 DSN 指向正确文件；相对路径以进程工作目录为基准。
5. 协议乱码或主程序无响应：检查插件是否向 stdout 输出了调试日志。
6. gRPC 测试失败：先确认 `grpcurl` 在 `PATH` 中。
