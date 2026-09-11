# Verix

Verix 是一个基于 Go 的 MCP Server，用于执行和校验 TestSpec 测试规范，并提供数据库工具和插件扩展能力。

## 主要能力

- 支持 HTTP、gRPC TestSpec 的校验与执行
- 支持 MySQL、SQLite 数据库工具
- 支持独立 MCP 插件
- 内置 `dao-plugin`，可根据数据库表结构生成 GORM DAO/model 代码

## 快速了解

主程序负责提供 MCP 服务，DAO Generator 是由主程序发现和启动的独立插件：

```text
Verix 主程序
└── plugins/dao-plugin/
    ├── plugin.json
    └── dao-plugin.exe
```

## 安装

本项目有两份不同用途的文档：

- **本文 README.md**：给人阅读，用于快速了解项目。
- **[INSTALL.md](INSTALL.md)**：给 AI/LLM 阅读，包含安装目录选择、源码临时拉取、两个可执行文件编译、MCP 配置、Skill 安装和安装后的旧代码清理要求。

如果需要让 AI 帮助安装或配置 Verix，请直接让它先阅读 [INSTALL.md](INSTALL.md)。

## 源码构建

需要 Go 1.25.6 或兼容版本。在仓库根目录执行：

```bash
go build -o verix .
go build -o plugins/dao-plugin/dao-plugin.exe ./plugins/dao-plugin
```

构建后的主程序和插件需要按照 [INSTALL.md](INSTALL.md) 中的目录结构放置。

## 开发说明

- 项目使用 stdio 运行 MCP，不启动 HTTP 监听端口。
- 插件通过 `plugin.json` 注册和发现。
- 新增或修改代码时，请遵守项目中的 `AGENTS.md` 规范。
- Verix 插件开发请参考：`.claude/skills/verix-plugin/`。
- Verix MCP 使用和排错请参考：`.claude/skills/verix-mcp-usage/`。

## License

License 信息以后续项目声明为准。
