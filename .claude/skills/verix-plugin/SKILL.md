---
name: verix-plugin
description: 生成符合 Verix 插件体系规范的 Go 独立 EXE 插件。当用户要求“开发一个插件”“写一个 Verix 插件”“给 Verix 增加一个插件能力”“新增 plugin”时使用本 skill，产出 cmd/<name>-plugin/main.go、plugins/<name>/plugin.json 以及构建说明。
---

# Verix 插件开发

本 skill 指导生成一个可被 Verix 主程序发现、启动、描述和调用的独立 EXE 插件。

## 核心约束（务必遵守）

1. **插件是独立进程**，通过 stdin/stdout 与主程序通信，不是 `.so`，不是主程序内 import 的业务包。
2. **插件只依赖两个稳定包**：`verix/sdk/plugin`（插件运行时）和 `verix/sdk/protocol`（跨进程契约）。禁止插件 import `verix/db`、`verix/engine`、`verix/tools`、`verix/core` 或 MCP SDK。
3. **插件日志写 stderr 或走 `host.log`**，绝不向 stdout 输出非协议内容（stdout 被 RPC 占用）。
4. **命令路径必须相对插件目录**，`plugin.json` 中的 `runtime.command` 不能是绝对路径或 `..` 逃逸。
5. **业务方法自己定义**，主程序不理解业务，只负责路由、校验和返回。

## 目录布局

生成两个文件：

```text
cmd/<name>-plugin/main.go        # 插件入口，注册业务方法
plugins/<name>/plugin.json       # 静态 Manifest
```

构建产物放到 Manifest 声明的位置：

```text
plugins/<name>/<command>         # 例如 plugins/weather/weather-plugin.exe
```

## 插件入口模板（cmd/<name>-plugin/main.go）

```go
package main

import (
	"context"
	"fmt"

	"verix/sdk/plugin"
	"verix/sdk/protocol"
)

// 业务输入结构体，字段名与 plugin.json 的 input_schema 保持一致。
type GetWeatherInput struct {
	City string `json:"city"`
}

func main() {
	_ = plugin.Run(context.Background(), plugin.Options{
		ID:          "com.example.weather", // 全局唯一，推荐反向域名格式
		Name:        "weather",             // 显示名，可被 plugin_call 按名引用
		Version:     "1.0.0",
		Description: "天气查询插件",
		// 静态声明业务方法；也可省略，让 SDK 从 Methods 的 key 推导方法名。
		Manifest: []protocol.Method{
			{
				Name:        "get_weather",
				Description: "查询指定城市的当前天气",
				Flags: protocol.MethodFlags{
					ReadOnly:             true,
					Idempotent:           true,
					SupportsCancellation: true,
				},
			},
		},
		Methods: map[string]plugin.Handler{
			"get_weather": getWeather,
		},
	})
}

func getWeather(ctx context.Context, call *plugin.Call) (any, error) {
	var in GetWeatherInput
	if err := call.DecodeInput(&in); err != nil {
		return nil, err
	}

	// 可选：通过 Host SDK 记录结构化日志（需在 plugin.json 声明 host.log）。
	_ = call.Host.Log(ctx, "info", "querying weather", map[string]any{"city": in.City})

	// 这里写真正的业务逻辑，返回 any 会被序列化为 plugin_call 的 result。
	return map[string]any{
		"city":        in.City,
		"temperature": 31,
		"condition":   "sunny",
	}, nil
}
```

## plugin.json 模板（plugins/<name>/plugin.json）

```json
{
  "manifest_version": "1",
  "protocol_version": "1.0",
  "id": "com.example.weather",
  "name": "weather",
  "display_name": "Weather Plugin",
  "version": "1.0.0",
  "description": "天气查询插件",
  "runtime": {
    "command": "weather-plugin.exe",
    "args": [],
    "activation": "lazy",
    "startup_timeout_ms": 5000,
    "call_timeout_ms": 30000,
    "shutdown_timeout_ms": 3000,
    "max_concurrent_calls": 4,
    "restart_policy": "on_failure",
    "max_restarts": 3
  },
  "permissions": [
    { "name": "host.log", "reason": "记录运行日志" }
  ],
  "methods": [
    {
      "name": "get_weather",
      "description": "查询指定城市的当前天气",
      "input_schema": {
        "type": "object",
        "properties": {
          "city": { "type": "string", "description": "城市名称" }
        },
        "required": ["city"],
        "additionalProperties": false
      },
      "output_schema": {
        "type": "object",
        "properties": {
          "city": { "type": "string" },
          "temperature": { "type": "number" },
          "condition": { "type": "string" }
        },
        "required": ["city", "temperature", "condition"],
        "additionalProperties": false
      },
      "flags": {
        "read_only": true,
        "idempotent": true,
        "supports_cancellation": true
      }
    }
  ]
}
```

## 关键字段说明

### 必填字段

| 字段 | 说明 |
|---|---|
| `manifest_version` | Manifest 格式版本，固定 `"1"` |
| `protocol_version` | RPC 协议版本，必须等于 `sdk/protocol` 的 `ProtocolVersion`（当前 `"1.0"`） |
| `id` | 全局唯一插件 ID，推荐反向域名格式 `com.example.xxx` |
| `name` | 显示名，`plugin_call`/`plugin_describe` 可按名引用 |
| `version` | 语义化版本 |
| `runtime.command` | 插件 EXE 相对路径，禁止绝对路径和 `..` |

### `runtime` 可选字段

| 字段 | 默认 | 说明 |
|---|---|---|
| `args` | `[]` | 启动参数 |
| `activation` | `"lazy"` | `"lazy"` 懒启动（首次调用才启动） |
| `startup_timeout_ms` | 5000 | 启动+初始化握手超时 |
| `call_timeout_ms` | 30000 | 单次业务调用超时 |
| `shutdown_timeout_ms` | 3000 | 关闭等待超时 |
| `max_concurrent_calls` | 1 | 同插件最大并发调用数 |
| `restart_policy` | - | 当前仅 `"on_failure"` |
| `max_restarts` | - | 预留，重启上限 |

### `permissions` 可用的 Host 能力

| 权限名 | 对应 Host 方法 | 说明 |
|---|---|---|
| `host.log` | `host.log` | 结构化日志 |
| `host.config.read` | `host.config.get` | 读取主程序配置 |
| `host.storage` | `host.storage.get/put/delete` | 插件隔离的内存 Storage |

> 插件在 `plugin.json` 声明权限后，才能在 Handler 里通过 `call.Host.*` 调用对应能力；主程序会在每次调用时做权限校验。

## Host SDK 可用 API（call.Host）

| 方法 | 签名 | 用途 |
|---|---|---|
| `Log` | `Log(ctx, level, message string, fields map[string]any) error` | 记录日志，需 `host.log` |
| `ConfigGet` | `ConfigGet(ctx, key string, target any) error` | 读取配置，需 `host.config.read` |
| `StorageGet` | `StorageGet(ctx, key string) ([]byte, error)` | 读存储，需 `host.storage` |
| `StoragePut` | `StoragePut(ctx, key string, value []byte) error` | 写存储，需 `host.storage` |
| `StorageDelete` | `StorageDelete(ctx, key string) error` | 删存储，需 `host.storage` |

## 插件固有方法（SDK 自动实现，无需手写）

`plugin.Run` 自动注册以下生命周期方法，插件作者不需要处理：

```text
plugin.initialize   握手，返回插件 ID/版本/能力
plugin.describe     返回业务方法和 Schema
plugin.ping         健康检查
plugin.shutdown     关闭
plugin.cancel       取消某次调用（SDK 内部按 call_id 关联 context.CancelFunc）
plugin.invoke       业务调用统一入口，SDK 分发给 Methods 里的 Handler
```

## 生成插件的完整步骤

1. 确认插件 ID、name、version，以及需要提供哪些业务方法。
2. 为每个业务方法确定输入 JSON Schema 和输出 JSON Schema。
3. 生成 `cmd/<name>-plugin/main.go`，用 `plugin.Run` + `plugin.Options` 注册方法。
4. 生成 `plugins/<name>/plugin.json`，填写 runtime、permissions、methods。
5. 构建并放到 Manifest 声明的路径：

```bash
go build -o plugins/<name>/<command> ./cmd/<name>-plugin
```

6. 运行主程序并设置插件目录（默认 `plugins`，可用 `VERIX_PLUGIN_DIR` 覆盖）：

```bash
# Windows PowerShell
$env:VERIX_PLUGIN_DIR = "plugins"
go run .
```

7. 通过 MCP 验证：

```text
plugin_list        → 应能看到新插件，status 为 discovered
plugin_describe    → 应能看到新插件的业务方法
plugin_call        → 调用业务方法并拿到结果
```

## 注意事项

- `Methods` 的 key 必须与 `plugin.json` 的 `methods[].name` 一致，否则 describe 声明的能力与实际可调用能力会不一致。
- Handler 返回 `(nil, err)` 会被 SDK 转成 RPC 错误，返回 `(any, nil)` 会被序列化为 `plugin_call` 的 `result`。
- `call.DecodeInput(&in)` 对空参数返回 nil（不报错），适合无参方法。
- 不要用 `fmt.Println`/`log.Println` 输出日志（会污染 stdout）；用 stderr 或 `call.Host.Log`。
- 插件崩溃会由主程序按 `restart_policy` 处理；当前版本重启策略较简，避免插件内 panic 拖垮主程序。
