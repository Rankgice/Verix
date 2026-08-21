package main

import (
	"context"
	"fmt"

	"verix/sdk/plugin"
	"verix/sdk/protocol"
)

type EchoInput struct {
	Message string `json:"message"`
}

// main 启动示例插件，注册 echo 方法并交由插件 SDK 处理协议通信。
func main() {
	_ = plugin.Run(context.Background(), plugin.Options{
		ID:          "com.verix.example",
		Name:        "example",
		Version:     "1.0.0",
		Description: "Example Verix plugin",
		Manifest: []protocol.Method{
			{Name: "echo", Description: "Echo a message", Flags: protocol.MethodFlags{ReadOnly: true, Idempotent: true, SupportsCancellation: true}},
		},
		Methods: map[string]plugin.Handler{
			"echo": func(ctx context.Context, call *plugin.Call) (any, error) {
				var in EchoInput
				if err := call.DecodeInput(&in); err != nil {
					return nil, err
				}
				if err := call.Host.Log(ctx, "info", "echo called", map[string]any{"message_length": len(in.Message)}); err != nil {
					return nil, fmt.Errorf("log through host: %w", err)
				}
				return map[string]any{"message": in.Message}, nil
			},
		},
	})
}
