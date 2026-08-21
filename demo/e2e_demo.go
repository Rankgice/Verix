// Command e2e-demo drives a real end-to-end run of the plugin extension.
//
// It exercises two layers and prints every message so the reader can see both:
//  1. MCP layer  : demo client <-> verix.exe        (newline-delimited JSON-RPC)
//  2. Plugin layer: host peer    <-> example plugin (Content-Length framed JSON-RPC)
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"verix/sdk/protocol"
	"verix/sdk/rpc"
)

func main() {
	demoMCPLayer()
	fmt.Println("\n" + strings.Repeat("=", 80) + "\n")
	demoRPCLayer()
}

// demoMCPLayer 启动真实的 verix.exe，作为 MCP client 手动发送新行分隔的
// JSON-RPC 消息，打印“我 <-> MCP”之间的完整输入输出。
func demoMCPLayer() {
	fmt.Println("############ 第 1 层：我(演示客户端) <-> MCP(verix.exe) ############")

	cmd := exec.Command(abs("verix.exe"))
	cmd.Env = append(os.Environ(), "VERIX_PLUGIN_DIR="+abs("plugins"))
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		fmt.Println("启动 verix.exe 失败:", err)
		return
	}
	defer cmd.Process.Kill()

	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			fmt.Println("  [verix stderr]", sc.Text())
		}
	}()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	// send 发送一行 MCP 消息并打印。
	send := func(id any, method string, params any) {
		msg := map[string]any{"jsonrpc": "2.0", "method": method}
		if id != nil {
			msg["id"] = id
		}
		if params != nil {
			msg["params"] = params
		}
		b, _ := json.Marshal(msg)
		fmt.Printf("\n>>> 我 -> MCP: %s\n", string(b))
		_, _ = stdin.Write(append(b, '\n'))
	}

	// recv 读取 MCP 消息；若 wantID 非空，则跳过通知和无关响应，直到收到匹配的响应。
	recv := func(wantID string) map[string]any {
		for scanner.Scan() {
			line := scanner.Text()
			var m map[string]any
			_ = json.Unmarshal([]byte(line), &m)
			// 通知（无 id）直接打印，不参与匹配。
			if _, hasID := m["id"]; !hasID {
				fmt.Printf("<<< MCP -> 我 [通知]: %s\n", line)
				continue
			}
			id := fmt.Sprintf("%v", m["id"])
			if wantID != "" && id != wantID {
				fmt.Printf("<<< MCP -> 我 [响应 id=%s 暂存]: %s\n", id, line)
				continue
			}
			fmt.Printf("<<< MCP -> 我: %s\n", line)
			return m
		}
		return nil
	}

	send(1, "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "e2e-demo", "version": "1.0"},
	})
	recv("1")

	send(nil, "notifications/initialized", nil)
	time.Sleep(200 * time.Millisecond)

	send(2, "tools/list", map[string]any{})
	recv("2")

	send(3, "tools/call", map[string]any{
		"name":      "plugin_list",
		"arguments": map[string]any{},
	})
	recv("3")

	send(4, "tools/call", map[string]any{
		"name":      "plugin_describe",
		"arguments": map[string]any{"plugin": "com.verix.example"},
	})
	recv("4")

	send(5, "tools/call", map[string]any{
		"name": "plugin_call",
		"arguments": map[string]any{
			"plugin":    "com.verix.example",
			"method":    "echo",
			"arguments": map[string]any{"message": "你好，世界"},
		},
	})
	recv("5")
}

// demoRPCLayer 启动真实的 example-plugin.exe，扮演主程序宿主，用 sdk/rpc
// 直接驱动插件协议，打印“主程序 <-> 插件”之间的完整输入输出。
func demoRPCLayer() {
	fmt.Println("############ 第 2 层：MCP(主程序) <-> 插件(example-plugin.exe) ############")

	cmd := exec.Command(abs("plugins/example/example-plugin.exe"))
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		fmt.Println("启动 example-plugin.exe 失败:", err)
		return
	}
	defer cmd.Process.Kill()

	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			fmt.Println("  [插件 stderr]", sc.Text())
		}
	}()

	peer := rpc.NewPeer(stdout, stdin)

	// 模拟主程序注册 host.log 服务，插件调用它时会打印并回 ok。
	peer.Register("host.log", func(_ context.Context, raw json.RawMessage) (any, *protocol.Error) {
		fmt.Printf("\n>>> 插件 -> 主程序 host.log: %s\n", string(raw))
		return map[string]string{"status": "ok"}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = peer.Serve(ctx) }()

	// 1. initialize
	fmt.Printf("\n>>> 主程序 -> 插件: plugin.initialize (protocol=%s)\n", protocol.ProtocolVersion)
	var initRes protocol.InitializeResult
	if err := peer.Call(ctx, "plugin.initialize", protocol.InitializeParams{
		ProtocolVersion: protocol.ProtocolVersion,
		Host:            protocol.HostInfo{ID: "verix", Version: "1.0.0", Capabilities: []string{"host.log"}},
		Plugin:          protocol.PluginRef{ID: "com.verix.example", Version: "1.0.0"},
	}, &initRes); err != nil {
		fmt.Println("initialize 失败:", err)
		return
	}
	b, _ := json.Marshal(initRes)
	fmt.Printf("<<< 插件 -> 主程序: %s\n", string(b))

	// 2. describe
	fmt.Printf("\n>>> 主程序 -> 插件: plugin.describe\n")
	var desc protocol.DescribeResult
	if err := peer.Call(ctx, "plugin.describe", map[string]any{}, &desc); err != nil {
		fmt.Println("describe 失败:", err)
		return
	}
	b, _ = json.Marshal(desc)
	fmt.Printf("<<< 插件 -> 主程序: %s\n", string(b))

	// 3. invoke（插件执行期间会回调 host.log）
	fmt.Printf("\n>>> 主程序 -> 插件: plugin.invoke (method=echo)\n")
	var inv protocol.InvokeResult
	if err := peer.Call(ctx, "plugin.invoke", protocol.InvokeParams{
		CallID:    "call-demo-1",
		Method:    "echo",
		Arguments: json.RawMessage(`{"message":"你好，世界"}`),
	}, &inv); err != nil {
		fmt.Println("invoke 失败:", err)
		return
	}
	b, _ = json.Marshal(inv)
	fmt.Printf("<<< 插件 -> 主程序: %s\n", string(b))

	cancel()
	peer.Close()
	time.Sleep(100 * time.Millisecond)
}

func abs(p string) string {
	wd, _ := os.Getwd()
	return wd + string(os.PathSeparator) + strings.ReplaceAll(p, "/", string(os.PathSeparator))
}
