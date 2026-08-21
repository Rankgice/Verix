package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"verix/sdk/protocol"
	"verix/sdk/rpc"
)

type Handler func(context.Context, *Call) (any, error)

type Options struct {
	ID          string
	Name        string
	Version     string
	Description string
	Methods     map[string]Handler
	Manifest    []protocol.Method
}

type Call struct {
	Arguments json.RawMessage
	Host      *HostClient
}

// DecodeInput 将插件调用参数反序列化到业务输入结构体。
func (c *Call) DecodeInput(target any) error {
	if len(c.Arguments) == 0 {
		return nil
	}
	return json.Unmarshal(c.Arguments, target)
}

// Run 启动插件 SDK，注册固有生命周期方法并进入 RPC 服务循环。
func Run(ctx context.Context, opts Options) error {
	if opts.ID == "" || opts.Name == "" || opts.Version == "" {
		return fmt.Errorf("plugin id, name, and version are required")
	}
	peer := rpc.NewPeer(os.Stdin, os.Stdout)
	host := &HostClient{peer: peer}
	active := struct {
		sync.Mutex
		calls map[string]context.CancelFunc
	}{calls: make(map[string]context.CancelFunc)}
	peer.Register("plugin.initialize", func(context.Context, json.RawMessage) (any, *protocol.Error) {
		return protocol.InitializeResult{ProtocolVersion: protocol.ProtocolVersion, PluginID: opts.ID, PluginVersion: opts.Version, Capabilities: protocol.PluginFeatures{Cancellation: true, ConcurrentCalls: true}}, nil
	})
	peer.Register("plugin.describe", func(context.Context, json.RawMessage) (any, *protocol.Error) {
		methods := opts.Manifest
		if methods == nil {
			methods = make([]protocol.Method, 0, len(opts.Methods))
			for name := range opts.Methods {
				methods = append(methods, protocol.Method{Name: name})
			}
		}
		return protocol.DescribeResult{PluginID: opts.ID, Name: opts.Name, Version: opts.Version, Description: opts.Description, Methods: methods}, nil
	})
	peer.Register("plugin.ping", func(context.Context, json.RawMessage) (any, *protocol.Error) {
		return protocol.PingResult{Status: "ok"}, nil
	})
	peer.Register("plugin.shutdown", func(context.Context, json.RawMessage) (any, *protocol.Error) {
		return map[string]string{"status": "stopping"}, nil
	})
	peer.Register("plugin.cancel", func(_ context.Context, raw json.RawMessage) (any, *protocol.Error) {
		var in protocol.CancelParams
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, &protocol.Error{Code: protocol.InvalidParams, Message: err.Error()}
		}
		active.Lock()
		cancel := active.calls[in.CallID]
		active.Unlock()
		if cancel != nil {
			cancel()
		}
		return nil, nil
	})
	peer.Register("plugin.invoke", func(parent context.Context, raw json.RawMessage) (any, *protocol.Error) {
		var in protocol.InvokeParams
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, &protocol.Error{Code: protocol.InvalidParams, Message: err.Error()}
		}
		handler := opts.Methods[in.Method]
		if handler == nil {
			return nil, &protocol.Error{Code: protocol.MethodNotFound, Message: "plugin method not found"}
		}
		callCtx, cancel := context.WithCancel(parent)
		defer cancel()
		active.Lock()
		active.calls[in.CallID] = cancel
		active.Unlock()
		defer func() { active.Lock(); delete(active.calls, in.CallID); active.Unlock() }()
		output, err := handler(callCtx, &Call{Arguments: in.Arguments, Host: host})
		if err != nil {
			return nil, &protocol.Error{Code: protocol.InternalError, Message: err.Error()}
		}
		encoded, err := json.Marshal(output)
		if err != nil {
			return nil, &protocol.Error{Code: protocol.InternalError, Message: err.Error()}
		}
		return protocol.InvokeResult{CallID: in.CallID, Output: encoded}, nil
	})
	return peer.Serve(ctx)
}

type HostClient struct{ peer *rpc.Peer }

// Log 通过 Host RPC 记录插件日志。
func (h *HostClient) Log(ctx context.Context, level, message string, fields map[string]any) error {
	return h.call(ctx, "host.log", protocol.HostLogParams{Level: level, Message: message, Fields: fields}, nil)
}

// ConfigGet 从主程序读取一个插件配置项，并解码到 target。
func (h *HostClient) ConfigGet(ctx context.Context, key string, target any) error {
	var out protocol.ConfigGetResult
	if err := h.call(ctx, "host.config.get", protocol.ConfigGetParams{Key: key}, &out); err != nil {
		return err
	}
	if len(out.Value) == 0 {
		return nil
	}
	return json.Unmarshal(out.Value, target)
}

// StorageGet 读取当前插件专属的 Host Storage 数据。
func (h *HostClient) StorageGet(ctx context.Context, key string) ([]byte, error) {
	var out protocol.StorageResult
	if err := h.call(ctx, "host.storage.get", protocol.StorageParams{Key: key}, &out); err != nil {
		return nil, err
	}
	return out.Value, nil
}

// StoragePut 写入当前插件专属的 Host Storage 数据。
func (h *HostClient) StoragePut(ctx context.Context, key string, value []byte) error {
	raw, _ := json.Marshal(value)
	return h.call(ctx, "host.storage.put", protocol.StorageParams{Key: key, Value: raw}, nil)
}

// StorageDelete 删除当前插件专属的 Host Storage 数据。
func (h *HostClient) StorageDelete(ctx context.Context, key string) error {
	return h.call(ctx, "host.storage.delete", protocol.StorageParams{Key: key}, nil)
}

// call 向主程序发送一个 Host API RPC 请求。
func (h *HostClient) call(ctx context.Context, method string, params any, result any) error {
	return h.peer.Call(ctx, method, params, result)
}
