package pluginhost

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"verix/sdk/protocol"
	"verix/sdk/rpc"
)

type Status string

const (
	StatusDiscovered   Status = "discovered"
	StatusStarting     Status = "starting"
	StatusReady        Status = "ready"
	StatusStopped      Status = "stopped"
	StatusFailed       Status = "failed"
	StatusCrashed      Status = "crashed"
	StatusIncompatible Status = "incompatible"
)

type PluginSummary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	Status      Status `json:"status"`
	Methods     int    `json:"methods"`
	Error       string `json:"error,omitempty"`
}

type Options struct {
	RootDir     string
	HostID      string
	HostVersion string
	Config      map[string]json.RawMessage
	Logger      func(level, message string, fields map[string]any)
}

type Manager struct {
	opts    Options
	mu      sync.Mutex
	plugins map[string]*instance
	storage map[string]map[string]json.RawMessage
}
type instance struct {
	dir      string
	manifest protocol.Manifest
	status   Status
	err      string
	peer     *rpc.Peer
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	done     chan error
	describe *protocol.DescribeResult
	sem      chan struct{}
	startMu  sync.Mutex
}

// New 创建插件管理器，并设置默认宿主标识、版本和插件目录。
func New(opts Options) *Manager {
	if opts.HostID == "" {
		opts.HostID = "verix"
	}
	if opts.HostVersion == "" {
		opts.HostVersion = "0.1.0"
	}
	if opts.RootDir == "" {
		opts.RootDir = defaultRootDir()
	}
	if opts.Config == nil {
		opts.Config = map[string]json.RawMessage{}
	}
	return &Manager{opts: opts, plugins: map[string]*instance{}, storage: map[string]map[string]json.RawMessage{}}
}

// defaultRootDir 返回默认插件目录：优先使用可执行文件所在目录下的 plugins 子目录。
// 这样把 verix.exe 和 plugins 放在同一目录时，即使 MCP 客户端的工作目录不同，
// 也能在不设置 VERIX_PLUGIN_DIR 的情况下自动发现插件。
func defaultRootDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "plugins"
	}
	return filepath.Join(filepath.Dir(exe), "plugins")
}

// Discover 扫描插件根目录，读取并校验所有 plugin.json。
func (m *Manager) Discover() error {
	entries, err := os.ReadDir(m.opts.RootDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(m.opts.RootDir, entry.Name())
		manifestPath := filepath.Join(dir, "plugin.json")
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			continue
		}
		var manifest protocol.Manifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			continue
		}
		if err := validateManifest(dir, manifest); err != nil {
			continue
		}
		max := manifest.Runtime.MaxConcurrentCalls
		if max <= 0 {
			max = 1
		}
		m.mu.Lock()
		m.plugins[manifest.ID] = &instance{dir: dir, manifest: manifest, status: StatusDiscovered, sem: make(chan struct{}, max)}
		m.mu.Unlock()
	}
	return nil
}

// validateManifest 校验 Manifest 必填字段、协议版本和插件命令路径。
func validateManifest(dir string, manifest protocol.Manifest) error {
	if manifest.ManifestVersion == "" || manifest.ProtocolVersion == "" || manifest.ID == "" || manifest.Name == "" || manifest.Version == "" {
		return fmt.Errorf("manifest missing required field")
	}
	if manifest.ProtocolVersion != protocol.ProtocolVersion {
		return fmt.Errorf("unsupported protocol version %q", manifest.ProtocolVersion)
	}
	if manifest.Runtime.Command == "" {
		return fmt.Errorf("runtime.command is required")
	}
	command := manifest.Runtime.Command
	if filepath.IsAbs(command) {
		return fmt.Errorf("runtime.command must be relative")
	}
	resolved, err := filepath.Abs(filepath.Join(dir, command))
	if err != nil {
		return err
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("runtime.command escapes plugin directory")
	}
	return nil
}

// List 返回当前已发现插件的摘要和运行状态。
func (m *Manager) List(ctx context.Context) []PluginSummary {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PluginSummary, 0, len(m.plugins))
	for _, p := range m.plugins {
		out = append(out, m.summaryLocked(p))
	}
	return out
}

// summaryLocked 将内部插件实例转换为对外展示的摘要。
func (m *Manager) summaryLocked(p *instance) PluginSummary {
	return PluginSummary{ID: p.manifest.ID, Name: p.manifest.Name, Version: p.manifest.Version, Description: p.manifest.Description, Status: p.status, Methods: len(p.manifest.Methods), Error: p.err}
}

// Describe 启动指定插件（如有需要）并返回插件运行时能力描述。
func (m *Manager) Describe(ctx context.Context, id string) (*protocol.DescribeResult, error) {
	p, err := m.get(id)
	if err != nil {
		return nil, err
	}
	if err := m.ensureReady(ctx, p); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.describe != nil {
		copy := *p.describe
		return &copy, nil
	}
	return nil, fmt.Errorf("plugin %q did not provide description", id)
}

// Invoke 调用插件业务方法，并处理并发限制、超时和结果返回。
func (m *Manager) Invoke(ctx context.Context, id, method string, arguments any, timeout time.Duration) (json.RawMessage, error) {
	p, err := m.get(id)
	if err != nil {
		return nil, err
	}
	if err := m.ensureReady(ctx, p); err != nil {
		return nil, err
	}

	m.mu.Lock()
	if p.describe != nil {
		found := false
		for _, declared := range p.describe.Methods {
			if declared.Name == method {
				found = true
				break
			}
		}
		m.mu.Unlock()
		if !found {
			return nil, fmt.Errorf("plugin %q method %q not found", id, method)
		}
	} else {
		m.mu.Unlock()
	}

	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if timeout <= 0 {
		timeout = time.Duration(p.manifest.Runtime.CallTimeoutMS) * time.Millisecond
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := json.Marshal(arguments)
	if err != nil {
		return nil, err
	}
	callID := fmt.Sprintf("call-%d", time.Now().UnixNano())
	var result protocol.InvokeResult
	err = p.peer.CallWithID(callCtx, callID, "plugin.invoke", protocol.InvokeParams{
		CallID:    callID,
		Method:    method,
		Arguments: raw,
		Context:   protocol.CallContext{Deadline: time.Now().Add(timeout).UTC().Format(time.RFC3339Nano)},
	}, &result)
	if err != nil {
		return nil, err
	}
	return result.Output, nil
}

// get 根据插件 ID 或名称查找内部插件实例。
func (m *Manager) get(id string) (*instance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.plugins[id]
	if p == nil {
		for _, candidate := range m.plugins {
			if candidate.manifest.Name == id {
				p = candidate
				break
			}
		}
	}
	if p == nil {
		return nil, fmt.Errorf("plugin %q not found", id)
	}
	return p, nil
}

// ensureReady 确保插件已经完成启动和初始化握手。
func (m *Manager) ensureReady(ctx context.Context, p *instance) error {
	m.mu.Lock()
	status := p.status
	m.mu.Unlock()
	if status == StatusReady {
		return nil
	}
	if err := m.start(ctx, p); err != nil {
		return err
	}
	return nil
}

// start 启动插件子进程，建立 RPC 连接并完成 initialize/describe 握手。
func (m *Manager) start(ctx context.Context, p *instance) error {
	p.startMu.Lock()
	defer p.startMu.Unlock()
	m.mu.Lock()
	if p.status == StatusReady {
		m.mu.Unlock()
		return nil
	}
	p.status = StatusStarting
	p.err = ""
	m.mu.Unlock()
	command := filepath.Join(p.dir, p.manifest.Runtime.Command)
	cmd := exec.Command(command, p.manifest.Runtime.Args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return m.fail(p, err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return m.fail(p, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return m.fail(p, err)
	}
	if err := cmd.Start(); err != nil {
		return m.fail(p, err)
	}
	peer := rpc.NewPeer(stdout, stdin)
	done := make(chan error, 1)
	p.peer, p.cmd, p.stdin, p.done = peer, cmd, stdin, done
	go func() { _, _ = io.Copy(io.Discard, bufio.NewReader(stderr)) }()
	go func() { done <- peer.Serve(context.Background()) }()
	timeout := time.Duration(p.manifest.Runtime.StartupTimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	initCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var initResult protocol.InitializeResult
	if err := peer.Call(initCtx, "plugin.initialize", protocol.InitializeParams{ProtocolVersion: protocol.ProtocolVersion, Host: protocol.HostInfo{ID: m.opts.HostID, Version: m.opts.HostVersion, Capabilities: []string{"host.log", "host.config.get", "host.storage.get", "host.storage.put", "host.storage.delete"}}, Plugin: protocol.PluginRef{ID: p.manifest.ID, Version: p.manifest.Version}}, &initResult); err != nil {
		_ = cmd.Process.Kill()
		return m.fail(p, err)
	}
	if initResult.ProtocolVersion != protocol.ProtocolVersion {
		_ = cmd.Process.Kill()
		m.mu.Lock()
		p.status = StatusIncompatible
		p.err = "plugin protocol version mismatch"
		m.mu.Unlock()
		return fmt.Errorf("plugin %q protocol version mismatch", p.manifest.ID)
	}
	var desc protocol.DescribeResult
	if err := peer.Call(initCtx, "plugin.describe", map[string]any{}, &desc); err != nil {
		_ = cmd.Process.Kill()
		return m.fail(p, err)
	}
	p.describe = &desc
	peer.Register("host.log", m.hostLog(p))
	peer.Register("host.config.get", m.hostConfig(p))
	peer.Register("host.storage.get", m.hostStorageGet(p))
	peer.Register("host.storage.put", m.hostStoragePut(p))
	peer.Register("host.storage.delete", m.hostStorageDelete(p))
	m.mu.Lock()
	p.status = StatusReady
	m.mu.Unlock()
	return nil
}

// fail 将插件标记为失败并保存错误原因。
func (m *Manager) fail(p *instance, err error) error {
	m.mu.Lock()
	p.status = StatusFailed
	p.err = err.Error()
	m.mu.Unlock()
	return err
}

// Shutdown 向所有已经启动的插件发送关闭请求并终止残留进程。
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	list := make([]*instance, 0, len(m.plugins))
	for _, p := range m.plugins {
		list = append(list, p)
	}
	m.mu.Unlock()
	for _, p := range list {
		m.mu.Lock()
		ready := p.status == StatusReady
		peer := p.peer
		cmd := p.cmd
		m.mu.Unlock()
		if ready && peer != nil {
			var out any
			_ = peer.Call(ctx, "plugin.shutdown", protocol.ShutdownParams{Reason: "host_shutdown"}, &out)
		}
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}
	return nil
}

// hostLog 处理插件发来的日志请求。
func (m *Manager) hostLog(p *instance) rpc.Handler {
	return func(_ context.Context, raw json.RawMessage) (any, *protocol.Error) {
		var in protocol.HostLogParams
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, &protocol.Error{Code: protocol.InvalidParams, Message: err.Error()}
		}
		if m.opts.Logger != nil {
			m.opts.Logger(in.Level, in.Message, in.Fields)
		}
		return map[string]string{"status": "ok"}, nil
	}
}

// allowed 判断插件 Manifest 是否声明了指定的 Host 权限。
func (m *Manager) allowed(p *instance, name string) bool {
	for _, permission := range p.manifest.Permissions {
		if permission.Name == name {
			return true
		}
	}
	return false
}

// hostConfig 处理插件读取主程序配置的请求。
func (m *Manager) hostConfig(p *instance) rpc.Handler {
	return func(_ context.Context, raw json.RawMessage) (any, *protocol.Error) {
		if !m.allowed(p, "host.config.read") {
			return nil, &protocol.Error{Code: protocol.PermissionDenied, Message: "permission denied"}
		}
		var in protocol.ConfigGetParams
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, &protocol.Error{Code: protocol.InvalidParams, Message: err.Error()}
		}
		value := m.opts.Config[in.Key]
		return protocol.ConfigGetResult{Value: value}, nil
	}
}

// storageMap 返回某个插件隔离的内存 Storage 命名空间。
func (m *Manager) storageMap(p *instance) map[string]json.RawMessage {
	key := p.manifest.ID + "\x00storage"
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.storage[key]; ok {
		return v
	}
	v := map[string]json.RawMessage{}
	m.storage[key] = v
	return v
}

// hostStorageGet 处理插件读取专属 Storage 的请求。
func (m *Manager) hostStorageGet(p *instance) rpc.Handler {
	return func(_ context.Context, raw json.RawMessage) (any, *protocol.Error) {
		if !m.allowed(p, "host.storage") {
			return nil, &protocol.Error{Code: protocol.PermissionDenied, Message: "permission denied"}
		}
		var in protocol.StorageParams
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, &protocol.Error{Code: protocol.InvalidParams, Message: err.Error()}
		}
		return protocol.StorageResult{Value: m.storageMap(p)[in.Key]}, nil
	}
}

// hostStoragePut 处理插件写入专属 Storage 的请求。
func (m *Manager) hostStoragePut(p *instance) rpc.Handler {
	return func(_ context.Context, raw json.RawMessage) (any, *protocol.Error) {
		if !m.allowed(p, "host.storage") {
			return nil, &protocol.Error{Code: protocol.PermissionDenied, Message: "permission denied"}
		}
		var in protocol.StorageParams
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, &protocol.Error{Code: protocol.InvalidParams, Message: err.Error()}
		}
		m.storageMap(p)[in.Key] = in.Value
		return map[string]string{"status": "ok"}, nil
	}
}

// hostStorageDelete 处理插件删除专属 Storage 数据的请求。
func (m *Manager) hostStorageDelete(p *instance) rpc.Handler {
	return func(_ context.Context, raw json.RawMessage) (any, *protocol.Error) {
		if !m.allowed(p, "host.storage") {
			return nil, &protocol.Error{Code: protocol.PermissionDenied, Message: "permission denied"}
		}
		var in protocol.StorageParams
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, &protocol.Error{Code: protocol.InvalidParams, Message: err.Error()}
		}
		delete(m.storageMap(p), in.Key)
		return map[string]string{"status": "ok"}, nil
	}
}
