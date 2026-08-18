package rpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"verix/sdk/protocol"
)

type Handler func(context.Context, json.RawMessage) (any, *protocol.Error)

type Peer struct {
	reader     *bufio.Reader
	writer     io.Writer
	writeMu    sync.Mutex
	pendingMu  sync.Mutex
	pending    map[string]chan protocol.Response
	handlersMu sync.RWMutex
	handlers   map[string]Handler
	nextID     atomic.Uint64
	closed     chan struct{}
	closeOnce  sync.Once
	done       chan struct{}
}

// NewPeer 创建一条基于输入流和输出流的双向 RPC 连接。
func NewPeer(r io.Reader, w io.Writer) *Peer {
	return &Peer{reader: bufio.NewReader(r), writer: w, pending: make(map[string]chan protocol.Response), handlers: make(map[string]Handler), closed: make(chan struct{}), done: make(chan struct{})}
}

// Register 注册一个 RPC 方法，用于处理对端发来的请求。
func (p *Peer) Register(method string, handler Handler) {
	p.handlersMu.Lock()
	defer p.handlersMu.Unlock()
	p.handlers[method] = handler
}

// Serve 持续读取并分发 RPC 消息，直到连接关闭或上下文结束。
func (p *Peer) Serve(ctx context.Context) error {
	defer close(p.done)
	for {
		select {
		case <-ctx.Done():
			p.Close()
			return ctx.Err()
		case <-p.closed:
			return nil
		default:
		}
		msg, err := readMessage(p.reader)
		if err != nil {
			p.Close()
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if len(msg.ID) > 0 && msg.Method == "" {
			var resp protocol.Response
			if err := json.Unmarshal(msg.Raw, &resp); err != nil {
				continue
			}
			p.pendingMu.Lock()
			ch := p.pending[string(resp.ID)]
			delete(p.pending, string(resp.ID))
			p.pendingMu.Unlock()
			if ch != nil {
				ch <- resp
			}
			continue
		}
		if msg.Method == "" {
			continue
		}
		p.handlersMu.RLock()
		handler := p.handlers[msg.Method]
		p.handlersMu.RUnlock()
		if handler == nil {
			if len(msg.ID) > 0 {
				_ = p.writeResponse(protocol.Response{JSONRPC: protocol.JSONRPCVersion, ID: msg.ID, Error: &protocol.Error{Code: protocol.MethodNotFound, Message: "method not found"}})
			}
			continue
		}
		go p.handleRequest(ctx, msg, handler)
	}
}

type inbound struct {
	Raw    json.RawMessage
	ID     json.RawMessage
	Method string
	Params json.RawMessage
}

// handleRequest 在独立协程中执行请求处理函数并发送响应。
func (p *Peer) handleRequest(ctx context.Context, in inbound, handler Handler) {
	result, rpcErr := handler(ctx, in.Params)
	if len(in.ID) == 0 {
		return
	}
	resp := protocol.Response{JSONRPC: protocol.JSONRPCVersion, ID: in.ID, Error: rpcErr}
	if rpcErr == nil {
		resp.Result, _ = json.Marshal(result)
	}
	_ = p.writeResponse(resp)
}

// Call 发送一个带自动生成请求 ID 的 RPC 请求，并等待响应。
func (p *Peer) Call(ctx context.Context, method string, params any, result any) error {
	id := strconv.FormatUint(p.nextID.Add(1), 10)
	return p.callWithID(ctx, id, method, params, result)
}

// CallWithID 使用调用方提供的请求 ID 发送 RPC 请求。
func (p *Peer) CallWithID(ctx context.Context, id, method string, params any, result any) error {
	if id == "" {
		return fmt.Errorf("call id is required")
	}
	return p.callWithID(ctx, id, method, params, result)
}

// callWithID 完成请求注册、消息发送、响应等待和结果反序列化。
func (p *Peer) callWithID(ctx context.Context, id, method string, params any, result any) error {
	idRaw, _ := json.Marshal(id)
	paramRaw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	ch := make(chan protocol.Response, 1)
	p.pendingMu.Lock()
	p.pending[string(idRaw)] = ch
	p.pendingMu.Unlock()
	if err := p.writeRequest(protocol.Request{JSONRPC: protocol.JSONRPCVersion, ID: idRaw, Method: method, Params: paramRaw}); err != nil {
		p.removePending(idRaw)
		return err
	}
	select {
	case <-ctx.Done():
		p.removePending(idRaw)
		_ = p.Notify("plugin.cancel", protocol.CancelParams{CallID: id})
		return ctx.Err()
	case <-p.closed:
		p.removePending(idRaw)
		return io.ErrClosedPipe
	case resp := <-ch:
		if resp.Error != nil {
			return fmt.Errorf("rpc error %d: %s", resp.Error.Code, resp.Error.Message)
		}
		if result == nil {
			return nil
		}
		if len(resp.Result) == 0 {
			return nil
		}
		return json.Unmarshal(resp.Result, result)
	}
}

// Notify 向对端发送不需要响应的通知消息。
func (p *Peer) Notify(method string, params any) error {
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	return p.writeRequest(protocol.Request{JSONRPC: protocol.JSONRPCVersion, Method: method, Params: raw})
}

// writeRequest 写出一个 RPC 请求。
func (p *Peer) writeRequest(req protocol.Request) error { return p.writeJSON(req) }

// writeResponse 写出一个 RPC 响应。
func (p *Peer) writeResponse(resp protocol.Response) error { return p.writeJSON(resp) }

// writeJSON 对消息进行 JSON 编码并使用写锁写入连接。
func (p *Peer) writeJSON(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	select {
	case <-p.closed:
		return io.ErrClosedPipe
	default:
	}
	return writeMessage(p.writer, b)
}

// removePending 从 pending 表中删除一个等待中的请求。
func (p *Peer) removePending(id []byte) {
	p.pendingMu.Lock()
	delete(p.pending, string(id))
	p.pendingMu.Unlock()
}

// Close 关闭 Peer，并让所有等待中的调用尽快返回。
func (p *Peer) Close() {
	p.closeOnce.Do(func() {
		close(p.closed)
		p.pendingMu.Lock()
		for id, ch := range p.pending {
			ch <- protocol.Response{JSONRPC: protocol.JSONRPCVersion, ID: json.RawMessage(id), Error: &protocol.Error{Code: protocol.PluginExited, Message: "peer closed"}}
		}
		p.pending = make(map[string]chan protocol.Response)
		p.pendingMu.Unlock()
	})
}

// Done 返回一个通道，在 Peer 的读循环退出后关闭。
func (p *Peer) Done() <-chan struct{} { return p.done }

type framedMessage struct {
	ID     json.RawMessage
	Method string
	Params json.RawMessage
	Raw    json.RawMessage
}

// readMessage 读取一个带 Content-Length 头的 RPC 消息并解析出请求字段。
func readMessage(r *bufio.Reader) (inbound, error) {
	var contentLength int
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return inbound{}, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return inbound{}, fmt.Errorf("invalid header")
		}
		if strings.EqualFold(strings.TrimSpace(parts[0]), "Content-Length") {
			contentLength, err = strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return inbound{}, err
			}
		}
	}
	if contentLength < 0 {
		return inbound{}, fmt.Errorf("invalid content length")
	}
	b := make([]byte, contentLength)
	if _, err := io.ReadFull(r, b); err != nil {
		return inbound{}, err
	}
	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(b, &req); err != nil {
		return inbound{}, err
	}
	return inbound{Raw: b, ID: req.ID, Method: req.Method, Params: req.Params}, nil
}

// writeMessage 写出一个带 Content-Length 头的 RPC 消息。
func writeMessage(w io.Writer, b []byte) error {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Content-Length: %d\r\n\r\n", len(b))
	buf.Write(b)
	_, err := w.Write(buf.Bytes())
	return err
}
