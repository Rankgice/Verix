package rpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	"verix/sdk/protocol"
)

// TestPeerSupportsBidirectionalCalls 验证连接双方可以在同一条 RPC 通道上互相发起请求。
func TestPeerSupportsBidirectionalCalls(t *testing.T) {
	leftR, rightW := io.Pipe()
	rightR, leftW := io.Pipe()
	left := NewPeer(leftR, leftW)
	right := NewPeer(rightR, rightW)
	right.Register("host.echo", func(_ context.Context, raw json.RawMessage) (any, *protocol.Error) {
		var in map[string]string
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, &protocol.Error{Code: protocol.InvalidParams, Message: err.Error()}
		}
		return in, nil
	})
	left.Register("plugin.call_host", func(ctx context.Context, raw json.RawMessage) (any, *protocol.Error) {
		var out map[string]string
		if err := left.Call(ctx, "host.echo", raw, &out); err != nil {
			return nil, &protocol.Error{Code: protocol.InternalError, Message: err.Error()}
		}
		return out, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = left.Serve(ctx) }()
	go func() { defer wg.Done(); _ = right.Serve(ctx) }()
	var result map[string]string
	if err := right.Call(ctx, "plugin.call_host", map[string]string{"value": "ok"}, &result); err != nil {
		t.Fatal(err)
	}
	if result["value"] != "ok" {
		t.Fatalf("unexpected result: %#v", result)
	}
	cancel()
	left.Close()
	right.Close()
	_ = leftW.Close()
	_ = rightW.Close()
	wg.Wait()
}

// TestFraming 验证 Content-Length 消息边界的写入和读取。
func TestFraming(t *testing.T) {
	var buf bytes.Buffer
	if err := writeMessage(&buf, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	msg, err := readMessage(bufio.NewReader(&buf))
	if err != nil {
		t.Fatal(err)
	}
	if string(msg.Raw) != `{"ok":true}` {
		t.Fatalf("unexpected raw: %s", msg.Raw)
	}
}

// TestPeerCallHonorsCancellation 验证调用超时后能够退出等待并返回错误。
func TestPeerCallHonorsCancellation(t *testing.T) {
	var out bytes.Buffer
	peer := NewPeer(bytes.NewBuffer(nil), &out)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := peer.Call(ctx, "never", nil, nil); err == nil {
		t.Fatal("expected cancellation")
	}
}
