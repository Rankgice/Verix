package pluginhost

import (
	"os"
	"path/filepath"
	"testing"

	"verix/sdk/protocol"
)

// TestValidateManifestRejectsEscapingCommand 验证插件命令不能逃出自己的目录。
func TestValidateManifestRejectsEscapingCommand(t *testing.T) {
	dir := t.TempDir()
	manifest := protocol.Manifest{
		ManifestVersion: "1",
		ProtocolVersion: protocol.ProtocolVersion,
		ID:              "com.example.test",
		Name:            "test",
		Version:         "1.0.0",
		Runtime:         protocol.Runtime{Command: "../plugin.exe"},
	}
	if err := validateManifest(dir, manifest); err == nil {
		t.Fatal("expected command path escape to be rejected")
	}
}

// TestDiscoverReadsManifest 验证插件管理器能够扫描并读取有效 Manifest。
func TestDiscoverReadsManifest(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "example")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"manifest_version":"1","protocol_version":"1.0","id":"com.example.test","name":"example","version":"1.0.0","runtime":{"command":"example.exe"}}`)
	if err := os.WriteFile(filepath.Join(dir, "plugin.json"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	manager := New(Options{RootDir: root})
	if err := manager.Discover(); err != nil {
		t.Fatal(err)
	}
	list := manager.List(nil)
	if len(list) != 1 || list[0].ID != "com.example.test" {
		t.Fatalf("unexpected plugins: %#v", list)
	}
}
