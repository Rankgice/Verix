# PROJECT KNOWLEDGE BASE

**Generated:** 2026-03-05T09:52:05+0800
**Commit:** 9ef8483
**Branch:** main

## OVERVIEW
Verix is a Go MCP server that validates and executes TestSpec v1 cases for HTTP/gRPC and returns structured diff-style diagnostics.

## HIERARCHY RULES
- Nearest `AGENTS.md` wins (directory-local instructions override parent notes).
- Root file is navigation + constraints; deep behavior details live in subdirectory files.

## AGENTS HIERARCHY
- `./AGENTS.md` (root)
- `./engine/AGENTS.md` (engine-specific execution/DSL rules)

## STRUCTURE
```text
verix/
├── main.go            # stdio MCP bootstrap
├── core/              # server assembly (register tools/resources)
├── tools/             # MCP tool handlers + spec loading
├── engine/            # TestSpec schema + execution/diff engine (complex hotspot)
├── resources/         # built-in example TestSpec resource URI
├── test.json          # local sample spec (includes intentional failure case)
└── 设计方案.md         # authoritative TestSpec v1 DSL/design notes
```

## WHERE TO LOOK
| Task | Location | Notes |
|---|---|---|
| Server startup path | `main.go`, `core/core.go` | `main -> core.NewServer -> Run(stdio)` |
| Register MCP tools | `tools/run_spec.go`, `tools/validate_spec.go` | Tool names are `run_testspec` and `validate_testspec` |
| Parse/ingest input spec | `tools/common.go` | `spec_path` or `spec_json` required |
| Spec schema contract | `engine/types.go` | Source of truth for TestSpec fields |
| Runtime + assertions + diffs | `engine/runner.go` | HTTP/gRPC execution, expect DSL, diagnosis |
| Built-in example payload | `resources/examples.go` | URI: `verix://examples/testspec/basic-http` |

## CONVENTIONS (PROJECT-SPECIFIC)
- Go toolchain target: `go 1.25.6` (`go.mod`).
- No CI/workflow files, no Makefile, no npm/pnpm scripts.
- Runtime path is MCP stdio transport, not HTTP listener startup.
- Register tools/resources before `server.Run(...)`; startup assumes capabilities are predeclared.
- Prefer `mcp.AddTool(...)` wrappers for tool registration/schema handling.
- `spec_path` takes precedence when both `spec_path` and `spec_json` are set.
- Relative HTTP request paths require `meta.protocol_defaults.http.base_url`.
- gRPC execution shells out to `grpcurl`; environment must provide it in `PATH`.
- Placeholder style: `{{vars.key}}` and `{{timestamp}}`.

## ANTI-PATTERNS (THIS PROJECT)
- Do not duplicate assertion/diff logic in `tools/`; keep behavioral logic in `engine/`.
- Do not register MCP capabilities after runtime start; keep initialization in `core.NewServer()`.
- Do not add new diff type strings ad hoc; keep vocabulary consistent with engine/design doc.
- Do not assume gRPC tests are runnable without `grpcurl` availability.
- Do not treat `resources/` as static files only; it is MCP resource registration code.
- Do not commit local build artifacts (example: `verix.exe`).

## UNIQUE STYLES
- Protocol-unified test model: HTTP and gRPC share one expect/extract reporting structure.
- Diff-first reporting: machine-readable `failed_cases[].diff` + human diagnosis text.
- Variable substitution is recursive and supports nested map/array payloads.

## COMMANDS
```bash
go fmt ./...
go vet ./...
go test ./...
go build ./...
go run .
```

## NOTES
- `test.json` contains one intentionally failing case (`reports_fail`) for diff demonstration.
- `设计方案.md` is the richest DSL reference; keep code behavior aligned with it.
