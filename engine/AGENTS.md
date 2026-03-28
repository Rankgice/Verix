# ENGINE PACKAGE KNOWLEDGE BASE

**Scope:** `engine/`
**Owner surface:** TestSpec schema + validation/execution + diff diagnostics

## OVERVIEW
`engine` is the behavioral core: it defines TestSpec contracts and executes/asserts HTTP+gRPC cases.

## WHERE TO LOOK
| Task | Location | Notes |
|---|---|---|
| Schema contract | `types.go` | Canonical JSON fields for spec/request/expect/report |
| Validate required fields/defaults | `runner.go:28-94` | Enforces protocol requirements; defaults timeout to 5000ms |
| Case orchestration | `runner.go:96-217` | Per-case execution loop + report aggregation |
| HTTP execution rules | `runner.go:220-297` | Base URL join, query/header merge, JSON body default |
| gRPC execution rules | `runner.go:299-366` | Calls `grpcurl`, maps stderr to grpc code |
| Expect DSL evaluation | `runner.go:368-572` | status/grpc/header/body rule assertions + diffs |
| Extract + placeholders | `runner.go:574-638` | `extract`, `{{vars.*}}`, `{{timestamp}}` behavior |
| Diff classification/diagnosis | `runner.go:813-866` | Runtime error type mapping + diagnosis hints |

## CONVENTIONS (ENGINE-SPECIFIC)
- Keep protocol behavior symmetric where possible (HTTP/gRPC feed unified report model).
- `ValidateSpec` and `RunSpec` must stay aligned with `types.go` and `设计方案.md` DSL.
- Body-path evaluation depends on `normalizePath` + `gjson` semantics.
- Diff type vocabulary is stable API surface for downstream consumers.
- Runtime diagnosis strings should stay concise and deduplicated (`uniqueStrings`).

## ANTI-PATTERNS
- Do not change diff type strings (`status_mismatch`, `type_mismatch`, etc.) without coordinated contract update.
- Do not bypass `substituteAny`/`substituteString` in protocol executors.
- Do not weaken relative-URL/base_url checks in `joinURL` + validation logic.
- Do not move execution concerns into `tools/`; keep tools thin and engine authoritative.
- Do not introduce MCP SDK dependency into this package.

## CHANGE CHECKLIST (WHEN EDITING ENGINE)
- Update both schema (`types.go`) and runtime behavior (`runner.go`) together.
- Re-run validation paths for both `http` and `grpc` test cases.
- Ensure new assertion rules emit deterministic `AssertionResult` and `Diff` entries.
- Keep extraction and placeholder behavior backward-compatible.
