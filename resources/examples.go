package resources

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	ExampleHTTPTestSpecURI = "verix://examples/testspec/basic-http"
	ExampleGRPCTestSpecURI = "verix://examples/testspec/basic-grpc"

	ExampleTestSpecURI = ExampleHTTPTestSpecURI
)

const exampleHTTPTestSpecJSON = `{
  "meta": {
    "name": "example-basic-http",
    "protocol_defaults": {
      "http": {
        "base_url": "http://localhost:8080",
        "headers": {
          "Accept": "application/json",
          "Content-Type": "application/json",
          "X-Trace-Id": "{{vars.trace_id}}"
        }
      }
    },
    "timeout_ms": 5000
  },
  "vars": {
    "user_id": "123",
    "trace_id": "http-trace-001"
  },
  "cases": [
    {
      "id": "get_user_assertions",
      "name": "GET /users/{id}",
      "protocol": {
        "type": "http"
      },
      "request": {
        "method": "GET",
        "path": "/users/{{vars.user_id}}"
      },
      "expect": {
        "status": 200,
        "headers": {
          "Content-Type": "application/json"
        },
        "body": {
          "id": {
            "type": "number",
            "not_empty": true
          },
          "name": {
            "type": "string",
            "not_empty": true,
            "matches": "^User "
          },
          "email": {
            "type": "string",
            "matches": "^[^@]+@[^@]+\\.[^@]+$"
          },
          "profile.nickname": {
            "exists": true,
            "type": "string"
          },
          "deprecated_field": {
            "exists": false
          },
          "roles": {
            "type": "array",
            "min_items": 1
          },
          "active": {
            "equals": true
          }
        }
      },
      "extract": {
        "email": "email"
      }
    },
    {
      "id": "update_user_assertions",
      "name": "POST /users/{id}",
      "protocol": {
        "type": "http"
      },
      "request": {
        "method": "POST",
        "path": "/users/{{vars.user_id}}",
        "body": {
          "email": "{{vars.email}}",
          "display_name": "http_{{timestamp}}"
        }
      },
      "expect": {
        "status": 200,
        "headers": {
          "Content-Type": "application/json"
        },
        "body": {
          "updated": {
            "equals": true
          },
          "message": {
            "type": "string",
            "not_empty": true,
            "matches": "^updated"
          }
        }
      },
      "extract": {}
    }
  ]
}`

const exampleGRPCTestSpecJSON = `{
  "meta": {
    "name": "example-basic-grpc",
    "protocol_defaults": {
      "grpc": {
        "target": "{{vars.grpc_target}}",
        "plaintext": true,
        "metadata": {
          "authorization": "Bearer {{vars.token}}",
          "x-trace-id": "{{vars.trace_id}}"
        }
      }
    },
    "timeout_ms": 5000
  },
  "vars": {
    "grpc_target": "127.0.0.1:50051",
    "token": "demo-token",
    "trace_id": "grpc-trace-001",
    "tenant_id": "tenant-a",
    "user_id": "123"
  },
  "cases": [
    {
      "id": "get_user_assertions_grpc",
      "name": "GetUser",
      "protocol": {
        "type": "grpc"
      },
      "request": {
        "service": "user.v1.UserService",
        "method": "GetUser",
        "metadata": {
          "x-tenant-id": "{{vars.tenant_id}}"
        },
        "message": {
          "user_id": "{{vars.user_id}}"
        }
      },
      "expect": {
        "grpc_code": "OK",
        "headers": {
          "content-type": "application/grpc"
        },
        "body": {
          "user.id": {
            "type": "string",
            "not_empty": true
          },
          "user.name": {
            "type": "string",
            "not_empty": true,
            "matches": "^User "
          },
          "user.email": {
            "type": "string",
            "matches": "^[^@]+@[^@]+\\.[^@]+$"
          },
          "user.nickname": {
            "exists": true,
            "type": "string"
          },
          "user.deleted_at": {
            "exists": false
          },
          "user.roles": {
            "type": "array",
            "min_items": 1
          },
          "user.active": {
            "equals": true
          }
        }
      },
      "extract": {
        "email": "user.email"
      }
    },
    {
      "id": "update_user_email_grpc",
      "name": "UpdateUserEmail",
      "protocol": {
        "type": "grpc"
      },
      "request": {
        "service": "user.v1.UserService",
        "method": "UpdateUserEmail",
        "message": {
          "user_id": "{{vars.user_id}}",
          "email": "{{vars.email}}",
          "display_name": "grpc_{{timestamp}}"
        }
      },
      "expect": {
        "grpc_code": "OK",
        "headers": {
          "content-type": "application/grpc"
        },
        "body": {
          "updated": {
            "equals": true
          },
          "message": {
            "type": "string",
            "not_empty": true,
            "matches": "^updated"
          }
        }
      },
      "extract": {}
    }
  ]
}`

func ExampleHTTPTestSpecJSON() string {
	return exampleHTTPTestSpecJSON
}

func ExampleGRPCTestSpecJSON() string {
	return exampleGRPCTestSpecJSON
}

func ExampleTestSpecJSON() string {
	return ExampleHTTPTestSpecJSON()
}

func Register(server *mcp.Server) {
	server.AddResource(&mcp.Resource{
		Name:        "testspec-basic-http",
		Title:       "Verix HTTP TestSpec Example",
		Description: "Example HTTP TestSpec JSON for external projects to bootstrap test cases.",
		MIMEType:    "application/json",
		URI:         ExampleHTTPTestSpecURI,
	}, readExampleSpec)

	server.AddResource(&mcp.Resource{
		Name:        "testspec-basic-grpc",
		Title:       "Verix gRPC TestSpec Example",
		Description: "Example gRPC TestSpec JSON for external projects to bootstrap test cases.",
		MIMEType:    "application/json",
		URI:         ExampleGRPCTestSpecURI,
	}, readExampleSpec)
}

func readExampleSpec(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	if req == nil || req.Params == nil {
		return nil, mcp.ResourceNotFoundError("")
	}

	text, ok := exampleSpecText(req.Params.URI)
	if !ok {
		return nil, mcp.ResourceNotFoundError(req.Params.URI)
	}

	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{
			{
				URI:      req.Params.URI,
				MIMEType: "application/json",
				Text:     text,
			},
		},
	}, nil
}

func exampleSpecText(uri string) (string, bool) {
	switch uri {
	case ExampleHTTPTestSpecURI:
		return ExampleHTTPTestSpecJSON(), true
	case ExampleGRPCTestSpecURI:
		return ExampleGRPCTestSpecJSON(), true
	default:
		return "", false
	}
}
