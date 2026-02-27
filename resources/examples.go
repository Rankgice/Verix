package resources

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const ExampleTestSpecURI = "verix://examples/testspec/basic-http"

const exampleTestSpecJSON = `{
  "meta": {
    "name": "example-basic-http",
    "protocol_defaults": {
      "http": {
        "base_url": "http://localhost:8080",
        "headers": {
          "Accept": "application/json",
          "Content-Type": "application/json"
        }
      }
    },
    "timeout_ms": 5000
  },
  "vars": {
    "user_id": "123"
  },
  "cases": [
    {
      "id": "get_user",
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
            "type": "number"
          },
          "name": {
            "type": "string",
            "not_empty": true
          }
        }
      },
      "extract": {
        "email": "email"
      }
    },
    {
      "id": "update_user",
      "name": "POST /users/{id}",
      "protocol": {
        "type": "http"
      },
      "request": {
        "method": "POST",
        "path": "/users/{{vars.user_id}}",
        "body": {
          "email": "{{vars.email}}"
        }
      },
      "expect": {
        "status": 200,
        "body": {
          "updated": {
            "equals": true
          }
        }
      },
      "extract": {}
    }
  ]
}`

func Register(server *mcp.Server) {
	server.AddResource(&mcp.Resource{
		Name:        "testspec-basic-http",
		Title:       "Verix TestSpec Example",
		Description: "Example TestSpec JSON for external projects to bootstrap test cases.",
		MIMEType:    "application/json",
		URI:         ExampleTestSpecURI,
	}, readExampleSpec)
}

func readExampleSpec(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	if req == nil || req.Params == nil || req.Params.URI != ExampleTestSpecURI {
		uri := ""
		if req != nil && req.Params != nil {
			uri = req.Params.URI
		}
		return nil, mcp.ResourceNotFoundError(uri)
	}

	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{
			{
				URI:      ExampleTestSpecURI,
				MIMEType: "application/json",
				Text:     exampleTestSpecJSON,
			},
		},
	}, nil
}
