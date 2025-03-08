# Go MCP (Model Context Protocol) Implementation

This package provides a Go implementation of the Model Context Protocol (MCP), which enables communication between LLM applications (clients) and context/tool providers (servers).

## Overview

The Model Context Protocol is a client-server architecture where:
- **Hosts** are LLM applications (like Claude Desktop or IDEs) that initiate connections
- **Clients** maintain 1:1 connections with servers, inside the host application
- **Servers** provide context, tools, and prompts to clients

This implementation follows the [MCP specification](https://modelcontextprotocol.io) and provides a composable framework for building MCP clients and servers.

## Features

- **Protocol Layer**: Handles message framing, request/response linking, and high-level communication patterns
- **Transport Layer**: Multiple transport mechanisms including:
  - Standard Input/Output (stdio)
  - Server-Sent Events (SSE)
  - In-memory transport (for testing)
- **Server Implementation**: Full server implementation with support for:
  - Tools registration and execution
  - Resource management
  - Prompt templates
  - Logging
- **Client Implementation**: Complete client implementation for interacting with MCP servers

## Installation

```bash
go get github.com/addcontent/nuclei-mcp/mcp
```

## Usage

### Creating a Server

```go
package main

import (
    "log"
    "github.com/addcontent/nuclei-mcp/mcp"
)

func main() {
    // Create a stdio transport
    transport := mcp.NewStdioTransport()

    // Create a server with tools, resources, and prompts support
    server := mcp.NewServer(
        transport,
        mcp.WithServerInfo("My MCP Server", "1.0.0"),
        mcp.WithInstructions("This server provides file system access."),
        mcp.WithToolsSupport(true),
        mcp.WithResourcesSupport(true, true),
        mcp.WithPromptsSupport(true),
        mcp.WithLoggingSupport(),
    )

    // Register a tool
    server.RegisterTool(mcp.Tool{
        Name:        "readFile",
        Description: "Reads a file from the filesystem",
        InputSchema: map[string]interface{}{
            "type": "object",
            "properties": map[string]interface{}{
                "path": map[string]interface{}{
                    "type":        "string",
                    "description": "The path to the file to read",
                },
            },
            "required": []string{"path"},
        },
    })

    // Register a tool handler
    server.RegisterToolHandler("readFile", func(args map[string]interface{}) (*mcp.CallToolResult, error) {
        // Implement tool logic here
        return &mcp.CallToolResult{
            Content: []mcp.Content{
                {
                    Type: mcp.ContentTypeText,
                    Text: "File content would go here",
                },
            },
        }, nil
    })

    // Start the server
    if err := server.Start(); err != nil {
        log.Fatalf("Failed to start server: %v", err)
    }

    // Keep the server running
    select {}
}
```

### Creating a Client

```go
package main

import (
    "fmt"
    "log"
    "github.com/addcontent/nuclei-mcp/mcp"
)

func main() {
    // Create a stdio transport
    transport := mcp.NewStdioTransport()

    // Create a client
    client := mcp.NewClient(
        transport,
        mcp.WithClientInfo("My MCP Client", "1.0.0"),
    )

    // Start the client
    if err := client.Start(); err != nil {
        log.Fatalf("Failed to start client: %v", err)
    }

    // List available tools
    tools, err := client.ListTools()
    if err != nil {
        log.Fatalf("Failed to list tools: %v", err)
    }

    fmt.Println("Available tools:")
    for _, tool := range tools {
        fmt.Printf("  - %s: %s\n", tool.Name, tool.Description)
    }

    // Call a tool
    result, err := client.CallTool("readFile", map[string]interface{}{
        "path": "/path/to/file.txt",
    })
    if err != nil {
        log.Fatalf("Failed to call tool: %v", err)
    }

    fmt.Println("Tool result:")
    for _, content := range result.Content {
        if content.Type == mcp.ContentTypeText {
            fmt.Println(content.Text)
        }
    }
}
```

## Examples

Check out the `examples` directory for complete working examples:

- `examples/simple`: A simple in-memory example demonstrating basic client-server communication
- `examples/stdio`: A stdio-based example showing a file system server implementation

## Architecture

### Core Components

1. **Protocol**: Handles the JSON-RPC communication protocol
2. **Transport**: Manages the actual sending and receiving of messages
3. **Server**: Implements the server-side of the MCP
4. **Client**: Implements the client-side of the MCP
5. **Types**: Defines all the data structures used in the protocol

### Message Flow

1. Client sends an initialize request to the server
2. Server responds with capabilities and information
3. Client sends an initialized notification
4. Normal request/response communication begins

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
