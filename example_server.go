package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"./mcpserver"
)

func main() {
	// Create new server instance
	server := mcpserver.NewServer(os.Stdout)

	// Register example tools
	server.RegisterTool(mcpserver.Tool{
		Name:        "calculator",
		Description: "A simple calculator tool",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"operation": map[string]interface{}{
					"type":        "string",
					"description": "Operation to perform (add, subtract, multiply, divide)",
					"enum":        []string{"add", "subtract", "multiply", "divide"},
				},
				"a": map[string]interface{}{
					"type":        "number",
					"description": "First number",
				},
				"b": map[string]interface{}{
					"type":        "number",
					"description": "Second number",
				},
			},
			"required": []string{"operation", "a", "b"},
		},
	})

	// Register example resources
	server.RegisterResource(mcpserver.Resource{
		URI:         "example://config",
		Name:        "Configuration",
		Description: "Server configuration settings",
		MimeType:    "application/json",
	})

	server.RegisterResource(mcpserver.Resource{
		URI:         "example://status",
		Name:        "Server Status",
		Description: "Current server status and metrics",
		MimeType:    "application/json",
	})

	// Handle interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "Shutting down MCP server...")
		os.Exit(0)
	}()

	// Start the server
	fmt.Fprintln(os.Stderr, "MCP server starting on stdin/stdout...")
	fmt.Fprintln(os.Stderr, "Use Ctrl+C to stop")
	server.Start()
}
