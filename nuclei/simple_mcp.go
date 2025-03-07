package main

import (
	"encoding/json"
	"fmt"
	"log"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/strowk/foxy-contexts/pkg/app"
	"github.com/strowk/foxy-contexts/pkg/fxctx"
	"github.com/strowk/foxy-contexts/pkg/mcp"
	"github.com/strowk/foxy-contexts/pkg/stdio"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/zap"
)

func main() {
	log.Println("Starting simple Nuclei MCP server...")

	// Create and run the MCP server
	err := app.
		NewBuilder().
		// Add the nuclei scan tool
		WithTool(func() fxctx.Tool {
			return fxctx.NewTool(
				&mcp.Tool{
					Name:        "nuclei-scan",
					Description: ptr("Execute a Nuclei vulnerability scan against a target"),
					InputSchema: mcp.ToolInputSchema{
						Type: "object",
						Properties: map[string]map[string]interface{}{
							"target": {
								"type":        "string",
								"description": "URL or IP to scan (e.g., scanme.sh)",
							},
						},
						Required: []string{"target"},
					},
				},
				func(args map[string]interface{}) *mcp.CallToolResult {
					log.Printf("Scan requested with args: %v", args)

					// Extract target
					target, _ := args["target"].(string)
					if target == "" {
						return &mcp.CallToolResult{
							IsError: ptr(true),
							Content: []interface{}{
								mcp.TextContent{
									Type: "text",
									Text: "Target URL or IP is required",
								},
							},
						}
					}

					// Create nuclei engine
					ne, err := nuclei.NewNucleiEngine()
					if err != nil {
						log.Printf("Failed to initialize engine: %v", err)
						return &mcp.CallToolResult{
							IsError: ptr(true),
							Content: []interface{}{
								mcp.TextContent{
									Type: "text",
									Text: fmt.Sprintf("Error: %v", err),
								},
							},
						}
					}
					defer ne.Close()

					// Store scan results
					var findings []*output.ResultEvent

					// Load target and execute scan
					log.Printf("Starting scan against %s", target)
					ne.LoadTargets([]string{target}, false)
					err = ne.ExecuteWithCallback(func(event *output.ResultEvent) {
						log.Printf("Found vulnerability: %s", event.Info.Name)
						findings = append(findings, event)
					})

					if err != nil {
						log.Printf("Scan error: %v", err)
						return &mcp.CallToolResult{
							IsError: ptr(true),
							Content: []interface{}{
								mcp.TextContent{
									Type: "text",
									Text: fmt.Sprintf("Scan failed: %v", err),
								},
							},
						}
					}

					// Format results
					if len(findings) == 0 {
						return &mcp.CallToolResult{
							Content: []interface{}{
								mcp.TextContent{
									Type: "text",
									Text: fmt.Sprintf("No vulnerabilities found for %s", target),
								},
							},
						}
					}

					// Format results
					results := make([]interface{}, len(findings))
					for i, finding := range findings {
						resultMap := map[string]interface{}{
							"name":        finding.Info.Name,
							"severity":    finding.Info.SeverityHolder.Severity,
							"description": finding.Info.Description,
							"host":        finding.Host,
						}

						// Convert to JSON string
						jsonBytes, _ := json.Marshal(resultMap)

						results[i] = mcp.TextContent{
							Type: "text",
							Text: string(jsonBytes),
						}
					}

					return &mcp.CallToolResult{
						Content: results,
					}
				},
			)
		}).
		// Set server metadata
		WithName("nuclei-mcp").
		WithVersion("0.1.0").
		// Use stdio transport
		WithTransport(stdio.NewTransport()).
		// Turn down logging to avoid noise
		WithFxOptions(
			fx.Provide(func() *zap.Logger {
				cfg := zap.NewDevelopmentConfig()
				cfg.Level.SetLevel(zap.ErrorLevel)
				logger, _ := cfg.Build()
				return logger
			}),
			fx.Option(fx.WithLogger(
				func(logger *zap.Logger) fxevent.Logger {
					return &fxevent.ZapLogger{Logger: logger}
				},
			)),
		).
		Run()

	if err != nil {
		log.Fatalf("MCP server error: %v", err)
	}
}

// Helper function for pointers
func pointer[T any](v T) *T {
	return &v
}
