

---

# Enhanced MCP Integration for Nuclei-LLM Interactions

This document provides a robust foundation for implementing Model Context Protocol servers for Nuclei, significantly streamlining Nuclei integration with large language models. This revised analysis incorporates insights from the implementation to enhance our strategy.

## Architecture Deep Dive

### Core Components

The architecture combines standard Go patterns with MCP primitives:

1. **Server Initialization**: Central coordination point for MCP components
```go
// Create MCP server
mcpServer := NewNucleiMCPServer(scannerService, logger)

// Start server based on transport type
if transportType == "sse" {
    sseServer := server.NewSSEServer(mcpServer, "/")
    err = sseServer.Start("0.0.0.0:8080")
} else {
    err = server.ServeStdio(mcpServer)
}
```

2. **Tool Registration**: Clear definition of tools with schema and handlers
```go
// Add Nuclei scan tool
mcpServer.AddTool(mcp.NewTool("nuclei_scan",
    mcp.WithDescription("Performs a Nuclei vulnerability scan on a target"),
    mcp.WithString("target",
        mcp.Description("Target URL or IP to scan"),
        mcp.Required(),
    ),
    mcp.WithString("severity",
        mcp.Description("Minimum severity level (info, low, medium, high, critical)"),
    ),
    // Additional parameters...
), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    return handleNucleiScanTool(ctx, request, service, logger)
})
```

3. **Resource Providers**: Expose scan results as queryable resources
```go
// Add vulnerability resource
mcpServer.AddResource(mcp.NewResource("vulnerabilities", "Recent Vulnerability Reports"),
    func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
        return handleVulnerabilityResource(ctx, request, service, logger)
    })
```


### Enhanced Security Implementation

The MCP server enables secure configurations through proper logging and error handling:

```go
// Set up logging to file instead of stdout to avoid interfering with stdio transport
logFile, err := os.OpenFile("nuclei-mcp.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
if err != nil {
    fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
    os.Exit(1)
}
defer logFile.Close()

logger := log.New(logFile, "", log.LstdFlags)
logger.Printf("Starting Nuclei MCP Server with %s transport", transportType)
```


## Nuclei Integration Patterns

### Tool Implementation Best Practices

Building on the example structure:

```go
// handleAdvancedScanTool handles the advanced_scan tool requests
func handleAdvancedScanTool(
    ctx context.Context,
    request mcp.CallToolRequest,
    service *ScannerService,
    logger *log.Logger,
) (*mcp.CallToolResult, error) {
    arguments := request.Params.Arguments

    // Extract parameters
    target, ok := arguments["target"].(string)
    if !ok || target == "" {
        return nil, fmt.Errorf("invalid or missing target parameter")
    }

    severity, _ := arguments["severity"].(string)
    protocols, _ := arguments["protocols"].(string)
    
    // Create options for Nuclei engine
    options := []nuclei.NucleiSDKOptions{
        nuclei.DisableUpdateCheck(),
    }

    // Add template filters
    if severity != "" || protocols != "" {
        filters := nuclei.TemplateFilters{
            Severity:      severity,
            ProtocolTypes: protocols,
        }
        options = append(options, nuclei.WithTemplateFilters(filters))
    }

    // Execute scan and return results
    // ...
}
```


### Resource Implementation

Leveraging the MCP resource providers:

```go
// handleVulnerabilityResource handles the vulnerability resource requests
func handleVulnerabilityResource(
    ctx context.Context,
    request mcp.ReadResourceRequest,
    service *ScannerService,
    logger *log.Logger,
) ([]mcp.ResourceContents, error) {
    // Get all cache entries
    c := service.cache
    c.lock.RLock()
    defer c.lock.RUnlock()

    var recentScans []map[string]interface{}
    for _, result := range c.cache {
        scanInfo := map[string]interface{}{
            "target":    result.Target,
            "scan_time": result.ScanTime.Format(time.RFC3339),
            "findings":  len(result.Findings),
        }

        // Add some sample findings
        if len(result.Findings) > 0 {
            var sampleFindings []map[string]string
            count := min(5, len(result.Findings))
            for i := 0; i < count; i++ {
                finding := result.Findings[i]
                sampleFindings = append(sampleFindings, map[string]string{
                    "name":        finding.Info.Name,
                    "severity":    finding.Info.SeverityHolder.Severity.String(),
                    "description": finding.Info.Description,
                    "url":         finding.Host,
                })
            }
            scanInfo["sample_findings"] = sampleFindings
        }

        recentScans = append(recentScans, scanInfo)
    }

    report := map[string]interface{}{
        "timestamp":    time.Now().Format(time.RFC3339),
        "recent_scans": recentScans,
        "total_scans":  len(recentScans),
    }

    return []mcp.ResourceContents{
        {
            ContentType: "application/json",
            Content:     report,
        },
    }, nil
}
```


## Advanced Deployment Patterns

### Caching Implementation

The Nuclei MCP server implements efficient caching for scan results:

```go
// ResultCache caches scan results
type ResultCache struct {
    cache  map[string]ScanResult
    expiry time.Duration
    lock   sync.RWMutex
    logger *log.Logger
}

// NewResultCache creates a new result cache
func NewResultCache(expiry time.Duration, logger *log.Logger) *ResultCache {
    return &ResultCache{
        cache:  make(map[string]ScanResult),
        expiry: expiry,
        logger: logger,
    }
}

// Set adds a result to the cache
func (c *ResultCache) Set(key string, result ScanResult) {
    c.lock.Lock()
    defer c.lock.Unlock()
    c.cache[key] = result
    c.logger.Printf("Cached result for %s with %d findings", result.Target, len(result.Findings))
    
    // Schedule cleanup after expiry
    go func() {
        time.Sleep(c.expiry)
        c.Remove(key)
    }()
}
```


### Dynamic Template Management

Integrating Nuclei template management:

```go
// Template filtering implementation
func applyTemplateFilters(options *[]nuclei.NucleiSDKOptions, filters map[string]interface{}) {
    templateFilters := nuclei.TemplateFilters{}
    
    if severity, ok := filters["severity"].(string); ok && severity != "" {
        templateFilters.Severity = severity
    }
    
    if tags, ok := filters["tags"].([]string); ok && len(tags) > 0 {
        templateFilters.Tags = tags
    }
    
    if excludeTags, ok := filters["exclude_tags"].([]string); ok && len(excludeTags) > 0 {
        templateFilters.ExcludeTags = excludeTags
    }
    
    *options = append(*options, nuclei.WithTemplateFilters(templateFilters))
}
```


## Debugging and Testing with MCP Inspector

The Model Context Protocol Inspector provides a powerful interface for debugging and testing your Nuclei MCP server implementation. It allows you to visualize tools, resources, and interactions in real-time.

### Setting Up the Inspector

The MCP Inspector can be run directly with your Nuclei MCP server without requiring installation:

```bash
# Run the inspector with the Nuclei MCP server
npx @modelcontextprotocol/inspector go run ./nuclei_mcp.go
```

For development workflows, you can also install it globally:

```bash
npm install -g @modelcontextprotocol/inspector
```

### Inspector Features for Nuclei MCP

When working with the Nuclei MCP server, the inspector provides several valuable capabilities:

1. **Tool Exploration**: Examine the schema and documentation for all available tools
   ```json
   // Example advanced_scan tool schema
   {
     "name": "advanced_scan",
     "description": "Performs a comprehensive Nuclei scan with advanced options",
     "parameters": {
       "target": {
         "type": "string",
         "description": "Target URL or IP to scan",
         "required": true
       },
       "severity": {
         "type": "string",
         "description": "Filter by severity (info,low,medium,high,critical)"
       },
       // Additional parameters...
     }
   }
   ```

2. **Live Tool Execution**: Test scan tools with various parameters and view results in real-time
   ```bash
   # Example tool call in the inspector
   {
     "target": "example.com",
     "severity": "high,critical",
     "tags": "cve,rce"
   }
   ```

3. **Resource Inspection**: View vulnerability reports as structured resources
   ```json
   // Example vulnerability resource
   {
     "timestamp": "2025-03-26T09:15:22+03:00",
     "recent_scans": [
       {
         "target": "example.com",
         "scan_time": "2025-03-26T09:10:15+03:00",
         "findings": 3,
         "sample_findings": [
           {
             "name": "Apache Log4j RCE",
             "severity": "critical",
             "description": "Remote code execution vulnerability in Log4j",
             "url": "https://example.com/api/login"
           }
         ]
       }
     ]
   }
   ```

### Debugging Common Issues

The inspector is particularly helpful for troubleshooting:

1. **Schema Validation Errors**: Quickly identify when tool parameters don't match schema requirements
2. **Execution Flow**: Trace the complete lifecycle of a scan request
3. **Resource Updates**: Monitor how vulnerability findings are exposed as resources

### Integration with Development Workflow

For an efficient development cycle:

```bash
# Terminal 1: Watch and rebuild on changes
go build -o nuclei_mcp ./nuclei_mcp.go && ./nuclei_mcp

# Terminal 2: Run the inspector against the built binary
npx @modelcontextprotocol/inspector ./nuclei_mcp
```

This setup allows you to make changes to the codebase and immediately test them through the inspector interface.


## Security Enhancements

### Audit Logging Implementation

Extending the server with custom logging:

```go
type AuditLogger struct {
  logger *log.Logger
}

func (l *AuditLogger) LogRequest(method, path string, params map[string]interface{}) {
  l.logger.Printf("Request: %s %s, Params: %v", method, path, params)
}

func (l *AuditLogger) LogResponse(method, path string, status int, duration time.Duration) {
  l.logger.Printf("Response: %s %s, Status: %d, Duration: %v", method, path, status, duration)
}

func main() {
  logFile, _ := os.OpenFile("audit.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
  auditLogger := &AuditLogger{
    logger: log.New(logFile, "AUDIT: ", log.LstdFlags),
  }
  
  // Use the audit logger in your handlers
}
```

### Rate Limiting

Implementing rate limiting for scan requests:

```go
type RateLimiter struct {
  tokens      int
  refillRate  int
  lastRefill  time.Time
  maxTokens   int
  mu          sync.Mutex
}

func (r *RateLimiter) Allow() bool {
  r.mu.Lock()
  defer r.mu.Unlock()
  
  now := time.Now()
  elapsed := now.Sub(r.lastRefill)
  
  // Refill tokens based on time elapsed
  newTokens := int(elapsed.Seconds()) * r.refillRate
  if newTokens > 0 {
    r.tokens = min(r.tokens + newTokens, r.maxTokens)
    r.lastRefill = now
  }
  
  if r.tokens > 0 {
    r.tokens--
    return true
  }
  
  return false
}

// Usage in scan handler
if !rateLimiter.Allow() {
  return nil, fmt.Errorf("rate limit exceeded, try again later")
}

## References

[^1]: Model Context Protocol. https://modelcontextprotocol.io/

[^2]: Nuclei Documentation. https://docs.projectdiscovery.io/tools/nuclei/overview

[^3]: Mark3 Labs MCP Go Library. https://github.com/mark3labs/mcp-go

[^4]: ProjectDiscovery Nuclei SDK. https://github.com/projectdiscovery/nuclei/tree/main/lib
