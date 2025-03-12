package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// ScanResult represents the result of a nuclei scan
type ScanResult struct {
	Target   string                `json:"target"`
	ScanTime time.Time             `json:"scan_time"`
	Findings []*output.ResultEvent `json:"findings"`
}

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

// Get retrieves a result from the cache
func (c *ResultCache) Get(key string) (ScanResult, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	result, found := c.cache[key]
	if !found {
		return ScanResult{}, false
	}

	// Check if result has expired
	if time.Since(result.ScanTime) > c.expiry {
		c.logger.Printf("Cache entry expired: %s", key)
		return ScanResult{}, false
	}

	c.logger.Printf("Cache hit: %s", key)
	return result, true
}

// Set stores a result in the cache
func (c *ResultCache) Set(key string, result ScanResult) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.cache[key] = result
	c.logger.Printf("Cache entry set: %s", key)
}

// ScannerService provides nuclei scanning operations
type ScannerService struct {
	cache  *ResultCache
	logger *log.Logger
}

// NewScannerService creates a new scanner service
func NewScannerService(cache *ResultCache, logger *log.Logger) *ScannerService {
	return &ScannerService{
		cache:  cache,
		logger: logger,
	}
}

// CreateCacheKey generates a cache key from scan parameters
func (s *ScannerService) CreateCacheKey(target string, severity string, protocols string) string {
	return fmt.Sprintf("%s:%s:%s", target, severity, protocols)
}

// Scan performs a nuclei scan
func (s *ScannerService) Scan(target string, severity string, protocols string, templateIDs []string) (ScanResult, error) {
	// Create cache key
	cacheKey := s.CreateCacheKey(target, severity, protocols)
	if len(templateIDs) > 0 {
		cacheKey += ":" + strings.Join(templateIDs, ",")
	}

	// Check cache first
	if result, found := s.cache.Get(cacheKey); found {
		s.logger.Printf("Returning cached scan result for %s (%d findings)", 
			target, len(result.Findings))
		return result, nil
	}

	s.logger.Printf("Starting new scan for target: %s", target)

	// Create a new nuclei engine for this scan
	options := []nuclei.NucleiSDKOptions{
		nuclei.DisableUpdateCheck(),
	}
	
	// Add template filters if provided
	if severity != "" || protocols != "" || len(templateIDs) > 0 {
		filters := nuclei.TemplateFilters{}
		
		if severity != "" {
			filters.Severity = severity
		}
		
		if protocols != "" {
			protocolsList := strings.Split(protocols, ",")
			var validProtocols []string
			for _, p := range protocolsList {
				p = strings.TrimSpace(p)
				if p != "https" { 
					validProtocols = append(validProtocols, p)
				}
			}
			if len(validProtocols) > 0 {
				filters.ProtocolTypes = strings.Join(validProtocols, ",")
			}
		}
		
		if len(templateIDs) > 0 {
			filters.IDs = templateIDs
		}
		
		options = append(options, nuclei.WithTemplateFilters(filters))
	}
	
	// Create the engine with options
	ne, err := nuclei.NewNucleiEngine(options...)
	if err != nil {
		s.logger.Printf("Failed to create nuclei engine: %v", err)
		return ScanResult{}, err
	}
	defer ne.Close()

	// Load targets
	ne.LoadTargets([]string{target}, true)
	
	// Ensure templates are loaded
	if err := ne.LoadAllTemplates(); err != nil {
		s.logger.Printf("Failed to load templates: %v", err)
		return ScanResult{}, err
	}

	// Collect results
	var findings []*output.ResultEvent
	var findingsMutex sync.Mutex

	// Callback for results
	callback := func(event *output.ResultEvent) {
		findingsMutex.Lock()
		defer findingsMutex.Unlock()
		findings = append(findings, event)
		s.logger.Printf("Found vulnerability: %s (%s) on %s", 
			event.Info.Name, 
			event.Info.SeverityHolder.Severity.String(), 
			event.Host)
	}

	// Execute scan with callback
	err = ne.ExecuteWithCallback(callback)
	if err != nil {
		s.logger.Printf("Scan failed: %v", err)
		return ScanResult{}, err
	}

	// Create result
	result := ScanResult{
		Target:   target,
		Findings: findings,
		ScanTime: time.Now(),
	}

	// Cache result
	s.cache.Set(cacheKey, result)

	s.logger.Printf("Scan completed for %s, found %d vulnerabilities", 
		target, len(findings))

	return result, nil
}

// ThreadSafeScan performs a thread-safe nuclei scan
func (s *ScannerService) ThreadSafeScan(ctx context.Context, target string, severity string, protocols string, templateIDs []string) (ScanResult, error) {
	// Create cache key
	cacheKey := s.CreateCacheKey(target, severity, protocols)
	if len(templateIDs) > 0 {
		cacheKey += ":" + strings.Join(templateIDs, ",")
	}

	// Check cache first
	if result, found := s.cache.Get(cacheKey); found {
		s.logger.Printf("Returning cached scan result for %s (%d findings)", 
			target, len(result.Findings))
		return result, nil
	}

	s.logger.Printf("Starting new thread-safe scan for target: %s", target)

	// Create options for the thread-safe engine
	options := []nuclei.NucleiSDKOptions{
		nuclei.DisableUpdateCheck(),
	}
	
	// Add template filters if provided
	if severity != "" || protocols != "" || len(templateIDs) > 0 {
		filters := nuclei.TemplateFilters{}
		
		if severity != "" {
			filters.Severity = severity
		}
		
		if protocols != "" {
			protocolsList := strings.Split(protocols, ",")
			var validProtocols []string
			for _, p := range protocolsList {
				p = strings.TrimSpace(p)
				if p != "https" { 
					validProtocols = append(validProtocols, p)
				}
			}
			if len(validProtocols) > 0 {
				filters.ProtocolTypes = strings.Join(validProtocols, ",")
			}
		}
		
		if len(templateIDs) > 0 {
			filters.IDs = templateIDs
		}
		
		options = append(options, nuclei.WithTemplateFilters(filters))
	}
	
	// Create a new thread-safe nuclei engine
	ne, err := nuclei.NewThreadSafeNucleiEngineCtx(ctx, options...)
	if err != nil {
		s.logger.Printf("Failed to create thread-safe nuclei engine: %v", err)
		return ScanResult{}, err
	}
	defer ne.Close()

	// Collect results
	var findings []*output.ResultEvent
	var findingsMutex sync.Mutex

	// Set up callback for results
	ne.GlobalResultCallback(func(event *output.ResultEvent) {
		findingsMutex.Lock()
		defer findingsMutex.Unlock()
		findings = append(findings, event)
		s.logger.Printf("Found vulnerability: %s (%s) on %s", 
			event.Info.Name, 
			event.Info.SeverityHolder.Severity.String(), 
			event.Host)
	})

	// Execute scan with options
	err = ne.ExecuteNucleiWithOptsCtx(ctx, []string{target}, options...)
	if err != nil {
		s.logger.Printf("Thread-safe scan failed: %v", err)
		return ScanResult{}, err
	}

	// Create result
	result := ScanResult{
		Target:   target,
		Findings: findings,
		ScanTime: time.Now(),
	}

	// Cache result
	s.cache.Set(cacheKey, result)

	s.logger.Printf("Thread-safe scan completed for %s, found %d vulnerabilities", 
		target, len(findings))

	return result, nil
}

// BasicScan performs a simple nuclei scan without requiring template IDs
func (s *ScannerService) BasicScan(target string) (ScanResult, error) {
	// Create cache key for basic scan
	cacheKey := fmt.Sprintf("basic:%s", target)

	// Check cache first
	if result, found := s.cache.Get(cacheKey); found {
		s.logger.Printf("Returning cached basic scan result for %s (%d findings)", 
			target, len(result.Findings))
		return result, nil
	}

	s.logger.Printf("Starting new basic scan for target: %s", target)

	// Ensure templates directory exists and is absolute path
	templatesDir, err := filepath.Abs("./templates")
	if err != nil {
		s.logger.Printf("Failed to get absolute path for templates directory: %v", err)
		return ScanResult{}, err
	}
	
	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		// Create templates directory if it doesn't exist
		s.logger.Printf("Creating templates directory: %s", templatesDir)
		if err := os.MkdirAll(templatesDir, 0755); err != nil {
			s.logger.Printf("Failed to create templates directory: %v", err)
			return ScanResult{}, err
		}
	}
	
	// Create a basic template file path
	basicTemplatePath := filepath.Join(templatesDir, "basic-test.yaml")
	
	// Check if basic template exists, create it if not
	if _, err := os.Stat(basicTemplatePath); os.IsNotExist(err) {
		// Create a basic template for testing
		basicTemplate := `id: basic-test
info:
  name: Basic Test Template
  author: MCP
  severity: info
  description: Basic test template for nuclei

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: status
        status:
          - 200
`
		// Write basic template to file
		s.logger.Printf("Creating basic template: %s", basicTemplatePath)
		if err := os.WriteFile(basicTemplatePath, []byte(basicTemplate), 0644); err != nil {
			s.logger.Printf("Failed to write basic template: %v", err)
			return ScanResult{}, err
		}
	}

	// Create nuclei options with specific template and config
	opts := []nuclei.NucleiSDKOptions{
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			IncludeTags: []string{"basic-test"},
			IDs: []string{"basic-test"},
		}),
		nuclei.DisableUpdateCheck(),
	}

	// Create a new nuclei engine with our options
	ne, err := nuclei.NewNucleiEngine(opts...)
	if err != nil {
		s.logger.Printf("Failed to create nuclei engine: %v", err)
		return ScanResult{}, err
	}
	defer ne.Close()

	// Load targets
	ne.LoadTargets([]string{target}, true)
	
	// Collect results
	var findings []*output.ResultEvent
	var findingsMutex sync.Mutex

	// Callback for results
	callback := func(event *output.ResultEvent) {
		findingsMutex.Lock()
		defer findingsMutex.Unlock()
		findings = append(findings, event)
		s.logger.Printf("Found vulnerability: %s (%s) on %s", 
			event.Info.Name, 
			event.Info.SeverityHolder.Severity.String(), 
			event.Host)
	}

	// Execute scan with callback
	err = ne.ExecuteWithCallback(callback)
	if err != nil {
		s.logger.Printf("Basic scan failed: %v", err)
		return ScanResult{}, err
	}

	// Create result
	result := ScanResult{
		Target:   target,
		Findings: findings,
		ScanTime: time.Now(),
	}

	// Cache result
	s.cache.Set(cacheKey, result)

	s.logger.Printf("Basic scan completed for %s, found %d vulnerabilities", 
		target, len(findings))

	return result, nil
}

// handleNucleiScanTool handles the nuclei_scan tool requests
func handleNucleiScanTool(
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
	if severity == "" {
		severity = "info"
	}
	
	protocols, _ := arguments["protocols"].(string)
	if protocols == "" {
		protocols = "http,https"
	}
	
	threadSafe, _ := arguments["thread_safe"].(bool)
	
	// Extract template IDs if provided
	var templateIDs []string
	if templateIDsStr, ok := arguments["template_ids"].(string); ok && templateIDsStr != "" {
		// Split comma-separated string into slice
		templateIDs = strings.Split(templateIDsStr, ",")
		// Trim whitespace
		for i, id := range templateIDs {
			templateIDs[i] = strings.TrimSpace(id)
		}
	} else if templateID, ok := arguments["template_id"].(string); ok && templateID != "" {
		templateIDs = append(templateIDs, templateID)
	}
	
	// Perform scan
	var result ScanResult
	var err error
	
	if threadSafe {
		result, err = service.ThreadSafeScan(ctx, target, severity, protocols, templateIDs)
	} else {
		result, err = service.Scan(target, severity, protocols, templateIDs)
	}
	
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}
	
	// Format findings
	var responseText string
	if len(result.Findings) == 0 {
		responseText = fmt.Sprintf("No vulnerabilities found for target: %s", target)
	} else {
		responseText = fmt.Sprintf("Found %d vulnerabilities for target: %s\n\n", len(result.Findings), target)
		
		for i, finding := range result.Findings {
			responseText += fmt.Sprintf("Finding #%d:\n", i+1)
			responseText += fmt.Sprintf("- Name: %s\n", finding.Info.Name)
			responseText += fmt.Sprintf("- Severity: %s\n", finding.Info.SeverityHolder.Severity.String())
			responseText += fmt.Sprintf("- Description: %s\n", finding.Info.Description)
			responseText += fmt.Sprintf("- URL: %s\n\n", finding.Host)
		}
	}
	
	return mcp.NewToolResultText(responseText), nil
}

// handleBasicScanTool handles the basic_scan tool requests
func handleBasicScanTool(
	ctx context.Context,
	request mcp.CallToolRequest,
	service *ScannerService,
	logger *log.Logger,
) (*mcp.CallToolResult, error) {
	arguments := request.Params.Arguments
	
	// Extract target parameter
	target, ok := arguments["target"].(string)
	if !ok || target == "" {
		return nil, fmt.Errorf("invalid or missing target parameter")
	}
	
	// Perform basic scan
	result, err := service.BasicScan(target)
	if err != nil {
		logger.Printf("Basic scan failed: %v", err)
		return nil, err
	}
	
	// Convert findings to a simplified format for the response
	type SimplifiedFinding struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		URL         string `json:"url"`
	}
	
	simplifiedFindings := make([]SimplifiedFinding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		simplifiedFindings = append(simplifiedFindings, SimplifiedFinding{
			Name:        finding.Info.Name,
			Severity:    finding.Info.SeverityHolder.Severity.String(),
			Description: finding.Info.Description,
			URL:         finding.Host,
		})
	}
	
	// Create response
	response := map[string]interface{}{
		"target":         result.Target,
		"scan_time":      result.ScanTime.Format(time.RFC3339),
		"findings_count": len(result.Findings),
		"findings":       simplifiedFindings,
	}
	
	// Marshal response to JSON
	responseJSON, err := json.Marshal(response)
	if err != nil {
		logger.Printf("Failed to marshal response: %v", err)
		return nil, err
	}
	
	return mcp.NewToolResultText(string(responseJSON)), nil
}

// NewNucleiMCPServer creates a new MCP server for Nuclei
func NewNucleiMCPServer(service *ScannerService, logger *log.Logger) *server.MCPServer {
	mcpServer := server.NewMCPServer(
		"nuclei-scanner",
		"1.0.0",
		server.WithLogging(),
	)

	// Add Nuclei scan tool
	mcpServer.AddTool(mcp.NewTool("nuclei_scan",
		mcp.WithDescription("Performs a Nuclei vulnerability scan on a target"),
		mcp.WithString("target",
			mcp.Description("Target URL or IP to scan"),
			mcp.Required(),
		),
		mcp.WithString("severity",
			mcp.Description("Minimum severity level (info, low, medium, high, critical)"),
			mcp.DefaultString("info"),
		),
		mcp.WithString("protocols",
			mcp.Description("Protocols to scan (comma-separated: http,https,tcp,etc)"),
			mcp.DefaultString("http"),
		),
		mcp.WithBoolean("thread_safe",
			mcp.Description("Use thread-safe engine for scanning"),
		),
		mcp.WithString("template_ids",
			mcp.Description("Comma-separated template IDs to run (e.g. \"self-signed-ssl,nameserver-fingerprint\")"),
		),
		mcp.WithString("template_id",
			mcp.Description("Single template ID to run (alternative to template_ids)"),
		),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleNucleiScanTool(ctx, request, service, logger)
	})

	// Add Basic scan tool
	mcpServer.AddTool(mcp.NewTool("basic_scan",
		mcp.WithDescription("Performs a basic Nuclei vulnerability scan on a target without requiring template IDs"),
		mcp.WithString("target",
			mcp.Description("Target URL or IP to scan"),
			mcp.Required(),
		),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleBasicScanTool(ctx, request, service, logger)
	})

	// Add vulnerability resource
	mcpServer.AddResource(mcp.NewResource("vulnerabilities", "Recent Vulnerability Reports"), 
	func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return handleVulnerabilityResource(ctx, request, service, logger)
	})

	return mcpServer
}

// handleVulnerabilityResource handles the vulnerability resource requests
func handleVulnerabilityResource(
	ctx context.Context,
	request mcp.ReadResourceRequest,
	service *ScannerService,
	logger *log.Logger,
) ([]mcp.ResourceContents, error) {
	// Get all cache entries (in a production system, you'd want to limit this)
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
			// Limit to 5 findings for brevity
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
		"timestamp":     time.Now().Format(time.RFC3339),
		"recent_scans":  recentScans,
		"total_scans":   len(recentScans),
	}
	
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal report: %w", err)
	}
	
	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      "vulnerabilities",
			MIMEType: "application/json",
			Text:     string(reportJSON),
		},
	}, nil
}

// min returns the smaller of x or y
func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// setupSignalHandling configures graceful shutdown
func setupSignalHandling() chan os.Signal {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	
	return sigs
}

func main() {
	// Parse command line flags
	transportType := flag.String("transport", "stdio", "Transport type (stdio or sse)")
	flag.Parse()

	// Set up logging to file instead of stdout to avoid interfering with stdio transport
	logFile, err := os.OpenFile("nuclei-mcp.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

	logger := log.New(logFile, "", log.LstdFlags)
	logger.Printf("Starting Nuclei MCP Server with %s transport", *transportType)

	// Create scanner service
	scannerService := NewScannerService(NewResultCache(5*time.Minute, logger), logger)

	// Create MCP server
	mcpServer := NewNucleiMCPServer(scannerService, logger)

	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	// Start server in a goroutine
	go func() {
		var err error
		if *transportType == "sse" {
			logger.Printf("Starting SSE server")
			sseServer := server.NewSSEServer(mcpServer, "/")
			err = sseServer.Start("0.0.0.0:8080")
		} else {
			logger.Printf("Starting stdio server")
			err = server.ServeStdio(mcpServer)
		}
		
		if err != nil {
			logger.Printf("Error starting server: %v", err)
			cancel()
		}
	}()

	// Wait for signal or context cancellation
	select {
	case sig := <-sigChan:
		logger.Printf("Received signal: %v", sig)
	case <-ctx.Done():
		logger.Printf("Context done: %v", ctx.Err())
	}

	logger.Printf("Server shutdown complete")
}
