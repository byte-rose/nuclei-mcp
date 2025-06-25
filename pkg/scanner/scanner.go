package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"nuclei-mcp/pkg/cache"
	"nuclei-mcp/pkg/logging"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// ScannerService provides nuclei scanning operations
type ScannerService struct {
	cache   *cache.ResultCache
	console *logging.ConsoleLogger
	Cache   *cache.ResultCache // Exported for testing purposes
}

// NewScannerService creates a new scanner service
func NewScannerService(cache *cache.ResultCache, console *logging.ConsoleLogger) *ScannerService {
	return &ScannerService{
		Cache:   cache,
		console: console,
	}
}

// CreateCacheKey generates a cache key from scan parameters
func (s *ScannerService) CreateCacheKey(target string, severity string, protocols string) string {
	return fmt.Sprintf("%s:%s:%s", target, severity, protocols)
}

// Scan performs a nuclei scan
func (s *ScannerService) Scan(target string, severity string, protocols string, templateIDs []string) (cache.ScanResult, error) {
	// Create cache key
	cacheKey := s.CreateCacheKey(target, severity, protocols)
	if len(templateIDs) > 0 {
		cacheKey += ":" + strings.Join(templateIDs, ",")
	}

	// Check cache first
	if result, found := s.cache.Get(cacheKey); found {
		s.console.Log("Returning cached scan result for %s (%d findings)", target, len(result.Findings))
		return result, nil
	}

	s.console.Log("Starting new scan for target: %s", target)

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
		s.console.Log("Failed to create nuclei engine: %v", err)
		return cache.ScanResult{}, err
	}
	defer ne.Close()

	// Load targets
	ne.LoadTargets([]string{target}, true)

	// Ensure templates are loaded
	if err := ne.LoadAllTemplates(); err != nil {
		s.console.Log("Failed to load templates: %v", err)
		return cache.ScanResult{}, err
	}

	// Collect results
	var findings []*output.ResultEvent
	var findingsMutex sync.Mutex

	// Callback for results
	callback := func(event *output.ResultEvent) {
		findingsMutex.Lock()
		defer findingsMutex.Unlock()
		findings = append(findings, event)
		s.console.Log("Found vulnerability: %s (%s) on %s", event.Info.Name, event.Info.SeverityHolder.Severity.String(), event.Host)
	}

	// Execute scan with callback
	err = ne.ExecuteWithCallback(callback)
	if err != nil {
		s.console.Log("Scan failed: %v", err)
		return cache.ScanResult{}, err
	}

	// Create result
	result := cache.ScanResult{
		Target:   target,
		Findings: findings,
		ScanTime: time.Now(),
	}

	// Cache result
	s.cache.Set(cacheKey, result)

	s.console.Log("Scan completed for %s, found %d vulnerabilities", target, len(findings))

	return result, nil
}

// ThreadSafeScan performs a thread-safe nuclei scan
func (s *ScannerService) ThreadSafeScan(ctx context.Context, target string, severity string, protocols string, templateIDs []string) (cache.ScanResult, error) {
	// Create cache key
	cacheKey := s.CreateCacheKey(target, severity, protocols)
	if len(templateIDs) > 0 {
		cacheKey += ":" + strings.Join(templateIDs, ",")
	}

	// Check cache first
	if result, found := s.cache.Get(cacheKey); found {
		s.console.Log("Returning cached scan result for %s (%d findings)", target, len(result.Findings))
		return result, nil
	}

	s.console.Log("Starting new thread-safe scan for target: %s", target)

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
		s.console.Log("Failed to create thread-safe nuclei engine: %v", err)
		return cache.ScanResult{}, err
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
		s.console.Log("Found vulnerability: %s (%s) on %s", event.Info.Name, event.Info.SeverityHolder.Severity.String(), event.Host)
	})

	// Execute scan with options
	err = ne.ExecuteNucleiWithOptsCtx(ctx, []string{target}, options...)
	if err != nil {
		s.console.Log("Thread-safe scan failed: %v", err)
		return cache.ScanResult{}, err
	}

	// Create result
	result := cache.ScanResult{
		Target:   target,
		Findings: findings,
		ScanTime: time.Now(),
	}

	// Cache result
	s.cache.Set(cacheKey, result)

	s.console.Log("Thread-safe scan completed for %s, found %d vulnerabilities", target, len(findings))

	return result, nil
}

// BasicScan performs a simple nuclei scan without requiring template IDs
func (s *ScannerService) BasicScan(target string) (cache.ScanResult, error) {
	// Create cache key for basic scan
	cacheKey := fmt.Sprintf("basic:%s", target)

	// Check cache first
	if result, found := s.cache.Get(cacheKey); found {
		s.console.Log("Returning cached basic scan result for %s (%d findings)", target, len(result.Findings))
		return result, nil
	}

	s.console.Log("Starting new basic scan for target: %s", target)

	// Ensure templates directory exists and is absolute path
	templatesDir, err := filepath.Abs("./templates")
	if err != nil {
		s.console.Log("Failed to get absolute path for templates directory: %v", err)
		return cache.ScanResult{}, err
	}

	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		// Create templates directory if it doesn't exist
		s.console.Log("Creating templates directory: %s", templatesDir)
		if err := os.MkdirAll(templatesDir, 0755); err != nil {
			s.console.Log("Failed to create templates directory: %v", err)
			return cache.ScanResult{}, err
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
		s.console.Log("Creating basic template: %s", basicTemplatePath)
		if err := os.WriteFile(basicTemplatePath, []byte(basicTemplate), 0644); err != nil {
			s.console.Log("Failed to write basic template: %v", err)
			return cache.ScanResult{}, err
		}
	}

	// Create nuclei options with specific template and config
	opts := []nuclei.NucleiSDKOptions{
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			IncludeTags: []string{"basic-test"},
			IDs:         []string{"basic-test"},
		}),
		nuclei.DisableUpdateCheck(),
	}

	// Create a new nuclei engine with our options
	ne, err := nuclei.NewNucleiEngine(opts...)
	if err != nil {
		s.console.Log("Failed to create nuclei engine: %v", err)
		return cache.ScanResult{}, err
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
		s.console.Log("Found vulnerability: %s (%s) on %s", event.Info.Name, event.Info.SeverityHolder.Severity.String(), event.Host)
	}

	// Execute scan with callback
	err = ne.ExecuteWithCallback(callback)
	if err != nil {
		s.console.Log("Basic scan failed: %v", err)
		return cache.ScanResult{}, err
	}

	// Create result
	result := cache.ScanResult{
		Target:   target,
		Findings: findings,
		ScanTime: time.Now(),
	}

	// Cache result
	s.cache.Set(cacheKey, result)

	s.console.Log("Basic scan completed for %s, found %d vulnerabilities", target, len(findings))

	return result, nil
}
