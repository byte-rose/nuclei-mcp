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

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// CacheInterface defines the interface for cache operations
type CacheInterface interface {
	Get(key string) (cache.ScanResult, bool)
	Set(key string, result cache.ScanResult)
	GetAll() []cache.ScanResult
}

// LoggerInterface defines the interface for logging operations
type LoggerInterface interface {
	Log(format string, v ...interface{})
	Close() error
}

type scannerServiceImpl struct {
	cache   CacheInterface
	console LoggerInterface
}

type ScannerService interface {
	CreateCacheKey(target string, severity string, protocols string) string
	Scan(target string, severity string, protocols string, templateIDs []string) (cache.ScanResult, error)
	ThreadSafeScan(ctx context.Context, target string, severity string, protocols string, templateIDs []string) (cache.ScanResult, error)
	BasicScan(target string) (cache.ScanResult, error)
	GetAll() []cache.ScanResult
}

// NewScannerService creates a new scanner service
func NewScannerService(cache CacheInterface, console LoggerInterface) ScannerService {
	return &scannerServiceImpl{
		cache:   cache,
		console: console,
	}
}

func (s *scannerServiceImpl) CreateCacheKey(target string, severity string, protocols string) string {
	return fmt.Sprintf("%s:%s:%s", target, severity, protocols)
}

func (s *scannerServiceImpl) Scan(target string, severity string, protocols string, templateIDs []string) (cache.ScanResult, error) {

	cacheKey := s.CreateCacheKey(target, severity, protocols)
	if len(templateIDs) > 0 {
		cacheKey += ":" + strings.Join(templateIDs, ",")
	}

	if result, found := s.cache.Get(cacheKey); found {
		s.console.Log("Returning cached scan result for %s (%d findings)", target, len(result.Findings))
		return result, nil
	}

	s.console.Log("Starting new scan for target: %s", target)

	options := []nuclei.NucleiSDKOptions{
		nuclei.DisableUpdateCheck(),
	}

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

	ne, err := nuclei.NewNucleiEngineCtx(context.Background(), options...)
	if err != nil {
		s.console.Log("Failed to create nuclei engine: %v", err)
		return cache.ScanResult{}, err
	}
	defer ne.Close()

	ne.LoadTargets([]string{target}, true)

	if err := ne.LoadAllTemplates(); err != nil {
		s.console.Log("Failed to load templates: %v", err)
		return cache.ScanResult{}, err
	}

	var findings []*output.ResultEvent
	var findingsMutex sync.Mutex

	callback := func(event *output.ResultEvent) {
		findingsMutex.Lock()
		defer findingsMutex.Unlock()
		findings = append(findings, event)
		s.console.Log("Found vulnerability: %s (%s) on %s", event.Info.Name, event.Info.SeverityHolder.Severity.String(), event.Host)
	}

	err = ne.ExecuteWithCallback(callback)
	if err != nil {
		s.console.Log("Scan failed: %v", err)
		return cache.ScanResult{}, err
	}

	result := cache.ScanResult{
		Target:   target,
		Findings: findings,
		ScanTime: time.Now(),
	}

	s.cache.Set(cacheKey, result)

	s.console.Log("Scan completed for %s, found %d vulnerabilities", target, len(findings))

	return result, nil
}

func (s *scannerServiceImpl) ThreadSafeScan(ctx context.Context, target string, severity string, protocols string, templateIDs []string) (cache.ScanResult, error) {
	// Create cache key
	cacheKey := s.CreateCacheKey(target, severity, protocols)
	if len(templateIDs) > 0 {
		cacheKey += ":" + strings.Join(templateIDs, ",")
	}

	if result, found := s.cache.Get(cacheKey); found {
		s.console.Log("Returning cached scan result for %s (%d findings)", target, len(result.Findings))
		return result, nil
	}

	s.console.Log("Starting new thread-safe scan for target: %s", target)

	options := []nuclei.NucleiSDKOptions{
		nuclei.DisableUpdateCheck(),
	}

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

	ne, err := nuclei.NewThreadSafeNucleiEngineCtx(ctx, options...)
	if err != nil {
		s.console.Log("Failed to create thread-safe nuclei engine: %v", err)
		return cache.ScanResult{}, err
	}
	defer ne.Close()

	var findings []*output.ResultEvent
	var findingsMutex sync.Mutex

	ne.GlobalResultCallback(func(event *output.ResultEvent) {
		findingsMutex.Lock()
		defer findingsMutex.Unlock()
		findings = append(findings, event)
		s.console.Log("Found vulnerability: %s (%s) on %s", event.Info.Name, event.Info.SeverityHolder.Severity.String(), event.Host)
	})

	err = ne.ExecuteNucleiWithOptsCtx(ctx, []string{target}, options...)
	if err != nil {
		s.console.Log("Thread-safe scan failed: %v", err)
		return cache.ScanResult{}, err
	}

	result := cache.ScanResult{
		Target:   target,
		Findings: findings,
		ScanTime: time.Now(),
	}

	s.cache.Set(cacheKey, result)

	s.console.Log("Thread-safe scan completed for %s, found %d vulnerabilities", target, len(findings))

	return result, nil
}

func (s *scannerServiceImpl) BasicScan(target string) (cache.ScanResult, error) {
	// Create cache key for basic scan
	cacheKey := fmt.Sprintf("basic:%s", target)

	if result, found := s.cache.Get(cacheKey); found {
		s.console.Log("Returning cached basic scan result for %s (%d findings)", target, len(result.Findings))
		return result, nil
	}

	s.console.Log("Starting new basic scan for target: %s", target)

	templatesDir, err := filepath.Abs("./templates")
	if err != nil {
		s.console.Log("Failed to get absolute path for templates directory: %v", err)
		return cache.ScanResult{}, err
	}

	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {

		s.console.Log("Creating templates directory: %s", templatesDir)
		if err := os.MkdirAll(templatesDir, 0755); err != nil {
			s.console.Log("Failed to create templates directory: %v", err)
			return cache.ScanResult{}, err
		}
	}

	basicTemplatePath := filepath.Join(templatesDir, "basic-test.yaml")

	if _, err := os.Stat(basicTemplatePath); os.IsNotExist(err) {

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

		s.console.Log("Creating basic template: %s", basicTemplatePath)
		if err := os.WriteFile(basicTemplatePath, []byte(basicTemplate), 0644); err != nil {
			s.console.Log("Failed to write basic template: %v", err)
			return cache.ScanResult{}, err
		}
	}

	opts := []nuclei.NucleiSDKOptions{
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			IncludeTags: []string{"basic-test"},
			IDs:         []string{"basic-test"},
		}),
		nuclei.DisableUpdateCheck(),
	}

	ne, err := nuclei.NewNucleiEngineCtx(context.Background(), opts...)
	if err != nil {
		s.console.Log("Failed to create nuclei engine: %v", err)
		return cache.ScanResult{}, err
	}
	defer ne.Close()

	ne.LoadTargets([]string{target}, true)

	var findings []*output.ResultEvent
	var findingsMutex sync.Mutex

	callback := func(event *output.ResultEvent) {
		findingsMutex.Lock()
		defer findingsMutex.Unlock()
		findings = append(findings, event)
		s.console.Log("Found vulnerability: %s (%s) on %s", event.Info.Name, event.Info.SeverityHolder.Severity.String(), event.Host)
	}

	err = ne.ExecuteWithCallback(callback)
	if err != nil {
		s.console.Log("Basic scan failed: %v", err)
		return cache.ScanResult{}, err
	}

	result := cache.ScanResult{
		Target:   target,
		Findings: findings,
		ScanTime: time.Now(),
	}

	s.cache.Set(cacheKey, result)

	s.console.Log("Basic scan completed for %s, found %d vulnerabilities", target, len(findings))

	return result, nil
}

func (s *scannerServiceImpl) GetAll() []cache.ScanResult {
	return s.cache.GetAll()
}
