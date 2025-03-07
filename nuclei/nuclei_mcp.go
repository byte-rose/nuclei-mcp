package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

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

// ===== Configuration =====

// Config holds all configuration parameters
type Config struct {
	LogLevel    string        `env:"LOG_LEVEL" envDefault:"info"`
	MaxWorkers  int           `env:"MAX_WORKERS" envDefault:"5"`
	UsePassive  bool          `env:"USE_PASSIVE" envDefault:"false"`
	CacheExpiry time.Duration `env:"CACHE_EXPIRY" envDefault:"5m"`
}

// ===== Scanner Pool =====

// ScannerPool maintains a pool of nuclei engines
type ScannerPool struct {
	scanners chan *nuclei.NucleiEngine
	size     int
	lock     sync.Mutex
	logger   *zap.Logger
}

// NewScannerPool creates a new scanner pool
func NewScannerPool(size int, logger *zap.Logger) *ScannerPool {
	logger.Info("Initializing scanner pool", zap.Int("size", size))

	pool := &ScannerPool{
		scanners: make(chan *nuclei.NucleiEngine, size),
		size:     size,
		logger:   logger,
	}

	// Initialize scanners
	for i := 0; i < size; i++ {
		options := []nuclei.NucleiSDKOptions{}
		scanner, err := nuclei.NewNucleiEngine(options...)
		if err != nil {
			logger.Error("Failed to create scanner", zap.Int("index", i), zap.Error(err))
			continue
		}
		pool.scanners <- scanner
	}

	return pool
}

// Get retrieves a scanner from the pool
func (p *ScannerPool) Get() (*nuclei.NucleiEngine, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	select {
	case scanner := <-p.scanners:
		return scanner, nil
	default:
		p.logger.Warn("Scanner pool exhausted, creating new scanner")
		scanner, err := nuclei.NewNucleiEngine()
		if err != nil {
			return nil, err
		}
		return scanner, nil
	}
}

// Put returns a scanner to the pool
func (p *ScannerPool) Put(scanner *nuclei.NucleiEngine) {
	p.lock.Lock()
	defer p.lock.Unlock()

	select {
	case p.scanners <- scanner:
		// Scanner returned to pool
	default:
		p.logger.Warn("Scanner pool full, closing scanner")
		scanner.Close()
	}
}

// Close closes all scanners in the pool
func (p *ScannerPool) Close() {
	p.lock.Lock()
	defer p.lock.Unlock()

	close(p.scanners)
	for scanner := range p.scanners {
		scanner.Close()
	}
}

// ===== Result Cache =====

// ScanResult represents the result of a nuclei scan
type ScanResult struct {
	Target   string
	Findings []*output.ResultEvent
	ScanTime time.Time
}

// ResultCache caches scan results
type ResultCache struct {
	cache  map[string]ScanResult
	expiry time.Duration
	lock   sync.RWMutex
	logger *zap.Logger
}

// NewResultCache creates a new result cache
func NewResultCache(expiry time.Duration, logger *zap.Logger) *ResultCache {
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
		c.logger.Debug("Cache entry expired", zap.String("key", key))
		return ScanResult{}, false
	}

	c.logger.Debug("Cache hit", zap.String("key", key))
	return result, true
}

// Set stores a result in the cache
func (c *ResultCache) Set(key string, result ScanResult) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.cache[key] = result
	c.logger.Debug("Cache entry set", zap.String("key", key))
}

// ===== Nuclei Scanner Service =====

// ScannerService provides nuclei scanning operations
type ScannerService struct {
	pool   *ScannerPool
	cache  *ResultCache
	logger *zap.Logger
}

// NewScannerService creates a new scanner service
func NewScannerService(pool *ScannerPool, cache *ResultCache, logger *zap.Logger) *ScannerService {
	return &ScannerService{
		pool:   pool,
		cache:  cache,
		logger: logger,
	}
}

// CreateCacheKey generates a cache key from scan parameters
func (s *ScannerService) CreateCacheKey(target string, severity string, protocols string) string {
	return fmt.Sprintf("%s:%s:%s", target, severity, protocols)
}

// Scan performs a nuclei scan
func (s *ScannerService) Scan(target string, severity string, protocols string) (ScanResult, error) {
	// Create cache key
	cacheKey := s.CreateCacheKey(target, severity, protocols)

	// Check cache first
	if result, found := s.cache.Get(cacheKey); found {
		s.logger.Info("Returning cached scan result",
			zap.String("target", target),
			zap.Int("findings", len(result.Findings)))
		return result, nil
	}

	// Get scanner from pool
	s.logger.Info("Starting new scan", zap.String("target", target))
	scanner, err := s.pool.Get()
	if err != nil {
		return ScanResult{}, fmt.Errorf("failed to get scanner: %v", err)
	}
	defer s.pool.Put(scanner)

	// Create options
	options := []nuclei.NucleiSDKOptions{}
	if severity != "" {
		options = append(options, nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			Severity: severity,
		}))
	}
	if protocols != "" {
		options = append(options, nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			ProtocolTypes: protocols,
		}))
	}

	// Store scan results
	var scanResults []*output.ResultEvent

	// Load target and execute scan
	scanner.LoadTargets([]string{target}, false)
	err = scanner.ExecuteWithCallback(func(event *output.ResultEvent) {
		s.logger.Debug("Found vulnerability",
			zap.String("name", event.Info.Name),
			zap.String("host", event.Host))
		scanResults = append(scanResults, event)
	})

	if err != nil {
		return ScanResult{}, fmt.Errorf("scan execution failed: %v", err)
	}

	// Create result
	result := ScanResult{
		Target:   target,
		Findings: scanResults,
		ScanTime: time.Now(),
	}

	// Cache result
	s.cache.Set(cacheKey, result)

	s.logger.Info("Scan completed",
		zap.String("target", target),
		zap.Int("findings", len(scanResults)))

	return result, nil
}

// ===== Nuclei MCP Tool =====

// NewNucleiScanTool creates a nuclei scan MCP tool
func NewNucleiScanTool(service *ScannerService, logger *zap.Logger) fxctx.Tool {
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
					"severity": {
						"type":        "string",
						"description": "Filter templates by severity",
						"enum":        []interface{}{"info", "low", "medium", "high", "critical"},
					},
					"protocols": {
						"type":        "string",
						"description": "Filter templates by protocol (e.g., http, dns)",
					},
				},
				Required: []string{"target"},
			},
		},
		func(args map[string]interface{}) *mcp.CallToolResult {
			logger.Info("Nuclei scan requested", zap.Any("args", args))

			// Extract parameters
			target, _ := args["target"].(string)
			if target == "" {
				logger.Warn("Missing target parameter")
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

			severity, _ := args["severity"].(string)
			protocols, _ := args["protocols"].(string)

			// Perform scan
			result, err := service.Scan(target, severity, protocols)
			if err != nil {
				logger.Error("Scan failed", zap.Error(err))
				return &mcp.CallToolResult{
					IsError: ptr(true),
					Content: []interface{}{
						mcp.TextContent{
							Type: "text",
							Text: fmt.Sprintf("Scan execution failed: %v", err),
						},
					},
				}
			}

			if len(result.Findings) == 0 {
				logger.Info("No vulnerabilities found", zap.String("target", target))
				return &mcp.CallToolResult{
					Content: []interface{}{
						mcp.TextContent{
							Type: "text",
							Text: fmt.Sprintf("No vulnerabilities found for target: %s", target),
						},
					},
				}
			}

			// Format results for LLM consumption
			logger.Info("Formatting scan results", zap.Int("count", len(result.Findings)))
			formattedResults := make([]interface{}, len(result.Findings))
			for i, finding := range result.Findings {
				resultInfo := map[string]interface{}{
					"name":        finding.Info.Name,
					"description": finding.Info.Description,
					"template_id": finding.TemplateID,
					"matched_at":  finding.MatcherName,
					"host":        finding.Host,
					"timestamp":   finding.Timestamp,
				}

				jsonData, err := json.Marshal(resultInfo)
				if err != nil {
					logger.Error("Failed to marshal result", zap.Error(err))
					jsonData = []byte(fmt.Sprintf("Error formatting result: %v", err))
				}

				formattedResults[i] = mcp.TextContent{
					Type: "text",
					Text: string(jsonData),
				}
			}

			return &mcp.CallToolResult{
				Meta: map[string]interface{}{
					"total_findings": len(result.Findings),
					"target":         target,
				},
				Content: formattedResults,
			}
		},
	)
}

// ===== Resource Providers =====

// VulnerabilityReportsProvider implements a resource provider for vulnerability reports
type VulnerabilityReportsProvider struct {
	service       *ScannerService
	logger        *zap.Logger
	recentResults []ScanResult
	lock          sync.RWMutex
}

// NewVulnerabilityReportsProvider creates a new vulnerability reports provider
func NewVulnerabilityReportsProvider(service *ScannerService, logger *zap.Logger) *VulnerabilityReportsProvider {
	return &VulnerabilityReportsProvider{
		service:       service,
		logger:        logger,
		recentResults: make([]ScanResult, 0),
	}
}

// AddResult adds a scan result to the recent results
func (p *VulnerabilityReportsProvider) AddResult(result ScanResult) {
	p.lock.Lock()
	defer p.lock.Unlock()

	// Keep only the latest 10 results
	if len(p.recentResults) >= 10 {
		p.recentResults = p.recentResults[1:]
	}
	p.recentResults = append(p.recentResults, result)
}

// GetResource implements the resource provider interface
func (p *VulnerabilityReportsProvider) GetResource(uri string) (*mcp.ReadResourceResult, error) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	results := make([]map[string]interface{}, 0)
	for _, result := range p.recentResults {
		resultMap := map[string]interface{}{
			"target":    result.Target,
			"findings":  len(result.Findings),
			"scan_time": result.ScanTime,
		}
		results = append(results, resultMap)
	}

	data, err := json.Marshal(results)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal results: %w", err)
	}

	return &mcp.ReadResourceResult{
		Contents: []interface{}{
			mcp.TextResourceContents{
				MimeType: ptr("application/json"),
				Text:     string(data),
				Uri:      uri,
			},
		},
	}, nil
}

// ===== Application Setup =====

// SetupSignalHandling configures graceful shutdown
func SetupSignalHandling(logger *zap.Logger) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		logger.Info("Shutdown signal received, exiting...")
		os.Exit(0)
	}()
}

// Main function to set up and run the MCP server
func main() {
	// Initialize logger
	logConfig := zap.NewDevelopmentConfig()
	logConfig.Level.SetLevel(zap.InfoLevel)
	logger, _ := logConfig.Build()
	defer logger.Sync()

	logger.Info("Starting Nuclei MCP server...")
	SetupSignalHandling(logger)

	// Create configuration
	config := Config{
		MaxWorkers:  5,
		CacheExpiry: 5 * time.Minute,
	}

	// Initialize components
	scannerPool := NewScannerPool(config.MaxWorkers, logger)
	defer scannerPool.Close()

	resultCache := NewResultCache(config.CacheExpiry, logger)
	scannerService := NewScannerService(scannerPool, resultCache, logger)

	// Create resource provider
	vulnReportsProvider := NewVulnerabilityReportsProvider(scannerService, logger)

	// Provider functions for FX
	scannerToolProvider := func(lc fx.Lifecycle, logger *zap.Logger) fxctx.Tool {
		tool := NewNucleiScanTool(scannerService, logger)
		return tool
	}

	vulnReportsResourceFunc := func() fxctx.Resource {
		return fxctx.NewResource(
			mcp.Resource{
				Name:        "vulnerability-reports",
				Uri:         "nuclei://vulnerability-reports",
				MimeType:    ptr("application/json"),
				Description: ptr("Access recent vulnerability scan reports"),
				Annotations: &mcp.ResourceAnnotations{
					Audience: []mcp.Role{
						mcp.RoleAssistant, mcp.RoleUser,
					},
				},
			},
			vulnReportsProvider.GetResource,
		)
	}

	// Run the MCP server
	app.
		NewBuilder().
		// Add the Nuclei scan tool with logger injection
		WithTool(scannerToolProvider).
		// Add resource provider - renamed to WithResource to match git example
		WithResource(vulnReportsResourceFunc).
		// Set server metadata
		WithName("nuclei-mcp").
		WithVersion("0.1.0").
		// Use stdio transport for communication with LLMs
		WithTransport(stdio.NewTransport()).
		// Configure logging
		WithFxOptions(fx.Provide(func() *zap.Logger {
			return logger
		}),
			fx.Option(fx.WithLogger(
				func(logger *zap.Logger) fxevent.Logger {
					return &fxevent.ZapLogger{Logger: logger.Named("fx")}
				},
			)),
		).
		Run()

	logger.Info("Nuclei MCP server stopped")
}

// Helper function to create pointers
func ptr[T any](v T) *T {
	return &v
}
