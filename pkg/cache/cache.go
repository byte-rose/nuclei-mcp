package cache

import (
	"log"
	"sync"
	"time"

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

// GetAll returns a copy of all items in the cache.
func (c *ResultCache) GetAll() []ScanResult {
	c.lock.RLock()
	defer c.lock.RUnlock()

	results := make([]ScanResult, 0, len(c.cache))
	for _, result := range c.cache {
		results = append(results, result)
	}
	return results
}
