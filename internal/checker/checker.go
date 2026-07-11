package checker

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/EdgarOrtegaRamirez/headerguard/internal/models"
)

// Checker performs HTTP security header analysis.
type Checker struct {
	Timeout time.Duration
	Client  *http.Client
}

// NewChecker creates a new Checker with the given timeout.
func NewChecker(timeout time.Duration) *Checker {
	return &Checker{
		Timeout: timeout,
		Client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Disable redirects — we want to check the final URL's headers
				// but for security scanning, following redirects can mask issues.
				// We'll still get the initial response headers.
				return http.ErrUseLastResponse
			},
		},
	}
}

// CheckURL performs a security header check on the given URL.
func (c *Checker) CheckURL(url string) (*models.ScanResult, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", url, err)
	}
	req.Header.Set("User-Agent", "HeaderGuard/1.0 (Security Headers Analyzer)")
	req.Header.Set("Accept", "*/*")

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed for %q: %w", url, err)
	}
	defer resp.Body.Close()

	// Read all headers (case-insensitive map)
	headers := make(map[string]string)
	for name, values := range resp.Header {
		headers[name] = strings.Join(values, ", ")
	}

	// Run checks against all defined header checks
	checks := models.GetHeaderChecks()
	results := make([]models.HeaderResult, 0, len(checks))
	score := 0
	var criticalMissing []string

	for _, check := range checks {
		result := c.checkHeader(headers, check)
		results = append(results, result)
		if result.Found {
			score += check.ScoreValue
		}
		if check.Critical && !result.Found {
			criticalMissing = append(criticalMissing, check.Name)
		}
	}

	maxScore := models.TotalWeight()
	grade := models.Grade(score, maxScore)

	return &models.ScanResult{
		URL:             url,
		StatusCode:      resp.StatusCode,
		Headers:         headers,
		Results:         results,
		Score:           score,
		Grade:           grade,
		MaxScore:        maxScore,
		CriticalMissing: criticalMissing,
	}, nil
}

// checkHeader checks a single header against its definition.
func (c *Checker) checkHeader(headers map[string]string, check models.HeaderCheck) models.HeaderResult {
	result := models.HeaderResult{
		Name:      check.Name,
		Present:   false,
		Weight:    check.Weight,
		Critical:  check.Critical,
		Forbidden: check.Forbidden,
	}

	// Case-insensitive header lookup
	for name, value := range headers {
		if strings.EqualFold(name, check.Name) {
			result.Present = true
			result.Value = value
			break
		}
	}

	// For forbidden headers, presence is a security issue
	if check.Forbidden {
		result.Found = result.Present
	} else {
		result.Found = result.Present
	}

	return result
}
