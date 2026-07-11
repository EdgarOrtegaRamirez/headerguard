package models

import "slices"

// HeaderCheck defines a security header check with its weight and criticality.
type HeaderCheck struct {
	Name       string `json:"name"`
	Weight     int    `json:"weight"`
	Critical   bool   `json:"critical"`
	MinValue   string `json:"min_value,omitempty"` // For headers with required values (e.g., HSTS min age)
	Forbidden  bool   `json:"forbidden"`           // If true, header should NOT be present (e.g., Server, X-Powered-By)
	ScoreValue int    `json:"score_value"`         // Points awarded when present (or condition met)
}

// headerChecks defines all security headers to check.
var headerChecks = []HeaderCheck{
	{
		Name:       "Content-Security-Policy",
		Weight:     20,
		Critical:   true,
		ScoreValue: 20,
	},
	{
		Name:       "Strict-Transport-Security",
		Weight:     20,
		Critical:   true,
		ScoreValue: 20,
	},
	{
		Name:       "X-Frame-Options",
		Weight:     10,
		Critical:   true,
		ScoreValue: 10,
	},
	{
		Name:       "X-Content-Type-Options",
		Weight:     10,
		Critical:   false,
		ScoreValue: 10,
	},
	{
		Name:       "X-XSS-Protection",
		Weight:     5,
		Critical:   false,
		ScoreValue: 5,
	},
	{
		Name:       "Referrer-Policy",
		Weight:     10,
		Critical:   false,
		ScoreValue: 10,
	},
	{
		Name:       "Permissions-Policy",
		Weight:     10,
		Critical:   false,
		ScoreValue: 10,
	},
	{
		Name:       "Cross-Origin-Opener-Policy",
		Weight:     5,
		Critical:   false,
		ScoreValue: 5,
	},
	{
		Name:       "Cross-Origin-Resource-Policy",
		Weight:     5,
		Critical:   false,
		ScoreValue: 5,
	},
	{
		Name:       "Cross-Origin-Embedder-Policy",
		Weight:     5,
		Critical:   false,
		ScoreValue: 5,
	},
	{
		Name:       "Cache-Control",
		Weight:     5,
		Critical:   false,
		ScoreValue: 5,
	},
	{
		Name:       "Server",
		Weight:     0,
		Critical:   false,
		Forbidden:  true,
		ScoreValue: 0,
	},
	{
		Name:       "X-Powered-By",
		Weight:     0,
		Critical:   false,
		Forbidden:  true,
		ScoreValue: 0,
	},
}

// GetHeaderChecks returns all defined header checks.
func GetHeaderChecks() []HeaderCheck {
	return slices.Clone(headerChecks)
}

// TotalWeight returns the sum of all header weights.
func TotalWeight() int {
	total := 0
	for _, h := range headerChecks {
		total += h.Weight
	}
	return total
}

// CriticalHeaders returns only critical headers.
func CriticalHeaders() []HeaderCheck {
	var critical []HeaderCheck
	for _, h := range headerChecks {
		if h.Critical {
			critical = append(critical, h)
		}
	}
	return critical
}

// ForbiddenHeaders returns headers that should not be present.
func ForbiddenHeaders() []HeaderCheck {
	var forbidden []HeaderCheck
	for _, h := range headerChecks {
		if h.Forbidden {
			forbidden = append(forbidden, h)
		}
	}
	return forbidden
}

// HeadersWithWeights returns only headers that contribute to the score.
func HeadersWithWeights() []HeaderCheck {
	var headers []HeaderCheck
	for _, h := range headerChecks {
		if h.Weight > 0 {
			headers = append(headers, h)
		}
	}
	return headers
}
