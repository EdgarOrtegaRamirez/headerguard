package models

// HeaderResult represents the check result for a single header.
type HeaderResult struct {
	Name      string `json:"name"`
	Present   bool   `json:"present"`
	Value     string `json:"value,omitempty"`
	Weight    int    `json:"weight"`
	Critical  bool   `json:"critical"`
	Forbidden bool   `json:"forbidden"`
	Found     bool   `json:"found"` // For forbidden headers: true means security issue
}

// ScanResult represents the complete scan result for a single URL.
type ScanResult struct {
	URL             string            `json:"url"`
	StatusCode      int               `json:"status_code"`
	Headers         map[string]string `json:"headers"`
	Results         []HeaderResult    `json:"results"`
	Score           int               `json:"score"`
	Grade           string            `json:"grade"`
	MaxScore        int               `json:"max_score"`
	CriticalMissing []string          `json:"critical_missing,omitempty"`
}

// Grade returns the letter grade based on score percentage.
func Grade(score, maxScore int) string {
	if maxScore == 0 {
		return "N/A"
	}
	pct := float64(score) / float64(maxScore) * 100
	switch {
	case pct >= 90:
		return "A"
	case pct >= 70:
		return "B"
	case pct >= 50:
		return "C"
	case pct >= 25:
		return "D"
	default:
		return "F"
	}
}
