package models

import (
	"testing"
)

func TestGetHeaderChecks(t *testing.T) {
	checks := GetHeaderChecks()
	if len(checks) == 0 {
		t.Fatal("expected header checks, got none")
	}
	// Verify critical headers exist
	critical := CriticalHeaders()
	if len(critical) == 0 {
		t.Fatal("expected critical headers, got none")
	}
}

func TestTotalWeight(t *testing.T) {
	total := TotalWeight()
	if total <= 0 {
		t.Fatalf("expected positive total weight, got %d", total)
	}
	// Manual check: 20+20+10+10+5+10+10+5+5+5+5 = 105
	expected := 105
	if total != expected {
		t.Errorf("expected total weight %d, got %d", expected, total)
	}
}

func TestCriticalHeaders(t *testing.T) {
	critical := CriticalHeaders()
	expectedNames := []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options"}
	for _, name := range expectedNames {
		found := false
		for _, h := range critical {
			if h.Name == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected critical header %q not found", name)
		}
	}
}

func TestForbiddenHeaders(t *testing.T) {
	forbidden := ForbiddenHeaders()
	if len(forbidden) != 2 {
		t.Errorf("expected 2 forbidden headers, got %d", len(forbidden))
	}
	names := make(map[string]bool)
	for _, h := range forbidden {
		names[h.Name] = true
	}
	if !names["Server"] {
		t.Error("expected Server in forbidden headers")
	}
	if !names["X-Powered-By"] {
		t.Error("expected X-Powered-By in forbidden headers")
	}
}

func TestGrade(t *testing.T) {
	tests := []struct {
		score    int
		maxScore int
		expected string
	}{
		{100, 100, "A"},
		{90, 100, "A"},
		{75, 100, "B"},
		{70, 100, "B"},
		{55, 100, "C"},
		{50, 100, "C"},
		{30, 100, "D"},
		{25, 100, "D"},
		{10, 100, "F"},
		{0, 100, "F"},
		{0, 0, "N/A"},
	}

	for _, tt := range tests {
		result := Grade(tt.score, tt.maxScore)
		if result != tt.expected {
			t.Errorf("Grade(%d, %d) = %q, want %q", tt.score, tt.maxScore, result, tt.expected)
		}
	}
}

func TestHeadersWithWeights(t *testing.T) {
	headers := HeadersWithWeights()
	// Should exclude Server and X-Powered-By (weight 0)
	for _, h := range headers {
		if h.Weight <= 0 {
			t.Errorf("expected positive weight for %q, got %d", h.Name, h.Weight)
		}
	}
	if len(headers) != len(headerChecks)-2 {
		t.Errorf("expected %d headers with weights, got %d", len(headerChecks)-2, len(headers))
	}
}

func TestGetHeaderChecksReturnsClone(t *testing.T) {
	checks1 := GetHeaderChecks()
	checks2 := GetHeaderChecks()
	if &checks1[0] == &checks2[0] {
		t.Error("GetHeaderChecks should return a clone, not the same slice")
	}
}
