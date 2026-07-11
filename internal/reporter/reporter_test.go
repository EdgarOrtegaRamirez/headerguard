package reporter

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/EdgarOrtegaRamirez/headerguard/internal/models"
)

func makeTestResult(url string) *models.ScanResult {
	return &models.ScanResult{
		URL:      url,
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Security-Policy":       "default-src 'self'",
			"Strict-Transport-Security":     "max-age=31536000",
			"X-Frame-Options":               "DENY",
		},
		Score:   50,
		Grade:   "C",
		MaxScore: 105,
		Results: []models.HeaderResult{
			{Name: "Content-Security-Policy", Present: true, Value: "default-src 'self'", Weight: 20, Critical: true, Found: true},
			{Name: "Strict-Transport-Security", Present: true, Value: "max-age=31536000", Weight: 20, Critical: true, Found: true},
			{Name: "X-Frame-Options", Present: true, Value: "DENY", Weight: 10, Critical: true, Found: true},
			{Name: "X-Content-Type-Options", Present: false, Weight: 10, Critical: false, Found: false},
		},
	}
}

func TestTextOutput(t *testing.T) {
	var buf bytes.Buffer
	r := NewReporter(&buf)
	results := []*models.ScanResult{makeTestResult("https://example.com")}
	if err := r.Text(results); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "example.com") {
		t.Error("expected URL in output")
	}
	if !strings.Contains(output, "Grade: C") {
		t.Error("expected grade in output")
	}
	if !strings.Contains(output, "Content-Security-Policy") {
		t.Error("expected header name in output")
	}
}

func TestJSONOutput(t *testing.T) {
	var buf bytes.Buffer
	r := NewReporter(&buf)
	results := []*models.ScanResult{makeTestResult("https://example.com")}
	if err := r.JSON(results); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify it's valid JSON
	var parsed []models.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("expected 1 result, got %d", len(parsed))
	}
	if parsed[0].URL != "https://example.com" {
		t.Errorf("expected URL https://example.com, got %s", parsed[0].URL)
	}
	if parsed[0].Grade != "C" {
		t.Errorf("expected grade C, got %s", parsed[0].Grade)
	}
}

func TestCSVOutput(t *testing.T) {
	var buf bytes.Buffer
	r := NewReporter(&buf)
	results := []*models.ScanResult{makeTestResult("https://example.com")}
	if err := r.CSV(results); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "example.com") {
		t.Error("expected URL in CSV output")
	}
	if !strings.Contains(output, "C") {
		t.Error("expected grade in CSV output")
	}
}

func TestPrintHeader(t *testing.T) {
	// Capture stdout by swapping it
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	PrintHeader()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()
	if !strings.Contains(output, "HeaderGuard") {
		t.Error("expected HeaderGuard in header output")
	}
}

func TestMultipleResults(t *testing.T) {
	var buf bytes.Buffer
	r := NewReporter(&buf)
	results := []*models.ScanResult{
		makeTestResult("https://example.com"),
		makeTestResult("https://test.com"),
	}
	if err := r.Text(results); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "example.com") {
		t.Error("expected first URL in output")
	}
	if !strings.Contains(output, "test.com") {
		t.Error("expected second URL in output")
	}
}
