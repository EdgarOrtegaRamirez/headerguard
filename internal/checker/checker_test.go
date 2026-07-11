package checker

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestServer(headers map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
	}))
}

func TestCheckURL(t *testing.T) {
	srv := newTestServer(map[string]string{
		"Content-Security-Policy": "default-src 'self'",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
	})
	defer srv.Close()

	c := NewChecker(5 * time.Second)
	res, err := c.CheckURL(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", res.StatusCode)
	}
	if res.Score != 60 {
		t.Errorf("expected score 60, got %d", res.Score)
	}
	if res.Grade != "C" {
		t.Errorf("expected grade C, got %s", res.Grade)
	}
	if len(res.CriticalMissing) > 0 {
		t.Errorf("expected no critical missing, got %v", res.CriticalMissing)
	}
}

func TestCheckURLNoHeaders(t *testing.T) {
	srv := newTestServer(map[string]string{})
	defer srv.Close()

	c := NewChecker(5 * time.Second)
	res, err := c.CheckURL(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Score != 0 {
		t.Errorf("expected score 0, got %d", res.Score)
	}
	if res.Grade != "F" {
		t.Errorf("expected grade F, got %s", res.Grade)
	}
	if len(res.CriticalMissing) != 3 {
		t.Errorf("expected 3 critical missing, got %d: %v", len(res.CriticalMissing), res.CriticalMissing)
	}
}

func TestCheckURLForbiddenHeaders(t *testing.T) {
	srv := newTestServer(map[string]string{
		"Server":         "Apache/2.4.41",
		"X-Powered-By":   "PHP/7.4",
		"Content-Security-Policy": "default-src 'self'",
		"Strict-Transport-Security": "max-age=31536000",
		"X-Frame-Options": "SAMEORIGIN",
	})
	defer srv.Close()

	c := NewChecker(5 * time.Second)
	res, err := c.CheckURL(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Score != 50 {
		t.Errorf("expected score 50 (CSP 20 + HSTS 20 + XFO 10), got %d", res.Score)
	}

	// Check that forbidden headers are detected
	serverFound := false
	poweredByFound := false
	for _, r := range res.Results {
		if r.Name == "Server" && r.Found {
			serverFound = true
		}
		if r.Name == "X-Powered-By" && r.Found {
			poweredByFound = true
		}
	}
	if !serverFound {
		t.Error("expected Server header to be detected as found")
	}
	if !poweredByFound {
		t.Error("expected X-Powered-By header to be detected as found")
	}
}

func TestCheckURLError(t *testing.T) {
	c := NewChecker(50 * time.Millisecond)
	_, err := c.CheckURL("https://this-domain-does-not-exist-xyz123.invalid")
	if err == nil {
		t.Error("expected error for invalid domain, got nil")
	}
}

func TestCheckURLCaseInsensitive(t *testing.T) {
	srv := newTestServer(map[string]string{
		"content-security-policy": "default-src 'self'",
		"strict-transport-security": "max-age=31536000",
		"x-frame-options": "DENY",
	})
	defer srv.Close()

	c := NewChecker(5 * time.Second)
	res, err := c.CheckURL(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Score != 50 {
		t.Errorf("expected score 50 (case-insensitive match), got %d", res.Score)
	}
}

func TestNewChecker(t *testing.T) {
	c := NewChecker(10 * time.Second)
	if c.Timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", c.Timeout)
	}
	if c.Client == nil {
		t.Error("expected non-nil client")
	}
}
