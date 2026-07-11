# HeaderGuard — AGENTS.md

## Project Overview

HeaderGuard is a Go CLI tool for analyzing HTTP security headers on websites. It checks 15+ security headers, computes a weighted security score (A-F grade), and outputs results in text, JSON, or CSV format.

## Build & Test

```bash
# Build
cd /root/workspace/headerguard
go build -o headerguard .

# Run all tests
go test ./...

# Lint
go vet ./...

# Format
gofmt -l .
```

## Architecture

- **`cmd/headerguard/main.go`** — Cobra CLI entry point
- **`cmd/headerguard/root.go`** — Root command and flags
- **`cmd/headerguard/check.go`** — Check command implementation
- **`internal/models/headers.go`** — Header definitions, weights, criticality
- **`internal/models/result.go`** — Scan result types
- **`internal/checker/checker.go`** — HTTP client, header extraction, scoring
- **`internal/reporter/text.go`** — Terminal text output
- **`internal/reporter/json.go`** — JSON output
- **`internal/reporter/csv.go`** — CSV output

## Key Design Decisions

1. **No external deps** beyond `github.com/spf13/cobra` — stdlib `net/http` for requests
2. **Concurrent scanning** via goroutines with configurable worker count
3. **Weighted scoring** — critical headers (CSP, HSTS, X-Frame-Options) have higher weights
4. **Strict mode** — exit code 1 if critical headers missing, CI-friendly
5. **Input validation** — URL validation, path traversal protection for file input
6. **Safe HTTP client** — no redirects by default, configurable timeout

## Common Tasks

### Add a new security header check
1. Add to `internal/models/headers.go` in the `headerChecks` slice
2. Set appropriate weight and criticality
3. Add test case in `internal/checker/checker_test.go`

### Modify scoring weights
1. Edit `internal/models/headers.go` — adjust `Weight` and `Critical` fields
2. Update README.md scoring table
3. Update tests to match new weights

### Add new output format
1. Create new file in `internal/reporter/` (e.g., `markdown.go`)
2. Implement `Reporter` interface
3. Add format string to cobra validArgs in `cmd/headerguard/check.go`

## Testing Strategy

- **checker_test.go**: Unit tests for header extraction, scoring, criticality detection
- **reporter_test.go**: Tests that each format produces valid output
- **check_test.go**: Integration tests for the check command with mock servers

## CI

GitHub Actions workflow at `.github/workflows/ci.yml` runs `go test ./...`, `go vet ./...`, and `gofmt` on push to main.
