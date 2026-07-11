# HeaderGuard: HTTP Security Headers Analysis CLI

A fast, comprehensive CLI tool for analyzing HTTP security headers on websites. Checks 15+ security headers, provides detailed reports, and exports to multiple formats.

## Features

- **15+ security header checks**: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, Cross-Origin-Embedder-Policy, Cache-Control, Server, X-Powered-By, Expect-CT, Public-Key-Pins
- **Security scoring**: A-F letter grade with weighted scoring
- **Multiple output formats**: text, JSON, CSV
- **Batch mode**: Scan multiple URLs from a file or stdin
- **CI-friendly**: Exit code 1 if critical headers missing (`--strict`)
- **Fast**: Concurrent scanning with configurable timeout
- **IPv6 support**: Works with IPv6-only hosts

## Install

```bash
go install github.com/EdgarOrtegaRamirez/headerguard@latest
```

Or download a binary from [releases](https://github.com/EdgarOrtegaRamirez/headerguard/releases).

## Quick Start

```bash
# Check a single URL
headerguard check https://example.com

# Check with JSON output
headerguard check https://example.com --format json

# Check multiple URLs from a file
headerguard check -f urls.txt

# CI mode — fail if critical headers missing
headerguard check https://example.com --strict

# Custom timeout
headerguard check https://example.com --timeout 5s
```

## Usage

```
headerguard [command]

Available Commands:
  check       Check security headers for one or more URLs
  version     Print version information

Flags:
  -f, --file string   File containing URLs (one per line)
  -F, --format string Output format: text, json, csv (default "text")
  -h, --help          help for headerguard
      --strict        Exit with code 1 if critical headers are missing
  -t, --timeout       Request timeout (default 5s)
  -w, --workers       Number of concurrent workers (default 10)
```

## Security Headers Checked

| Header | Weight | Critical | Description |
|--------|--------|----------|-------------|
| Content-Security-Policy | 20 | Yes | Prevents XSS and data injection |
| Strict-Transport-Security | 20 | Yes | Enforces HTTPS |
| X-Frame-Options | 10 | Yes | Prevents clickjacking |
| X-Content-Type-Options | 10 | No | Prevents MIME sniffing |
| X-XSS-Protection | 5 | No | Legacy XSS filter |
| Referrer-Policy | 10 | No | Controls referrer info |
| Permissions-Policy | 10 | No | Controls browser features |
| Cross-Origin-Opener-Policy | 5 | No | Isolates browsing context |
| Cross-Origin-Resource-Policy | 5 | No | Controls resource sharing |
| Cross-Origin-Embedder-Policy | 5 | No | Controls embed loading |
| Cache-Control | 5 | No | Controls caching |
| Server | - | No | Reveals server info (should be hidden) |
| X-Powered-By | - | No | Reveals tech stack (should be hidden) |

## Scoring

- **A (90-100)**: Excellent security headers
- **B (70-89)**: Good, some improvements needed
- **C (50-69)**: Moderate security posture
- **D (25-49)**: Poor security headers
- **F (0-24)**: Critical security gaps

## Architecture

```
cmd/headerguard/     — Cobra CLI entry point
internal/models/     — Header definitions, scoring models
internal/checker/    — HTTP client, header extraction, scoring
internal/reporter/   — Text, JSON, CSV output formatters
```

## License

MIT — See [LICENSE](LICENSE) for details.
