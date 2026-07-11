# Security

## Security Considerations

### Input Validation
- All URLs are validated before use
- File paths are resolved safely with path traversal protection
- User-provided input is never executed as code

### HTTP Client Security
- Redirects are disabled by default (follows best practice for security scanning)
- TLS verification is always enabled
- Timeout prevents hanging on unresponsive hosts
- User-Agent is set to identify the tool

### Network Security
- No sensitive data is transmitted
- Results are only displayed locally or exported to user-specified files
- No DNS rebinding protection needed (single-host per request)

### Data Handling
- No credentials or tokens are stored
- No logging of response bodies (only headers)
- File input is read safely with size limits

## Reporting Security Issues

If you discover a security vulnerability, please open a private security advisory on GitHub rather than a public issue.
