# Secrets Scanner

A comprehensive GitHub Action that scans your repository for exposed secrets, API keys, and sensitive information using advanced pattern matching. Helps prevent accidental exposure of sensitive data in your codebase.

## Features

- 🔍 **Comprehensive Detection**: Scans for AWS keys, GitHub tokens, Slack tokens, Stripe keys, JWT tokens, private keys, and more
- 🎯 **Custom Patterns**: Support for custom regex patterns to detect organization-specific secrets
- 📊 **Severity Levels**: Categorizes findings by severity (low, medium, high, critical)
- 📋 **Multiple Output Formats**: Generates JSON reports and SARIF files for GitHub Security tab integration
- 💬 **PR Comments**: Automatically comments on pull requests with scan results
- ⚙️ **Configurable**: Flexible configuration options for paths, exclusions, and thresholds
- 🚀 **Fast & Efficient**: Optimized scanning with smart exclusions for binary files and large files

## Usage

```yaml
name: Security Scan
on:
  pull_request:
  push:
    branches: [ main, develop ]

jobs:
  secrets-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: write
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        
      - name: Scan for secrets
        uses: ./
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on-detection: true
          comment-pr: true
          severity-threshold: 'medium'
          
      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: secrets-scan-results.sarif
```

## Inputs

| Name | Description | Required | Default |
|------|-------------|----------|---------|
| `github-token` | GitHub token for API access and commenting | Yes | - |
| `scan-path` | Path to scan for secrets (relative to repository root) | No | `.` |
| `exclude-paths` | Comma-separated list of paths to exclude from scanning | No | `node_modules,.git,dist,build` |
| `fail-on-detection` | Whether to fail the action if secrets are detected | No | `true` |
| `comment-pr` | Whether to comment on PR with findings (only for pull_request events) | No | `true` |
| `severity-threshold` | Minimum severity level to report (low, medium, high, critical) | No | `medium` |
| `custom-patterns` | JSON string of custom regex patterns to scan for | No | `{}` |

## Outputs

| Name | Description |
|------|-------------|
| `secrets-found` | Number of secrets detected |
| `report-file` | Path to the generated JSON report file |
| `sarif-file` | Path to the generated SARIF report file |
| `has-secrets` | Whether any secrets were found (true/false) |

## Examples

### Basic Usage

```yaml
- name: Scan for secrets
  uses: vercel-labs/secrets-scanner@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Advanced Configuration

```yaml
- name: Advanced secrets scan
  uses: vercel-labs/secrets-scanner@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    scan-path: './src'
    exclude-paths: 'node_modules,.git,dist,build,tests/fixtures'
    fail-on-detection: false
    comment-pr: true
    severity-threshold: 'high'
    custom-patterns: >-
      {
        "company-api-key": {
          "pattern": "COMP_[A-Z0-9]{32}",
          "severity": "critical",
          "description": "Company API Key"
        },
        "database-url": {
          "pattern": "postgresql://[^\\s]+",
          "severity": "high",
          "description": "Database Connection URL"
        }
      }
```

### Continuous Monitoring

```yaml
name: Daily Security Scan
on:
  schedule:
    - cron: '0 2 * * *'  # Run daily at 2 AM
  workflow_dispatch:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - name: Full repository scan
        uses: vercel-labs/secrets-scanner@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          severity-threshold: 'low'
          fail-on-detection: true
      
      - name: Upload results to Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: secrets-scan-results.sarif
```

### Custom Patterns Only

```yaml
- name: Scan for organization secrets
  uses: vercel-labs/secrets-scanner@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    severity-threshold: 'low'
    custom-patterns: >-
      {
        "internal-token": {
          "pattern": "INT_[a-zA-Z0-9]{40}",
          "severity": "critical",
          "description": "Internal Service Token"
        },
        "session-key": {
          "pattern": "sess_[a-f0-9]{64}",
          "severity": "medium",
          "description": "Session Key"
        }
      }
```

## Detected Secret Types

The action detects the following types of secrets out of the box:

| Type | Severity | Description |
|------|----------|-------------|
| AWS Access Key | Critical | Amazon Web Services access keys |
| AWS Secret Key | Critical | Amazon Web Services secret keys |
| GitHub Token | Critical | GitHub personal access tokens |
| Slack Token | High | Slack bot and user tokens |
| Stripe Key | Critical | Stripe payment processing keys |
| Google API Key | High | Google Cloud and API keys |
| JWT Token | Medium | JSON Web Tokens |
| Private Key | Critical | RSA, EC, OpenSSH, DSA private keys |
| Generic Secret | Medium | Common secret/password patterns |
| Email Password | High | Email addresses with passwords |

## Custom Patterns Format

Custom patterns should be provided as a JSON string with the following format:

```json
{
  "pattern-name": {
    "pattern": "regex-pattern",
    "severity": "low|medium|high|critical",
    "description": "Human readable description"
  }
}
```

Example:
```json
{
  "api-key": {
    "pattern": "api[_-]key[\"\\s]*[=:][\"\\s]*[a-zA-Z0-9]{32,}",
    "severity": "high",
    "description": "Generic API Key"
  }
}
```

## Reports

### JSON Report

The action generates a comprehensive JSON report (`secrets-scan-report.json`) with:
- Scan metadata and statistics
- Detailed findings with file locations
- Severity breakdown
- Remediation guidance

### SARIF Report

A SARIF-compliant report (`secrets-scan-results.sarif`) is generated for integration with:
- GitHub Security tab
- Security dashboards
- Other SARIF-compatible tools

## Security Considerations

- The action only **detects and reports** secrets, never exposes or exploits them
- Sensitive matches are truncated in reports to prevent accidental exposure
- Reports should be treated as sensitive and not exposed publicly
- Consider using branch protection rules to enforce secret scanning

## Troubleshooting

### High False Positive Rate

- Adjust the `severity-threshold` to focus on higher severity findings
- Use `exclude-paths` to skip test files, documentation, or mock data
- Review and refine custom patterns

### Performance Issues

- Exclude large directories like `node_modules`, `dist`, `build`
- The action automatically skips files larger than 10MB
- Use specific `scan-path` instead of scanning entire repository

### Missing Permissions

```yaml
permissions:
  contents: read
  pull-requests: write      # For PR comments
  security-events: write    # For SARIF uploads
```

### Action Failing

If `fail-on-detection` is `true` (default), the action will fail when secrets are found. Set to `false` for warning-only mode:

```yaml
with:
  fail-on-detection: false
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new patterns or features
4. Update documentation
5. Submit a pull request

### Adding New Secret Patterns

To add new built-in patterns, update the `SECRET_PATTERNS` object in `main.js`:

```javascript
'new-service-key': {
  pattern: /NEW_[A-Z0-9]{20}/g,
  severity: 'critical',
  description: 'New Service API Key'
}
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

For issues and questions:
- 🐛 [Report bugs](https://github.com/vercel-labs/agent-browser/issues)
- 💡 [Request features](https://github.com/vercel-labs/agent-browser/issues)
- 📖 [View documentation](https://github.com/vercel-labs/agent-browser)

---

**⚠️ Important**: This tool helps detect secrets but is not a substitute for proper secret management practices. Always use environment variables, secret management services, and follow security best practices.