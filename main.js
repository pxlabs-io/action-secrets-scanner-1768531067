const core = require('@actions/core');
const github = require('@actions/github');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Predefined secret patterns with severity levels
const SECRET_PATTERNS = {
  'aws-access-key': {
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'critical',
    description: 'AWS Access Key ID'
  },
  'aws-secret-key': {
    pattern: /[0-9a-zA-Z/+]{40}/g,
    severity: 'critical',
    description: 'AWS Secret Access Key',
    context: ['aws', 'secret', 'key']
  },
  'github-token': {
    pattern: /gh[pousr]_[A-Za-z0-9_]{36}/g,
    severity: 'critical',
    description: 'GitHub Personal Access Token'
  },
  'slack-token': {
    pattern: /xox[baprs]-([0-9a-zA-Z]{10,48})?/g,
    severity: 'high',
    description: 'Slack Token'
  },
  'stripe-key': {
    pattern: /sk_live_[0-9a-zA-Z]{24}/g,
    severity: 'critical',
    description: 'Stripe Live Secret Key'
  },
  'google-api-key': {
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    severity: 'high',
    description: 'Google API Key'
  },
  'jwt-token': {
    pattern: /eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
    severity: 'medium',
    description: 'JWT Token'
  },
  'private-key': {
    pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    severity: 'critical',
    description: 'Private Key'
  },
  'generic-secret': {
    pattern: /(?i)(secret|password|passwd|pwd|key|token|api[_-]?key)\s*[=:]\s*['\"][^'\"\s]{8,}['\"]?/g,
    severity: 'medium',
    description: 'Generic Secret Pattern'
  },
  'email-password': {
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:[^\s]{6,}/g,
    severity: 'high',
    description: 'Email with Password'
  }
};

const SEVERITY_LEVELS = {
  'low': 1,
  'medium': 2,
  'high': 3,
  'critical': 4
};

class SecretsScanner {
  constructor() {
    this.findings = [];
    this.scannedFiles = 0;
    this.excludePaths = [];
    this.severityThreshold = 'medium';
    this.customPatterns = {};
  }

  initialize() {
    // Get inputs
    const excludePaths = core.getInput('exclude-paths');
    this.excludePaths = excludePaths.split(',').map(p => p.trim()).filter(p => p);
    
    this.severityThreshold = core.getInput('severity-threshold') || 'medium';
    
    // Parse custom patterns
    const customPatternsInput = core.getInput('custom-patterns');
    if (customPatternsInput) {
      try {
        const parsed = JSON.parse(customPatternsInput);
        Object.entries(parsed).forEach(([key, config]) => {
          if (config.pattern && config.severity) {
            this.customPatterns[key] = {
              pattern: new RegExp(config.pattern, 'g'),
              severity: config.severity,
              description: config.description || `Custom pattern: ${key}`
            };
          }
        });
      } catch (error) {
        core.warning(`Failed to parse custom patterns: ${error.message}`);
      }
    }
    
    core.info(`Initialized scanner with ${Object.keys(this.customPatterns).length} custom patterns`);
    core.info(`Severity threshold: ${this.severityThreshold}`);
    core.info(`Exclude paths: ${this.excludePaths.join(', ')}`);
  }

  shouldExcludePath(filePath) {
    return this.excludePaths.some(excludePath => {
      const normalizedExclude = excludePath.replace(/\\/g, '/');
      const normalizedFile = filePath.replace(/\\/g, '/');
      return normalizedFile.includes(normalizedExclude) || 
             normalizedFile.startsWith(normalizedExclude + '/') ||
             normalizedFile === normalizedExclude;
    });
  }

  scanFile(filePath) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const lines = content.split('\n');
      const allPatterns = { ...SECRET_PATTERNS, ...this.customPatterns };

      Object.entries(allPatterns).forEach(([patternName, config]) => {
        const matches = content.matchAll(config.pattern);
        
        for (const match of matches) {
          const lineNumber = this.getLineNumber(content, match.index);
          const line = lines[lineNumber - 1];
          
          // Skip if severity is below threshold
          if (SEVERITY_LEVELS[config.severity] < SEVERITY_LEVELS[this.severityThreshold]) {
            continue;
          }

          // Additional context validation for certain patterns
          if (config.context && !this.hasContext(line.toLowerCase(), config.context)) {
            continue;
          }

          // Generate a hash of the match for deduplication
          const hash = crypto.createHash('md5')
            .update(`${filePath}:${lineNumber}:${patternName}`)
            .digest('hex').substring(0, 8);

          const finding = {
            id: hash,
            type: patternName,
            description: config.description,
            severity: config.severity,
            file: filePath,
            line: lineNumber,
            column: match.index - content.lastIndexOf('\n', match.index),
            match: match[0].substring(0, 50) + (match[0].length > 50 ? '...' : ''),
            context: line.trim()
          };

          // Avoid duplicates
          if (!this.findings.find(f => f.id === finding.id)) {
            this.findings.push(finding);
          }
        }
      });

      this.scannedFiles++;
    } catch (error) {
      core.warning(`Failed to scan file ${filePath}: ${error.message}`);
    }
  }

  hasContext(line, contextWords) {
    return contextWords.some(word => line.includes(word.toLowerCase()));
  }

  getLineNumber(content, index) {
    return content.substring(0, index).split('\n').length;
  }

  scanDirectory(dirPath) {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      const relativePath = path.relative(process.cwd(), fullPath);
      
      if (this.shouldExcludePath(relativePath)) {
        continue;
      }

      if (entry.isDirectory()) {
        this.scanDirectory(fullPath);
      } else if (entry.isFile()) {
        // Skip binary files and large files
        const stats = fs.statSync(fullPath);
        if (stats.size > 10 * 1024 * 1024) { // Skip files > 10MB
          core.debug(`Skipping large file: ${relativePath}`);
          continue;
        }

        // Skip common binary file extensions
        const ext = path.extname(fullPath).toLowerCase();
        const binaryExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip', '.tar', '.gz', '.exe', '.bin', '.so', '.dll'];
        if (binaryExtensions.includes(ext)) {
          continue;
        }

        this.scanFile(fullPath);
      }
    }
  }

  generateReport() {
    const report = {
      timestamp: new Date().toISOString(),
      scanned_files: this.scannedFiles,
      total_findings: this.findings.length,
      findings_by_severity: {
        critical: this.findings.filter(f => f.severity === 'critical').length,
        high: this.findings.filter(f => f.severity === 'high').length,
        medium: this.findings.filter(f => f.severity === 'medium').length,
        low: this.findings.filter(f => f.severity === 'low').length
      },
      findings: this.findings.sort((a, b) => {
        const severityDiff = SEVERITY_LEVELS[b.severity] - SEVERITY_LEVELS[a.severity];
        if (severityDiff !== 0) return severityDiff;
        return a.file.localeCompare(b.file);
      })
    };

    const reportFile = path.join(process.cwd(), 'secrets-scan-report.json');
    fs.writeFileSync(reportFile, JSON.stringify(report, null, 2));
    
    return reportFile;
  }

  generateSARIF() {
    const sarif = {
      version: '2.1.0',
      '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      runs: [{
        tool: {
          driver: {
            name: 'Secrets Scanner',
            version: '1.0.0',
            informationUri: 'https://github.com/vercel-labs/agent-browser',
            rules: Object.entries({ ...SECRET_PATTERNS, ...this.customPatterns }).map(([id, config]) => ({
              id,
              name: config.description,
              shortDescription: { text: config.description },
              fullDescription: { text: `Detects ${config.description.toLowerCase()} in source code` },
              defaultConfiguration: { level: config.severity === 'critical' ? 'error' : 'warning' },
              properties: { tags: ['security', 'secrets'] }
            }))
          }
        },
        results: this.findings.map(finding => ({
          ruleId: finding.type,
          message: { text: `${finding.description} detected` },
          level: finding.severity === 'critical' ? 'error' : 'warning',
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: finding.file },
              region: {
                startLine: finding.line,
                startColumn: finding.column,
                snippet: { text: finding.context }
              }
            }
          }],
          properties: {
            severity: finding.severity,
            match: finding.match
          }
        }))
      }]
    };

    const sarifFile = path.join(process.cwd(), 'secrets-scan-results.sarif');
    fs.writeFileSync(sarifFile, JSON.stringify(sarif, null, 2));
    
    return sarifFile;
  }

  async commentOnPR(token) {
    if (github.context.eventName !== 'pull_request' || this.findings.length === 0) {
      return;
    }

    const octokit = github.getOctokit(token);
    
    const criticalFindings = this.findings.filter(f => f.severity === 'critical');
    const highFindings = this.findings.filter(f => f.severity === 'high');
    const otherFindings = this.findings.filter(f => !['critical', 'high'].includes(f.severity));

    let comment = '## 🔍 Secrets Scanner Results\n\n';
    
    if (criticalFindings.length > 0) {
      comment += '### ❌ Critical Issues\n';
      criticalFindings.slice(0, 5).forEach(finding => {
        comment += `- **${finding.description}** in \`${finding.file}:${finding.line}\`\n`;
      });
      if (criticalFindings.length > 5) {
        comment += `- ... and ${criticalFindings.length - 5} more critical issues\n`;
      }
      comment += '\n';
    }

    if (highFindings.length > 0) {
      comment += '### ⚠️ High Severity Issues\n';
      highFindings.slice(0, 3).forEach(finding => {
        comment += `- **${finding.description}** in \`${finding.file}:${finding.line}\`\n`;
      });
      if (highFindings.length > 3) {
        comment += `- ... and ${highFindings.length - 3} more high severity issues\n`;
      }
      comment += '\n';
    }

    if (otherFindings.length > 0) {
      comment += `### ℹ️ Other Issues: ${otherFindings.length}\n\n`;
    }

    comment += '### 🛡️ Remediation\n';
    comment += '1. **Remove or rotate** any exposed secrets immediately\n';
    comment += '2. Use environment variables or secure secret management\n';
    comment += '3. Add sensitive files to `.gitignore`\n';
    comment += '4. Consider using [git-secrets](https://github.com/awslabs/git-secrets) for prevention\n\n';
    comment += `📄 **Full report**: Check the Actions tab for detailed results\n`;
    comment += `🔍 **Files scanned**: ${this.scannedFiles}`;

    try {
      await octokit.rest.issues.createComment({
        owner: github.context.repo.owner,
        repo: github.context.repo.repo,
        issue_number: github.context.payload.pull_request.number,
        body: comment
      });
      core.info('Posted comment on PR with scan results');
    } catch (error) {
      core.warning(`Failed to comment on PR: ${error.message}`);
    }
  }
}

async function run() {
  try {
    const scanner = new SecretsScanner();
    scanner.initialize();

    // Get inputs
    const token = core.getInput('github-token', { required: true });
    const scanPath = core.getInput('scan-path') || '.';
    const failOnDetection = core.getInput('fail-on-detection') === 'true';
    const commentPR = core.getInput('comment-pr') === 'true';

    // Validate scan path
    const fullScanPath = path.resolve(scanPath);
    if (!fs.existsSync(fullScanPath)) {
      throw new Error(`Scan path does not exist: ${scanPath}`);
    }

    core.info(`Starting secrets scan on: ${fullScanPath}`);
    
    // Perform the scan
    if (fs.statSync(fullScanPath).isDirectory()) {
      scanner.scanDirectory(fullScanPath);
    } else {
      scanner.scanFile(fullScanPath);
    }

    core.info(`Scan completed. Files scanned: ${scanner.scannedFiles}`);
    core.info(`Total findings: ${scanner.findings.length}`);

    // Generate reports
    const reportFile = scanner.generateReport();
    const sarifFile = scanner.generateSARIF();

    core.info(`Reports generated:`);
    core.info(`- JSON report: ${reportFile}`);
    core.info(`- SARIF report: ${sarifFile}`);

    // Set outputs
    core.setOutput('secrets-found', scanner.findings.length.toString());
    core.setOutput('report-file', reportFile);
    core.setOutput('sarif-file', sarifFile);
    core.setOutput('has-secrets', (scanner.findings.length > 0).toString());

    // Comment on PR if enabled
    if (commentPR) {
      await scanner.commentOnPR(token);
    }

    // Log findings summary
    if (scanner.findings.length > 0) {
      core.startGroup('Findings Summary');
      const bySeverity = {
        critical: scanner.findings.filter(f => f.severity === 'critical').length,
        high: scanner.findings.filter(f => f.severity === 'high').length,
        medium: scanner.findings.filter(f => f.severity === 'medium').length,
        low: scanner.findings.filter(f => f.severity === 'low').length
      };
      
      Object.entries(bySeverity).forEach(([severity, count]) => {
        if (count > 0) {
          core.info(`${severity.toUpperCase()}: ${count}`);
        }
      });
      
      // Show first few findings
      scanner.findings.slice(0, 5).forEach(finding => {
        core.warning(`${finding.severity.toUpperCase()}: ${finding.description} in ${finding.file}:${finding.line}`);
      });
      
      if (scanner.findings.length > 5) {
        core.info(`... and ${scanner.findings.length - 5} more findings in the reports`);
      }
      core.endGroup();
      
      if (failOnDetection) {
        throw new Error(`Secrets detected! Found ${scanner.findings.length} potential secrets. Check the reports for details.`);
      }
    } else {
      core.info('✅ No secrets detected!');
    }

  } catch (error) {
    core.setFailed(error.message);
  }
}

run();