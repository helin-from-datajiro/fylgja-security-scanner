# FYLGJA Security Scanner

**Real-time security vulnerability scanner and auto-fixer for VS Code.**

Detects **SQL Injection**, **XSS**, **Command Injection**, **Hardcoded Secrets**, **Weak Cryptography**, and **Path Traversal** vulnerabilities in your code — and fixes them with one click.

## Features

- 🔍 **6 vulnerability categories** with 50+ detection patterns
- ⚡ **Auto-scan on save** — vulnerabilities appear instantly as you code
- 🔧 **One-click fix** — lightbulb menu with intelligent auto-fix
- 📊 **Status bar integration** — live issue count
- 🌍 **Multi-language** — Python, JavaScript, TypeScript, PHP, Java

## Supported Vulnerability Types

| Type | Severity | Auto-Fix |
|---|---|---|
| SQL Injection | CRITICAL | ✅ Parameterized queries |
| Command Injection | CRITICAL | ✅ Safe subprocess/execFile |
| Hardcoded Secret | HIGH | ✅ Environment variables |
| Weak Cryptography | HIGH | ✅ SHA-256 replacement |
| XSS | HIGH | ⚠️ Security comment |
| Path Traversal | HIGH | ⚠️ Security comment |

## How to Use

### Quick Start
1. Open any supported file (`.py`, `.js`, `.ts`, `.php`, `.java`)
2. Vulnerabilities appear automatically with underlines
3. Hover for details, click lightbulb for fixes

### Commands
- `FYLGJA: Scan Current File` — scan the active file
- `FYLGJA: Scan Entire Workspace` — scan all files in workspace
- `FYLGJA: Fix All Vulnerabilities` — batch fix current file

### Settings
| Setting | Default | Description |
|---|---|---|
| `fylgja.scanOnSave` | `true` | Auto-scan when files are saved |
| `fylgja.scanOnOpen` | `true` | Auto-scan when files are opened |
| `fylgja.severityThreshold` | `MEDIUM` | Minimum severity to display |

## Development

```bash
# Install dependencies
npm install

# Compile
npm run compile

# Watch mode
npm run watch

# Test in VS Code
# Press F5 in VS Code to launch Extension Development Host
```

## Testing

Open the files in `test-files/` to see the scanner in action:
- `vulnerable-sample.py` — Python vulnerabilities (all 6 categories)
- `vulnerable-sample.js` — JavaScript vulnerabilities (XSS, exec, SQL injection)

## License

MIT
