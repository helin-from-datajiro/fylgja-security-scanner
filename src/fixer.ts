/**
 * FYLGJA Auto-Fixer Engine
 * Ported from Python fixer.py → TypeScript
 * 
 * Auto-fix support:
 * - Hardcoded Secret    → process.env / os.getenv()
 * - Weak Cryptography   → sha256 replacement
 * - Command Injection   → subprocess.run([], shell=False) / execFile()
 * - SQL Injection       → parameterized queries
 * - XSS / Path Traversal → security review comment + FYLGJA-FIXED tag
 */

import * as vscode from 'vscode';
import { Vulnerability } from './scanner';

const AUTO_FIX_SUPPORTED = new Set([
    'Hardcoded Secret',
    'Weak Cryptography',
    'Command Injection',
    'SQL Injection',
]);

export function canAutoFix(vulnType: string): boolean {
    return AUTO_FIX_SUPPORTED.has(vulnType);
}

/**
 * Create a WorkspaceEdit that fixes the given vulnerability.
 */
export function createFix(document: vscode.TextDocument, vuln: Vulnerability): vscode.WorkspaceEdit | null {
    const lineIdx = vuln.lineNumber - 1;
    if (lineIdx < 0 || lineIdx >= document.lineCount) { return null; }

    const line = document.lineAt(lineIdx);
    const originalText = line.text;

    // Already fixed?
    if (originalText.includes('FYLGJA-FIXED') || originalText.includes('FYLGJA-FIX:')) {
        return null;
    }

    let fixedText: string;

    switch (vuln.vulnType) {
        case 'Hardcoded Secret':
            fixedText = fixHardcodedSecret(originalText);
            break;
        case 'Weak Cryptography':
            fixedText = fixWeakCrypto(originalText);
            break;
        case 'Command Injection':
            fixedText = fixCommandInjection(originalText);
            break;
        case 'SQL Injection':
            fixedText = fixSqlInjection(originalText);
            break;
        default:
            fixedText = addReviewComment(originalText, vuln.vulnType);
            break;
    }

    if (fixedText === originalText) {
        // Couldn't transform — add a safety comment
        fixedText = addReviewComment(originalText, vuln.vulnType);
    }

    // Ensure FYLGJA-FIXED tag
    if (!fixedText.includes('FYLGJA-FIXED')) {
        fixedText = addFixedTag(fixedText);
    }

    const edit = new vscode.WorkspaceEdit();

    if (fixedText.includes('\n')) {
        // Multi-line fix (e.g., review comment above the line)
        const range = new vscode.Range(line.range.start, line.range.end);
        edit.replace(document.uri, range, fixedText);
    } else {
        edit.replace(document.uri, line.range, fixedText);
    }

    return edit;
}

// ─── Individual Fix Functions ───────────────────────────────────────

function fixHardcodedSecret(line: string): string {
    // Python: PASSWORD = "secret123"  →  PASSWORD = os.getenv("PASSWORD", "")
    const pyMatch = line.match(/^(\s*)([\w_]+)\s*=\s*(["'])([^"']{4,})\3(.*)/);
    if (pyMatch) {
        const [, indent, varName, , , rest] = pyMatch;
        const envName = varName.toUpperCase();
        const tail = rest.trim();
        return `${indent}${varName} = os.getenv("${envName}", "")${tail ? '  # ' + tail : ''}`;
    }

    // JavaScript: const apiKey = "sk-abc123"  →  const apiKey = process.env.API_KEY || ""
    const jsMatch = line.match(/^(\s*)(const|let|var)\s+([\w_]+)\s*=\s*(["'])([^"']{4,})\4(.*)/);
    if (jsMatch) {
        const [, indent, keyword, varName, , , rest] = jsMatch;
        const envName = varName.replace(/([A-Z])/g, '_$1').toUpperCase().replace(/^_/, '');
        const tail = rest.trim();
        return `${indent}${keyword} ${varName} = process.env.${envName} || ""${tail ? '  // ' + tail : ''}`;
    }

    return line;
}

function fixWeakCrypto(line: string): string {
    let fixed = line;
    // Python
    fixed = fixed.replace(/hashlib\.md5\s*\(/gi, 'hashlib.sha256(');
    fixed = fixed.replace(/hashlib\.sha1\s*\(/gi, 'hashlib.sha256(');
    fixed = fixed.replace(/\bMD5\s*\(/g, 'SHA256(');
    // JavaScript
    fixed = fixed.replace(/createHash\s*\(\s*["']md5["']\s*\)/gi, 'createHash("sha256")');
    fixed = fixed.replace(/createHash\s*\(\s*["']sha1["']\s*\)/gi, 'createHash("sha256")');
    // Math.random → crypto
    fixed = fixed.replace(/Math\.random\s*\(\)/g, 'crypto.randomBytes(16).toString("hex")');
    return fixed;
}

function fixCommandInjection(line: string): string {
    // Python: os.system(cmd) → subprocess.run([cmd], shell=False)
    const osSystemMatch = line.match(/^(\s*)os\.system\s*\((.+)\)(.*)/);
    if (osSystemMatch) {
        const [, indent, expr, tail] = osSystemMatch;
        return `${indent}subprocess.run([${expr.trim()}], shell=False)${tail}`;
    }

    // Python: subprocess.run("cmd", shell=True) → subprocess.run(["cmd"], shell=False)
    const subprocessMatch = line.match(/^(\s*)(subprocess\.(?:run|call|Popen))\s*\((.+),\s*shell\s*=\s*True(.*)\)(.*)/);
    if (subprocessMatch) {
        const [, indent, func, args, extra, tail] = subprocessMatch;
        const argClean = args.trim();
        return `${indent}${func}([${argClean}], shell=False${extra})${tail}`;
    }

    // Node.js: child_process.exec(cmd) → child_process.execFile(cmd)
    const execMatch = line.match(/^(\s*)(child_process\.exec)\s*\((.+)\)(.*)/);
    if (execMatch) {
        const [, indent, , args, tail] = execMatch;
        return `${indent}child_process.execFile(${args})${tail}`;
    }

    return line;
}

function fixSqlInjection(line: string): string {
    // f-string: cursor.execute(f"SELECT ... {var}") → cursor.execute("SELECT ... ?", (var,))
    const fstringMatch = line.match(/^(\s*\w+(?:\.\w+)*\s*\.\s*execute\s*\(\s*)f(["'])(.*?)\2(\s*\).*)/);
    if (fstringMatch) {
        const [, prefix, , fstring, suffix] = fstringMatch;
        const varsFound = [...fstring.matchAll(/\{([^}]+)\}/g)].map(m => m[1]);
        if (varsFound.length > 0) {
            const plainSql = fstring.replace(/\{[^}]+\}/g, '?');
            const params = varsFound.length === 1 ? `(${varsFound[0]},)` : `(${varsFound.join(', ')},)`;
            return `${prefix}"${plainSql}", ${params})`;
        }
    }

    // String concat: cursor.execute("SELECT ..." + var + "...")
    const concatMatch = line.match(/^(\s*\w+(?:\.\w+)*\s*\.\s*execute\s*\(\s*)(["'])(.*?)\2\s*\+\s*(.+)/);
    if (concatMatch) {
        const [, prefix, , sqlStart, rest] = concatMatch;
        const varMatch = rest.trim().match(/^(\w+)/);
        if (varMatch) {
            const varName = varMatch[1];
            const cleanSql = sqlStart.replace(/['"\s]+$/, '');
            return `${prefix}"${cleanSql} ?", (${varName},))`;
        }
    }

    // Node.js template literal: .query(`SELECT ... ${var}`)
    const templateMatch = line.match(/^(\s*\w+(?:\.\w+)*\s*\.\s*query\s*\(\s*)`([^`]*)\$\{([^}]+)\}([^`]*)`(.*)/);
    if (templateMatch) {
        const [, prefix, sqlBefore, varName, sqlAfter, tail] = templateMatch;
        return `${prefix}"${sqlBefore}?${sqlAfter}", [${varName}]${tail}`;
    }

    return line;
}

// ─── Helper Functions ───────────────────────────────────────────────

function addFixedTag(line: string): string {
    const stripped = line.trimEnd();
    if (stripped.includes('FYLGJA-FIXED')) { return line; }

    // Detect comment style based on content
    const isJs = line.includes('//') || line.includes('const ') || line.includes('let ') || line.includes('var ');
    const commentMarker = isJs ? '//' : '#';

    return `${stripped}  ${commentMarker} FYLGJA-FIXED`;
}

function addReviewComment(line: string, vulnType: string): string {
    const indent = line.match(/^(\s*)/)?.[1] || '';
    const isJs = line.includes('//') || line.includes('{') || line.includes('=>');
    const commentMarker = isJs ? '//' : '#';

    const suggestions: Record<string, string> = {
        'Cross-Site Scripting (XSS)': 'Use textContent instead of innerHTML, or sanitize with DOMPurify/html.escape()',
        'Path Traversal': 'Validate paths with path.resolve() and ensure they stay within allowed directories',
    };
    const suggestion = suggestions[vulnType] || 'Security review required';

    const commentLine = `${indent}${commentMarker} FYLGJA-FIX [${vulnType}]: ${suggestion}`;
    const taggedLine = addFixedTag(line);
    return `${commentLine}\n${taggedLine}`;
}
