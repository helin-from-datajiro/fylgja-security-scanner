/**
 * FYLGJA Security Scanner Engine
 * Ported from Python scanner.py → TypeScript
 * 
 * Detects 6 vulnerability categories with 30+ regex patterns.
 * All detection is real — pattern-matched on actual source code lines.
 */

export interface Vulnerability {
    id: string;
    fileName: string;
    lineNumber: number;
    vulnType: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
    description: string;
    fix: string;
    codeSnippet: string;
    isFixed: boolean;
}

interface VulnPattern {
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
    vulnType: string;
    patterns: RegExp[];
    description: string;
    fix: string;
}

const PATTERNS: Record<string, VulnPattern> = {
    SQL_INJECTION: {
        severity: 'CRITICAL',
        vulnType: 'SQL Injection',
        patterns: [
            /execute\s*\(\s*["'].*?%s.*?["'].*?%/i,
            /execute\s*\(\s*["'].*?\{.*?\}.*?["'].*?\.format/i,
            /execute\s*\(\s*f["'].*?\{.*?\}.*?["']/i,
            /execute\s*\(\s*["'].*?\+/i,
            /(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE).*?\+.*?["']/i,
            /cursor\.execute\s*\(\s*["'].*?%.*?["'].*?%/i,
            /db\.execute\s*\(\s*f["']/i,
            /query\s*\(\s*["'].*?\+/i,
            /\.query\s*\(\s*`[^`]*\$\{/i,
        ],
        description: 'SQL query is built using user input via string concatenation or interpolation. This enables SQL Injection attacks.',
        fix: 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
    },
    PATH_TRAVERSAL: {
        severity: 'HIGH',
        vulnType: 'Path Traversal',
        patterns: [
            /open\s*\(\s*.*?request\./i,
            /open\s*\(\s*.*?input\(/i,
            /Path\s*\(\s*.*?request\./i,
            /os\.path\.join\s*\(.*?request\./i,
            /os\.path\.join\s*\(.*?input\(/i,
            /open\s*\(\s*.*?argv\[/i,
            /open\s*\(\s*.*?\.get\s*\(/i,
            /readFileSync\s*\(.*?req\./i,
            /readFile\s*\(.*?req\./i,
        ],
        description: 'User input is used in a file path without validation. This allows Path Traversal attacks to read arbitrary files.',
        fix: 'Validate paths with os.path.abspath() and ensure they stay within allowed directories.',
    },
    XSS: {
        severity: 'HIGH',
        vulnType: 'Cross-Site Scripting (XSS)',
        patterns: [
            /mark_safe\s*\(/i,
            /\.write\s*\(.*?\+.*?["']</i,
            /innerHTML\s*=.*?\+/i,
            /document\.write\s*\(/i,
            /\.html\s*\(.*?\+/i,
            /Markup\s*\(/i,
            /dangerouslySetInnerHTML/i,
            /v-html\s*=/i,
            /\[innerHTML\]\s*=/i,
        ],
        description: 'User input is rendered into HTML without sanitization. This enables Cross-Site Scripting (XSS) attacks.',
        fix: 'Use html.escape(), textContent instead of innerHTML, or enable template auto-escaping.',
    },
    HARDCODED_SECRET: {
        severity: 'HIGH',
        vulnType: 'Hardcoded Secret',
        patterns: [
            /password\s*=\s*["'][^"']{4,}["']/i,
            /secret_key\s*=\s*["'][^"']{4,}["']/i,
            /api_key\s*=\s*["'][^"']{4,}["']/i,
            /SECRET\s*=\s*["'][^"']{4,}["']/i,
            /TOKEN\s*=\s*["'][^"']{4,}["']/i,
            /AWS_SECRET/i,
            /PRIVATE_KEY\s*=\s*["']/i,
            /apiKey\s*[:=]\s*["'][^"']{8,}["']/i,
            /connectionString\s*=\s*["'][^"']{10,}["']/i,
        ],
        description: 'Sensitive information (password, API key, token) is hardcoded in source code.',
        fix: 'Use environment variables: os.getenv("SECRET_KEY") or process.env.SECRET_KEY. Store secrets in .env files.',
    },
    COMMAND_INJECTION: {
        severity: 'CRITICAL',
        vulnType: 'Command Injection',
        patterns: [
            /os\.system\s*\(/i,
            /subprocess\.(call|run|Popen)\s*\(.*?shell\s*=\s*True/i,
            /eval\s*\(.*?(input|request|req\.|argv)/i,
            /exec\s*\(.*?request\./i,
            /__import__\s*\(.*?input\(/i,
            /child_process\.exec\s*\(/i,
            /child_process\.execSync\s*\(/i,
        ],
        description: 'User input is passed directly into a system command. This enables Command Injection attacks.',
        fix: 'Never use shell=True. Use subprocess.run() with list arguments: ["ls", "-la"]. For Node.js, use execFile() instead of exec().',
    },
    WEAK_CRYPTO: {
        severity: 'HIGH',
        vulnType: 'Weak Cryptography',
        patterns: [
            /hashlib\.md5\s*\(/i,
            /hashlib\.sha1\s*\(/i,
            /import\s+md5/i,
            /MD5\s*\(/i,
            /DES\.new\s*\(/i,
            /AES\.MODE_ECB/i,
            /createHash\s*\(\s*["']md5["']\s*\)/i,
            /createHash\s*\(\s*["']sha1["']\s*\)/i,
            /random\.random\s*\(\)/i,
            /Math\.random\s*\(\)/i,
        ],
        description: 'Insecure cryptographic algorithm detected (MD5/SHA1/DES/ECB/Math.random). These are vulnerable to collision and brute-force attacks.',
        fix: 'Use AES-256-GCM for encryption, bcrypt/argon2 for password hashing, and crypto.randomBytes() for secure randomness.',
    },
};

/**
 * Scan a single file's content and return found vulnerabilities.
 */
export function scanFileContent(fileName: string, content: string): Vulnerability[] {
    const results: Vulnerability[] = [];
    const lines = content.split('\n');
    const reported = new Set<string>();

    for (const [vulnId, vulnInfo] of Object.entries(PATTERNS)) {
        let matched = false;

        for (const pattern of vulnInfo.patterns) {
            if (matched) { break; }

            for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
                const line = lines[lineIdx];
                const lineNum = lineIdx + 1;
                const stripped = line.trim();

                // Skip empty lines
                if (!stripped) { continue; }

                // Skip comment lines
                if (stripped.startsWith('#') || stripped.startsWith('//') || stripped.startsWith('*') || stripped.startsWith('/*')) {
                    continue;
                }

                // Skip already-fixed lines
                if (line.includes('FYLGJA-FIXED') || line.includes('FYLGJA-FIX:')) {
                    continue;
                }

                // Skip lines inside string literals that happen to match (e.g., error messages)
                // Simple heuristic: if the line is a pure string assignment for a description, skip
                if (/^\s*(description|message|help|error|warning|info)\s*[:=]/i.test(stripped)) {
                    continue;
                }

                if (pattern.test(line)) {
                    const key = `${lineNum}:${vulnId}`;
                    if (reported.has(key)) { continue; }
                    reported.add(key);

                    results.push({
                        id: `${vulnId}_${lineNum}`,
                        fileName,
                        lineNumber: lineNum,
                        vulnType: vulnInfo.vulnType,
                        severity: vulnInfo.severity,
                        description: vulnInfo.description,
                        fix: vulnInfo.fix,
                        codeSnippet: stripped.substring(0, 120),
                        isFixed: false,
                    });

                    matched = true;
                    break;
                }
            }
        }
    }

    return results;
}

/**
 * Supported file extensions for scanning.
 */
export const SUPPORTED_EXTENSIONS = ['.py', '.js', '.ts', '.jsx', '.tsx', '.php', '.java'];

/**
 * Check if a file should be scanned based on its extension.
 */
export function isSupportedFile(fileName: string): boolean {
    const lower = fileName.toLowerCase();
    return SUPPORTED_EXTENSIONS.some(ext => lower.endsWith(ext));
}

/**
 * Directories to skip during workspace scanning.
 */
export const SKIP_DIRS = new Set([
    'node_modules', '.git', '__pycache__', '.venv', 'venv',
    'env', 'dist', 'build', '.dart_tool', '.pub-cache',
    'out', '.next', 'coverage', '.nyc_output',
]);
