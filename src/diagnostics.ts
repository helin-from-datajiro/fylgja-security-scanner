/**
 * FYLGJA Diagnostics Provider
 * Maps scanner vulnerabilities → VS Code inline squigglies.
 * 
 * CRITICAL → Error (red underline)
 * HIGH     → Warning (yellow underline)
 * MEDIUM   → Information (blue underline)
 */

import * as vscode from 'vscode';
import { Vulnerability, scanFileContent, isSupportedFile } from './scanner';

let diagnosticCollection: vscode.DiagnosticCollection;
let lastScanResults: Map<string, Vulnerability[]> = new Map();

export function initDiagnostics(context: vscode.ExtensionContext): vscode.DiagnosticCollection {
    diagnosticCollection = vscode.languages.createDiagnosticCollection('fylgja');
    context.subscriptions.push(diagnosticCollection);
    return diagnosticCollection;
}

export function getDiagnosticCollection(): vscode.DiagnosticCollection {
    return diagnosticCollection;
}

export function getLastScanResults(uri: string): Vulnerability[] {
    return lastScanResults.get(uri) || [];
}

/**
 * Scan a single document and publish diagnostics.
 */
export function scanAndPublish(document: vscode.TextDocument): Vulnerability[] {
    if (!isSupportedFile(document.fileName)) {
        return [];
    }

    const content = document.getText();
    const vulns = scanFileContent(document.fileName, content);

    // Store results for code actions
    lastScanResults.set(document.uri.toString(), vulns);

    // Convert to VS Code diagnostics
    const diagnostics: vscode.Diagnostic[] = vulns.map(vuln => {
        const line = document.lineAt(vuln.lineNumber - 1);
        const range = new vscode.Range(
            vuln.lineNumber - 1, 0,
            vuln.lineNumber - 1, line.text.length
        );

        const severity = mapSeverity(vuln.severity);
        const diagnostic = new vscode.Diagnostic(range, vuln.description, severity);
        diagnostic.source = 'FYLGJA';
        diagnostic.code = vuln.vulnType;

        // Add fix suggestion to the message
        diagnostic.message = `[${vuln.severity}] ${vuln.vulnType}\n\n${vuln.description}\n\n💡 Fix: ${vuln.fix}`;

        return diagnostic;
    });

    diagnosticCollection.set(document.uri, diagnostics);
    return vulns;
}

/**
 * Clear diagnostics for a document.
 */
export function clearDiagnostics(uri: vscode.Uri): void {
    diagnosticCollection.delete(uri);
    lastScanResults.delete(uri.toString());
}

function mapSeverity(severity: string): vscode.DiagnosticSeverity {
    switch (severity) {
        case 'CRITICAL': return vscode.DiagnosticSeverity.Error;
        case 'HIGH': return vscode.DiagnosticSeverity.Warning;
        case 'MEDIUM': return vscode.DiagnosticSeverity.Information;
        default: return vscode.DiagnosticSeverity.Hint;
    }
}
