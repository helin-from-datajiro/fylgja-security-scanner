/**
 * FYLGJA Security Scanner — VS Code Extension
 * 
 * Main entry point. Registers:
 * - Diagnostics provider (inline squigglies)
 * - Code action provider (lightbulb quick fixes)
 * - Commands (scan file, scan workspace, fix all)
 * - Status bar item
 * - Event listeners (on save, on open)
 */

import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { scanFileContent, isSupportedFile, SUPPORTED_EXTENSIONS, SKIP_DIRS } from './scanner';
import { createFix } from './fixer';
import { initDiagnostics, scanAndPublish, getLastScanResults, clearDiagnostics } from './diagnostics';
import { FylgjaCodeActionProvider } from './codeActions';
import { initStatusBar, updateStatusBar, setStatusBarScanning } from './statusBar';

export function activate(context: vscode.ExtensionContext) {
    console.log('FYLGJA Security Scanner is now active.');

    // Initialize diagnostics collection
    initDiagnostics(context);

    // Initialize status bar
    initStatusBar(context);

    // Register code action provider for all supported languages
    const supportedLanguages = [
        { scheme: 'file', language: 'python' },
        { scheme: 'file', language: 'javascript' },
        { scheme: 'file', language: 'typescript' },
        { scheme: 'file', language: 'javascriptreact' },
        { scheme: 'file', language: 'typescriptreact' },
        { scheme: 'file', language: 'php' },
        { scheme: 'file', language: 'java' },
    ];

    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            supportedLanguages,
            new FylgjaCodeActionProvider(),
            { providedCodeActionKinds: FylgjaCodeActionProvider.providedCodeActionKinds }
        )
    );

    // ─── Commands ───────────────────────────────────────────────────

    // Scan Current File
    context.subscriptions.push(
        vscode.commands.registerCommand('fylgja.scanFile', () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showInformationMessage('FYLGJA: No active file to scan.');
                return;
            }

            if (!isSupportedFile(editor.document.fileName)) {
                vscode.window.showInformationMessage(
                    `FYLGJA: File type not supported. Supported: ${SUPPORTED_EXTENSIONS.join(', ')}`
                );
                return;
            }

            setStatusBarScanning();
            const vulns = scanAndPublish(editor.document);
            updateStatusBar(vulns.length);

            if (vulns.length === 0) {
                vscode.window.showInformationMessage('🛡️ FYLGJA: No vulnerabilities found. Code is clean!');
            } else {
                const critCount = vulns.filter(v => v.severity === 'CRITICAL').length;
                const highCount = vulns.filter(v => v.severity === 'HIGH').length;
                vscode.window.showWarningMessage(
                    `🛡️ FYLGJA: Found ${vulns.length} vulnerabilities (${critCount} critical, ${highCount} high). Click on underlined lines for fixes.`
                );
            }
        })
    );

    // Scan Entire Workspace
    context.subscriptions.push(
        vscode.commands.registerCommand('fylgja.scanWorkspace', async () => {
            const workspaceFolders = vscode.workspace.workspaceFolders;
            if (!workspaceFolders) {
                vscode.window.showInformationMessage('FYLGJA: No workspace folder open.');
                return;
            }

            setStatusBarScanning();
            let totalVulns = 0;
            let totalFiles = 0;

            await vscode.window.withProgress(
                {
                    location: vscode.ProgressLocation.Notification,
                    title: 'FYLGJA: Scanning workspace...',
                    cancellable: true,
                },
                async (progress, token) => {
                    for (const folder of workspaceFolders) {
                        const result = await scanDirectoryRecursive(folder.uri.fsPath, progress, token);
                        totalVulns += result.vulns;
                        totalFiles += result.files;
                    }
                }
            );

            updateStatusBar(totalVulns);

            if (totalVulns === 0) {
                vscode.window.showInformationMessage(
                    `🛡️ FYLGJA: Scanned ${totalFiles} files. No vulnerabilities found!`
                );
            } else {
                vscode.window.showWarningMessage(
                    `🛡️ FYLGJA: Scanned ${totalFiles} files. Found ${totalVulns} vulnerabilities across the workspace.`
                );
            }
        })
    );

    // Fix All Vulnerabilities in Current File
    context.subscriptions.push(
        vscode.commands.registerCommand('fylgja.fixAll', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showInformationMessage('FYLGJA: No active file.');
                return;
            }

            const vulns = getLastScanResults(editor.document.uri.toString());
            if (!vulns.length) {
                vscode.window.showInformationMessage('FYLGJA: No vulnerabilities to fix.');
                return;
            }

            let fixCount = 0;
            // Fix from bottom to top to preserve line numbers
            const sortedVulns = [...vulns].sort((a, b) => b.lineNumber - a.lineNumber);

            for (const vuln of sortedVulns) {
                const edit = createFix(editor.document, vuln);
                if (edit) {
                    await vscode.workspace.applyEdit(edit);
                    fixCount++;
                }
            }

            vscode.window.showInformationMessage(
                `🛡️ FYLGJA: Fixed ${fixCount} of ${vulns.length} vulnerabilities.`
            );

            // Re-scan to update diagnostics
            setTimeout(() => {
                scanAndPublish(editor.document);
                const remaining = getLastScanResults(editor.document.uri.toString());
                updateStatusBar(remaining.length);
            }, 500);
        })
    );

    // ─── Auto-Scan Events ───────────────────────────────────────────

    const config = vscode.workspace.getConfiguration('fylgja');

    // Scan on save
    if (config.get('scanOnSave', true)) {
        context.subscriptions.push(
            vscode.workspace.onDidSaveTextDocument((document) => {
                if (isSupportedFile(document.fileName)) {
                    const vulns = scanAndPublish(document);
                    updateStatusBar(vulns.length);
                }
            })
        );
    }

    // Scan on open
    if (config.get('scanOnOpen', true)) {
        context.subscriptions.push(
            vscode.workspace.onDidOpenTextDocument((document) => {
                if (isSupportedFile(document.fileName)) {
                    const vulns = scanAndPublish(document);
                    updateStatusBar(vulns.length);
                }
            })
        );
    }

    // Clear diagnostics when a document is closed
    context.subscriptions.push(
        vscode.workspace.onDidCloseTextDocument((document) => {
            clearDiagnostics(document.uri);
        })
    );

    // Scan currently open editors on activation
    if (vscode.window.activeTextEditor) {
        const doc = vscode.window.activeTextEditor.document;
        if (isSupportedFile(doc.fileName)) {
            const vulns = scanAndPublish(doc);
            updateStatusBar(vulns.length);
        }
    }
}

// ─── Workspace Scanner ──────────────────────────────────────────────

async function scanDirectoryRecursive(
    dirPath: string,
    progress: vscode.Progress<{ message?: string; increment?: number }>,
    token: vscode.CancellationToken,
): Promise<{ vulns: number; files: number }> {
    let totalVulns = 0;
    let totalFiles = 0;

    try {
        const entries = fs.readdirSync(dirPath, { withFileTypes: true });

        for (const entry of entries) {
            if (token.isCancellationRequested) { break; }

            const fullPath = path.join(dirPath, entry.name);

            if (entry.isDirectory()) {
                if (SKIP_DIRS.has(entry.name)) { continue; }
                const sub = await scanDirectoryRecursive(fullPath, progress, token);
                totalVulns += sub.vulns;
                totalFiles += sub.files;
            } else if (entry.isFile() && isSupportedFile(entry.name)) {
                try {
                    const content = fs.readFileSync(fullPath, 'utf-8');
                    const vulns = scanFileContent(fullPath, content);
                    totalVulns += vulns.length;
                    totalFiles++;
                    progress.report({ message: `${totalFiles} files scanned... (${entry.name})` });

                    // Open the file as a text document to publish diagnostics
                    if (vulns.length > 0) {
                        const uri = vscode.Uri.file(fullPath);
                        const doc = await vscode.workspace.openTextDocument(uri);
                        scanAndPublish(doc);
                    }
                } catch {
                    // Skip files that can't be read
                }
            }
        }
    } catch {
        // Skip directories that can't be read
    }

    return { vulns: totalVulns, files: totalFiles };
}

export function deactivate() {
    console.log('FYLGJA Security Scanner deactivated.');
}
