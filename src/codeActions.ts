/**
 * FYLGJA Code Action Provider
 * Provides "Quick Fix" options in the lightbulb menu.
 * 
 * When the cursor is on a vulnerability line:
 * - "FYLGJA: Fix [vuln_type]" → applies the auto-fix
 * - "FYLGJA: Fix All in File" → fixes every vulnerability in the file
 */

import * as vscode from 'vscode';
import { Vulnerability } from './scanner';
import { canAutoFix, createFix } from './fixer';
import { getLastScanResults } from './diagnostics';

export class FylgjaCodeActionProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix,
    ];

    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];
        const vulns = getLastScanResults(document.uri.toString());

        if (!vulns.length) { return actions; }

        // Find vulnerabilities on the current line(s)
        for (const vuln of vulns) {
            const vulnLine = vuln.lineNumber - 1;
            if (vulnLine >= range.start.line && vulnLine <= range.end.line) {
                const fixType = canAutoFix(vuln.vulnType) ? 'Fix' : 'Add Safety Comment for';
                const action = new vscode.CodeAction(
                    `FYLGJA: ${fixType} ${vuln.vulnType}`,
                    vscode.CodeActionKind.QuickFix
                );

                const edit = createFix(document, vuln);
                if (edit) {
                    action.edit = edit;
                    action.isPreferred = true;
                    action.diagnostics = this.getRelatedDiagnostics(document, vuln);
                    actions.push(action);
                }
            }
        }

        // If there are multiple vulnerabilities in the file, offer "Fix All"
        if (vulns.length > 1) {
            const fixAllAction = new vscode.CodeAction(
                `FYLGJA: Fix All Vulnerabilities (${vulns.length} issues)`,
                vscode.CodeActionKind.QuickFix
            );
            fixAllAction.command = {
                command: 'fylgja.fixAll',
                title: 'Fix All Vulnerabilities',
            };
            actions.push(fixAllAction);
        }

        return actions;
    }

    private getRelatedDiagnostics(document: vscode.TextDocument, vuln: Vulnerability): vscode.Diagnostic[] {
        const allDiagnostics = vscode.languages.getDiagnostics(document.uri);
        return allDiagnostics.filter(d =>
            d.source === 'FYLGJA' &&
            d.range.start.line === vuln.lineNumber - 1
        );
    }
}
