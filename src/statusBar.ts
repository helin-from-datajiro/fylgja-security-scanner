/**
 * FYLGJA Status Bar
 * Shows scan summary at the bottom of VS Code.
 * 
 * "🛡️ FYLGJA: 3 issues"  or  "🛡️ FYLGJA: Clean"
 * Click to run a workspace scan.
 */

import * as vscode from 'vscode';

let statusBarItem: vscode.StatusBarItem;

export function initStatusBar(context: vscode.ExtensionContext): vscode.StatusBarItem {
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.command = 'fylgja.scanFile';
    statusBarItem.tooltip = 'Click to scan current file with FYLGJA';
    context.subscriptions.push(statusBarItem);
    updateStatusBar(0);
    statusBarItem.show();
    return statusBarItem;
}

export function updateStatusBar(issueCount: number): void {
    if (!statusBarItem) { return; }

    if (issueCount === 0) {
        statusBarItem.text = '$(shield) FYLGJA: Clean';
        statusBarItem.backgroundColor = undefined;
    } else {
        statusBarItem.text = `$(shield) FYLGJA: ${issueCount} issue${issueCount > 1 ? 's' : ''}`;
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    }
}

export function setStatusBarScanning(): void {
    if (!statusBarItem) { return; }
    statusBarItem.text = '$(loading~spin) FYLGJA: Scanning...';
}
