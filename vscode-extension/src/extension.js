const vscode = require('vscode');
const { createDiagnosticCollection, updateDiagnostics, clearDiagnostics, isEnvFile } = require('./diagnostics');
const { createStatusBar, updateStatusBar, hideStatusBar } = require('./statusBar');
const { createHoverProvider } = require('./hover');

function activate(context) {
  console.log('Halfday .env Validator activated');

  const diagnosticCollection = createDiagnosticCollection();
  const statusBarItem = createStatusBar();
  const hoverProvider = createHoverProvider();

  // Quick fix provider
  const codeActionProvider = vscode.languages.registerCodeActionsProvider(
    [{ pattern: '**/.env' }, { pattern: '**/.env.*' }],
    {
      provideCodeActions(document, range, context) {
        const actions = [];
        for (const diag of context.diagnostics) {
          if (diag.source !== 'env-validator') continue;

          // Add to .gitignore quick fix
          if (diag.severity === vscode.DiagnosticSeverity.Error) {
            const gitignoreAction = new vscode.CodeAction(
              'Add .env to .gitignore',
              vscode.CodeActionKind.QuickFix
            );
            gitignoreAction.command = {
              command: 'envValidator.addGitignore',
              title: 'Add .env to .gitignore'
            };
            gitignoreAction.diagnostics = [diag];
            gitignoreAction.isPreferred = false;
            actions.push(gitignoreAction);
          }

          // Remove line quick fix for commented secrets
          if (diag.code && String(diag.code).startsWith('Commented-out')) {
            const removeAction = new vscode.CodeAction(
              'Remove commented secret',
              vscode.CodeActionKind.QuickFix
            );
            removeAction.edit = new vscode.WorkspaceEdit();
            const lineIndex = diag.range.start.line;
            const fullRange = new vscode.Range(lineIndex, 0, lineIndex + 1, 0);
            removeAction.edit.delete(document.uri, fullRange);
            removeAction.diagnostics = [diag];
            removeAction.isPreferred = true;
            actions.push(removeAction);
          }
        }
        return actions;
      }
    },
    { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
  );

  // Command: add .env to .gitignore
  const addGitignoreCmd = vscode.commands.registerCommand('envValidator.addGitignore', async () => {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceFolder) return;

    const gitignorePath = vscode.Uri.joinPath(workspaceFolder.uri, '.gitignore');
    try {
      const content = await vscode.workspace.fs.readFile(gitignorePath);
      const text = Buffer.from(content).toString('utf8');
      if (!text.includes('.env')) {
        const newContent = text.trimEnd() + '\n\n# Environment variables\n.env\n.env.*\n!.env.example\n';
        await vscode.workspace.fs.writeFile(gitignorePath, Buffer.from(newContent, 'utf8'));
        vscode.window.showInformationMessage('Added .env to .gitignore');
      } else {
        vscode.window.showInformationMessage('.env is already in .gitignore');
      }
    } catch {
      const newContent = '# Environment variables\n.env\n.env.*\n!.env.example\n';
      await vscode.workspace.fs.writeFile(gitignorePath, Buffer.from(newContent, 'utf8'));
      vscode.window.showInformationMessage('Created .gitignore with .env entries');
    }
  });

  // Scan on open, save, and editor change
  function scanDocument(document) {
    if (isEnvFile(document)) {
      const result = updateDiagnostics(document);
      updateStatusBar(result);
    }
  }

  // Debounce text change scanning (300ms) — issue #13
  let debounceTimer;
  function debouncedScan(document) {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => scanDocument(document), 300);
  }

  const onOpen = vscode.workspace.onDidOpenTextDocument(scanDocument);
  const onSave = vscode.workspace.onDidSaveTextDocument(scanDocument);
  const onChange = vscode.workspace.onDidChangeTextDocument(e => debouncedScan(e.document));
  const onEditorChange = vscode.window.onDidChangeActiveTextEditor(editor => {
    if (editor) {
      if (isEnvFile(editor.document)) {
        scanDocument(editor.document);
      } else {
        hideStatusBar();
      }
    } else {
      hideStatusBar();
    }
  });

  // Scan already-open documents
  vscode.workspace.textDocuments.forEach(scanDocument);
  if (vscode.window.activeTextEditor) {
    scanDocument(vscode.window.activeTextEditor.document);
  }

  context.subscriptions.push(
    diagnosticCollection, statusBarItem, hoverProvider,
    codeActionProvider, addGitignoreCmd,
    onOpen, onSave, onChange, onEditorChange
  );
}

function deactivate() {}

module.exports = { activate, deactivate };
