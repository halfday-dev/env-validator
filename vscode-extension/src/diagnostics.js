const vscode = require('vscode');
const { analyze, computeScore } = require('./scanner');

let diagnosticCollection;

function createDiagnosticCollection() {
  diagnosticCollection = vscode.languages.createDiagnosticCollection('envValidator');
  return diagnosticCollection;
}

function severityToVscode(severity) {
  switch (severity) {
    case 'critical': return vscode.DiagnosticSeverity.Error;
    case 'warning': return vscode.DiagnosticSeverity.Warning;
    case 'info': return vscode.DiagnosticSeverity.Information;
    default: return vscode.DiagnosticSeverity.Warning;
  }
}

function updateDiagnostics(document) {
  if (!isEnvFile(document)) {
    return null;
  }

  const text = document.getText();
  const findings = analyze(text, document.uri.toString());
  const scoreResult = computeScore(findings);

  const diagnostics = findings.map(f => {
    const lineIndex = f.line - 1;
    const line = document.lineAt(lineIndex);
    const range = new vscode.Range(lineIndex, 0, lineIndex, line.text.length);
    const diag = new vscode.Diagnostic(range, `${f.name}: ${f.desc}`, severityToVscode(f.severity));
    diag.source = 'env-validator';
    diag.code = f.name;
    // Store fix info for quick fixes and hover
    diag.relatedInformation = [
      new vscode.DiagnosticRelatedInformation(
        new vscode.Location(document.uri, range),
        `Fix: ${f.fix}`
      )
    ];
    return diag;
  });

  diagnosticCollection.set(document.uri, diagnostics);
  return scoreResult;
}

function isEnvFile(document) {
  const fileName = document.fileName;
  const baseName = require('path').basename(fileName);
  return baseName === '.env' || baseName.startsWith('.env.');
}

function clearDiagnostics(uri) {
  diagnosticCollection.delete(uri);
}

module.exports = { createDiagnosticCollection, updateDiagnostics, clearDiagnostics, isEnvFile };
