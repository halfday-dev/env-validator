const vscode = require('vscode');
const { isEnvFile } = require('./diagnostics');
const { analyze } = require('./scanner');

function createHoverProvider() {
  return vscode.languages.registerHoverProvider(
    [{ pattern: '**/.env' }, { pattern: '**/.env.*' }],
    {
      provideHover(document, position) {
        if (!isEnvFile(document)) return null;

        const text = document.getText();
        const findings = analyze(text);
        const lineFindings = findings.filter(f => f.line === position.line + 1);

        if (lineFindings.length === 0) return null;

        const contents = new vscode.MarkdownString();
        contents.isTrusted = true;

        for (const f of lineFindings) {
          const icon = f.severity === 'critical' ? '🔴' : f.severity === 'warning' ? '🟡' : 'ℹ️';
          contents.appendMarkdown(`### ${icon} ${f.name}\n\n`);
          contents.appendMarkdown(`${f.desc}\n\n`);
          contents.appendMarkdown(`**Fix:** ${f.fix}\n\n`);
          contents.appendMarkdown(`---\n\n`);
        }

        contents.appendMarkdown(`*[Halfday .env Validator](https://halfday.dev)*`);

        return new vscode.Hover(contents);
      }
    }
  );
}

module.exports = { createHoverProvider };
