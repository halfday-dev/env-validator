const vscode = require('vscode');

let statusBarItem;

function createStatusBar() {
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.command = undefined;
  statusBarItem.tooltip = 'Halfday .env Validator — Security Grade';
  return statusBarItem;
}

function updateStatusBar(scoreResult) {
  if (!scoreResult) {
    statusBarItem.hide();
    return;
  }

  const { grade, label, score } = scoreResult;
  const icon = grade === 'A' ? '$(shield)' : grade === 'F' ? '$(alert)' : '$(warning)';
  statusBarItem.text = `${icon} .env: ${grade} (${score}/100)`;
  statusBarItem.tooltip = `Halfday .env Validator\nGrade: ${grade} — ${label}\nScore: ${score}/100`;

  switch (grade) {
    case 'A': statusBarItem.backgroundColor = undefined; break;
    case 'B': statusBarItem.backgroundColor = undefined; break;
    case 'C': statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground'); break;
    case 'D':
    case 'F': statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground'); break;
  }

  statusBarItem.show();
}

function hideStatusBar() {
  if (statusBarItem) statusBarItem.hide();
}

module.exports = { createStatusBar, updateStatusBar, hideStatusBar };
