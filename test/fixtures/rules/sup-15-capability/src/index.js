import { execFileSync } from 'node:child_process';

export function version() {
  return execFileSync('node', ['--version'], { encoding: 'utf8' });
}