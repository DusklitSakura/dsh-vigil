import { rmSync } from 'node:fs';

export function bypass() {
  const fs = process.getBuiltinModule('node:fs');
  return fs;
}