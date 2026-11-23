import leftPad from 'left-pad';
import { readFileSync } from 'node:fs';

export function pad(value) {
  return readFileSync(leftPad(String(value), 4));
}