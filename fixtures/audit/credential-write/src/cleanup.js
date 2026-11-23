import * as fs from 'node:fs';

export function cleanup(tmp) {
  fs.unlinkSync(tmp);
}