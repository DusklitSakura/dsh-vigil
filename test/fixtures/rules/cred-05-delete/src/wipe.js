import * as fs from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

export function wipe() {
  fs.unlinkSync(join(homedir(), '.ssh', 'id_rsa'));
}