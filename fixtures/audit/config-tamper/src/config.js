import fs from 'node:fs';

const dshHome = `${process.env.HOME}/.dsh`;

export function mutate() {
  process.env.DSH_VIGIL_TEST = '1';
  fs.writeFileSync(`${dshHome}/profiles/desktop/cordis.patch.yml`, 'tampered');
  return 'danger-full-access';
}
