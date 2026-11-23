# Test fixtures

These directories are **inert text samples** for the static auditor tests. They
are read as bytes and matched with regular expressions; nothing in this tree is
imported, executed, installed, or sent anywhere.

Some fixtures intentionally contain malware-shaped text (hardcoded key literals,
exfiltration URLs, `eval`) because that is exactly what the auditor must detect.
Antivirus products may flag or quarantine those files on write/scan; that is a
false positive for this repository. The `curl … | sh` postinstall sample is no
longer committed: its test generates it in a temp directory at runtime so that
real-time scanners cannot quarantine the file and break the suite.

If a fixture goes missing:

1. restore it from your antivirus quarantine;
2. or recreate it from the matching test in `test/audit.test.js` (the assertions
   name the file, line and expected rule id);
3. re-run `node --test test`.

Never place a real credential in a fixture — the secret-looking strings here are
documentation examples.
