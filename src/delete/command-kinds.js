/**
 * Canonical delete/move/truncate command names.
 *
 * `parser.js` classifies chunks by shell, `parser-posix.js` dispatches POSIX
 * delete commands and `sentinel/guard.js` decides which statements can destroy
 * the plugin directory. They previously kept independent lists, so a command
 * could be classified as POSIX yet missing from the POSIX dispatch table (the
 * `mv`/`ren` self-protection bypass). New names go here once.
 *
 * @module delete/command-kinds
 */

/** @type {ReadonlyMap<string, 'delete'|'move'|'truncate'>} */
export const COMMAND_KINDS = new Map([
  ['rm', 'delete'],
  ['rmdir', 'delete'],
  ['unlink', 'delete'],
  ['shred', 'delete'],
  ['find', 'delete'],
  ['xargs', 'delete'],
  ['git', 'delete'],
  ['rsync', 'delete'],
  ['del', 'delete'],
  ['erase', 'delete'],
  ['rd', 'delete'],
  ['mv', 'move'],
  ['move', 'move'],
  ['ren', 'move'],
  ['rename', 'move'],
  ['move-item', 'move'],
  ['rename-item', 'move'],
  ['clear-content', 'truncate'],
  ['set-content', 'truncate'],
  ['out-file', 'truncate'],
])

/** POSIX commands the POSIX parser dispatches (including `mv` for guard targets). */
export const POSIX_DELETE_COMMANDS = new Set(['rm', 'rmdir', 'unlink', 'shred', 'find', 'xargs', 'git', 'rsync', 'mv'])

/** Commands that move/rename rather than delete. */
export const MOVE_COMMANDS = new Set([...COMMAND_KINDS].filter(([, kind]) => kind === 'move').map(([name]) => name))

/** @param {string} name @returns {boolean} */
export function isMoveCommand(name) {
  return MOVE_COMMANDS.has(String(name || '').toLowerCase())
}
