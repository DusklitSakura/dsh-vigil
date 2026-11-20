/**
 * Windows shell deletion-intent parser: PowerShell 5.1/7 + cmd.exe.
 *
 * Internal module used by `parser.js`. Pure string analysis only: no process
 * spawning, no filesystem access, no dependencies. It never throws; internal
 * failures degrade to an `unparsed` statement.
 *
 * The parser emits *partial statements* whose `rawTargets` are resolved to
 * absolute paths later by parser.js (shared expansion/root-classification).
 *
 * Masking convention (same as parser-posix): a `\u0001` sentinel protects a
 * literal character from later variable expansion (e.g. `` `$ `` or `'$x'`).
 *
 * @module delete/parser-pwsh
 */

/** Sentinel protecting literal characters from variable expansion. */
const ESC = '\u0001';

/** Hard cap on tokens per simple command. */
const MAX_TOKENS = 2048;

/** PowerShell aliases relevant to deletion / listing. */
const PWSH_ALIASES = new Map([
  ['rm', 'remove-item'],
  ['del', 'remove-item'],
  ['erase', 'remove-item'],
  ['rd', 'remove-item'],
  ['rmdir', 'remove-item'],
  ['ri', 'remove-item'],
  ['remove-item', 'remove-item'],
  ['gci', 'get-childitem'],
  ['ls', 'get-childitem'],
  ['dir', 'get-childitem'],
  ['get-childitem', 'get-childitem'],
  ['get-item', 'get-item'],
  ['gi', 'get-item'],
  ['gc', 'get-content'],
  ['cat', 'get-content'],
  ['type', 'get-content'],
  ['where', 'where-object'],
  ['where-object', 'where-object'],
  ['?', 'where-object'],
  ['%', 'foreach-object'],
  ['foreach', 'foreach-object'],
  ['foreach-object', 'foreach-object'],
  ['select', 'select-object'],
  ['select-object', 'select-object'],
  ['iex', 'invoke-expression'],
  ['invoke-expression', 'invoke-expression'],
  ['iwr', 'invoke-webrequest'],
  ['irm', 'invoke-restmethod'],
  ['cp', 'copy-item'],
  ['copy', 'copy-item'],
  ['mv', 'move-item'],
  ['move', 'move-item'],
  ['ni', 'new-item'],
  ['si', 'set-item'],
  ['sc', 'set-content'],
  ['ac', 'add-content'],
  ['clc', 'clear-content'],
  ['cli', 'clear-item'],
]);

/** Parameters of Remove-Item relevant to static deletion analysis. */
const REMOVE_ITEM_PARAMS = [
  'path',
  'literalpath',
  'filter',
  'include',
  'exclude',
  'recurse',
  'force',
  'whatif',
  'confirm',
  'verbose',
  'debug',
  'erroraction',
  'warningaction',
  'informationaction',
  'progressaction',
  'credential',
  'stream',
  'usetransaction',
  'passthru',
];

/** Short/ambiguous parameter spellings agents actually type. */
const REMOVE_ITEM_PARAM_ALIASES = Object.assign(Object.create(null), {
  p: 'path',
  pat: 'path',
  pa: 'path',
  lp: 'literalpath',
  l: 'literalpath',
  r: 'recurse',
  rec: 'recurse',
  f: 'force',
  fo: 'force',
  wi: 'whatif',
  w: 'whatif',
  c: 'confirm',
  cf: 'confirm',
  inc: 'include',
  i: 'include',
  exc: 'exclude',
  e: 'exclude',
  fi: 'filter',
  '': null,
});

/** Parameters that consume one following value when no `:` value is given. */
const PARAM_WITH_VALUE = new Set([
  'erroraction',
  'warningaction',
  'informationaction',
  'progressaction',
  'credential',
  'stream',
]);

/**
 * Decode masked text.
 * @param {string} value
 * @returns {string}
 */
function unmask(value) {
  return typeof value === 'string' && value.indexOf(ESC) >= 0 ? value.split(ESC).join('') : String(value || '');
}

/**
 * Lowercase basename of a command word.
 * @param {string} value
 * @returns {string}
 */
function baseName(value) {
  const text = unmask(value).trim().replace(/^&/, '').trim();
  const idx = Math.max(text.lastIndexOf('/'), text.lastIndexOf('\\'));
  return (idx >= 0 ? text.slice(idx + 1) : text).replace(/\.exe$/i, '').toLowerCase();
}

/**
 * Default object shape for a partial statement.
 * @param {object} fields
 * @returns {object}
 */
function makePartial(fields) {
  return Object.assign(
    {
      shell: 'pwsh',
      text: '',
      command: '',
      isDelete: false,
      dryRun: false,
      recursive: false,
      force: false,
      wildcard: false,
      deleteKind: 'none',
      unparsed: false,
      notes: [],
      risks: [],
      rawTargets: [],
    },
    fields,
  );
}

/**
 * Detect glob characters in a PowerShell argument (wildcards are expanded by
 * the cmdlet, quoted or not; `-LiteralPath` callers disable this).
 * @param {string} text
 * @returns {{hasGlob:boolean, globKind:string}}
 */
function psGlobFromText(text) {
  const value = String(text || '');
  const kinds = new Set();
  if (value.includes('*')) kinds.add('asterisk');
  if (value.includes('?')) kinds.add('question');
  if (/\[[^\]]*\]/.test(value)) kinds.add('bracket');
  if (kinds.size === 0) return { hasGlob: false, globKind: 'none' };
  if (kinds.size > 1) return { hasGlob: true, globKind: 'mixed' };
  return { hasGlob: true, globKind: kinds.values().next().value };
}

/**
 * Build a raw target from a PowerShell token.
 * @param {{value:string, hasGlob?:boolean, globKind?:string}} token
 * @param {boolean} literal `-LiteralPath` semantics: never a glob
 * @param {object} [extra]
 * @returns {object}
 */
function psTarget(token, literal, extra) {
  const glob = literal ? { hasGlob: false, globKind: 'none' } : { hasGlob: Boolean(token.hasGlob), globKind: token.globKind || 'none' };
  return Object.assign(
    {
      raw: unmask(token.value),
      text: token.value,
      hasGlob: glob.hasGlob,
      globKind: glob.globKind,
    },
    extra || {},
  );
}

/**
 * Build a raw target from an inline parameter value (`-Path:C:\x`).
 * @param {string} value masked value
 * @param {boolean} literal
 * @returns {object}
 */
function psTargetInline(value, literal) {
  const glob = literal ? { hasGlob: false, globKind: 'none' } : psGlobFromText(value);
  return { raw: unmask(value), text: value, hasGlob: glob.hasGlob, globKind: glob.globKind };
}

/** A synthetic `.` root token / target. */
function dotToken() {
  return { value: '.', text: '.', raw: '.', hasGlob: false, globKind: 'none' };
}

/**
 * Parse a PowerShell parameter word.
 * @param {string} value
 * @returns {{name:string, inline:string|undefined}|null}
 */
function parseParamName(value) {
  if (typeof value !== 'string' || value.length < 2 || value[0] !== '-' || value === '--%') return null;
  const match = /^-([A-Za-z][A-Za-z0-9_]*)(?::([\s\S]*))?$/.exec(value);
  if (!match) return null;
  return { name: match[1].toLowerCase(), inline: match[2] };
}

/**
 * Resolve a (possibly abbreviated) Remove-Item parameter name.
 * @param {string} name
 * @returns {string|null}
 */
function resolveDeleteParam(name) {
  if (name === '') return null;
  if (Object.prototype.hasOwnProperty.call(REMOVE_ITEM_PARAM_ALIASES, name)) {
    return REMOVE_ITEM_PARAM_ALIASES[name] || null;
  }
  const matches = REMOVE_ITEM_PARAMS.filter((param) => param.startsWith(name));
  if (matches.length === 1) return matches[0];
  if (matches.length > 1) {
    const exact = matches.find((param) => param === name);
    if (exact) return exact;
    // Prefer the first parameter in canonical order (path, literalpath, ...).
    return matches[0];
  }
  return null;
}

/**
 * Interpret a PowerShell boolean value / switch presence.
 * @param {string|undefined} inline
 * @returns {boolean}
 */
function booleanValue(inline) {
  if (inline === undefined) return true;
  const value = unmask(inline).trim().toLowerCase().replace(/^["']|["']$/g, '');
  if (value === 'false' || value === '$false' || value === '0' || value === 'no') return false;
  return true;
}

/**
 * Find the closing bracket matching `open`.
 * @param {string} src
 * @param {number} open
 * @param {string} openChar
 * @param {string} closeChar
 * @returns {number} index of the closing char, or `src.length`
 */
function findMatching(src, open, openChar, closeChar) {
  let depth = 0;
  let quote = null;
  for (let i = open; i < src.length; i += 1) {
    const c = src[i];
    if (quote === "'") {
      if (c === "'") {
        if (src[i + 1] === "'") {
          i += 1;
          continue;
        }
        quote = null;
      }
      continue;
    }
    if (quote === '"') {
      if (c === '`') {
        i += 1;
        continue;
      }
      if (c === '"') {
        if (src[i + 1] === '"') {
          i += 1;
          continue;
        }
        quote = null;
      }
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      continue;
    }
    if (c === openChar) depth += 1;
    else if (c === closeChar) {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return src.length;
}

/**
 * Split PowerShell arguments on top-level commas.
 * @param {string} src
 * @returns {string[]}
 */
function splitPwshArguments(src) {
  const parts = [];
  let start = 0;
  let quote = null;
  let depth = 0;
  for (let i = 0; i < src.length; i += 1) {
    const c = src[i];
    if (quote === "'") {
      if (c === "'") quote = null;
      continue;
    }
    if (quote === '"') {
      if (c === '`') i += 1;
      else if (c === '"') quote = null;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    else if (c === ',' && depth === 0) {
      parts.push(src.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(src.slice(start));
  return parts.map((part) => part.trim()).filter((part) => part.length > 0);
}

/**
 * Tokenize one PowerShell pipeline stage.
 *
 * Quotes, backtick escapes, `$(...)`, `@(...)`, script blocks `{...}` and
 * here-strings are kept inside a single token where appropriate.
 *
 * @param {string} src
 * @returns {Array<object>}
 */
function tokenizePwsh(src) {
  const tokens = [];
  const n = src.length;
  let i = 0;

  while (i < n && tokens.length < MAX_TOKENS) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n') {
      i += 1;
      continue;
    }
    if (c === '#' && (i === 0 || /\s/.test(src[i - 1]))) break;
    if (c === ';' || c === '|' || c === ',') {
      i += 1;
      continue;
    }
    if (c === '&' && src[i + 1] !== '&') {
      i += 1;
      continue;
    }
    // Redirection operators (`>`, `>>`, `2>&1`, `*>` ...).
    const redirect = /^(?:[0-9*])?(?:>>|>|<)(?:&[0-9]+)?/.exec(src.slice(i));
    if (redirect) {
      i += redirect[0].length;
      tokens.push({ op: true, value: redirect[0], raw: redirect[0] });
      continue;
    }
    // Here-strings @" ... "@ / @' ... '@
    if (c === '@' && (src[i + 1] === '"' || src[i + 1] === "'")) {
      const quoteChar = src[i + 1];
      const lineStart = /^\r?\n/.exec(src.slice(i + 2));
      if (lineStart) {
        const terminator = '\n' + quoteChar + '@';
        let end = src.indexOf(terminator, i + 2 + lineStart[0].length);
        let content;
        if (end < 0) {
          end = n;
          content = src.slice(i + 2 + lineStart[0].length);
        } else {
          content = src.slice(i + 2 + lineStart[0].length, end);
          end += terminator.length;
        }
        tokens.push({ value: content, raw: content, quoted: true, hasGlob: false, globKind: 'none' });
        i = Math.min(end, n);
        continue;
      }
    }

    const before = i;
    let value = '';
    let raw = '';
    let quote = null;
    let quotedAny = false;
    let hasSub = false;

    while (i < n) {
      const ch = src[i];
      if (quote === "'") {
        if (ch === "'") {
          if (src[i + 1] === "'") {
            value += "'";
            raw += "'";
            i += 2;
            continue;
          }
          quote = null;
          i += 1;
          continue;
        }
        if (ch === '$' || ch === '%') value += ESC + ch;
        else value += ch;
        raw += ch;
        i += 1;
        continue;
      }
      if (quote === '"') {
        if (ch === '"') {
          if (src[i + 1] === '"') {
            value += '"';
            raw += '"';
            i += 2;
            continue;
          }
          quote = null;
          i += 1;
          continue;
        }
        if (ch === '`') {
          const next = src[i + 1];
          if (next === undefined) {
            i += 1;
            continue;
          }
          if (next === '$' || next === '%' || next === '`') value += ESC + next;
          else if (next === 'n') value += '\n';
          else if (next === 't') value += '\t';
          else if (next === 'r') value += '\r';
          else if (next === '0') value += '\0';
          else value += next;
          raw += next;
          i += 2;
          continue;
        }
        if (ch === '$' && src[i + 1] === '(') {
          const end = findMatching(src, i + 1, '(', ')');
          const segment = src.slice(i, Math.min(end + 1, n));
          value += segment;
          raw += segment;
          hasSub = true;
          i = Math.min(end + 1, n);
          continue;
        }
        value += ch;
        raw += ch;
        i += 1;
        continue;
      }

      // Unquoted.
      if (ch === "'" || ch === '"') {
        quote = ch;
        quotedAny = true;
        i += 1;
        continue;
      }
      if (ch === '`') {
        const next = src[i + 1];
        if (next === undefined) {
          i += 1;
          continue;
        }
        if (next === '$' || next === '%' || next === '`') value += ESC + next;
        else if (next === 'n') value += '\n';
        else if (next === 't') value += '\t';
        else if (next === 'r') value += '\r';
        else if (next === '0') value += '\0';
        else value += next;
        raw += next;
        i += 2;
        continue;
      }
      if (ch === '$' && src[i + 1] === '(') {
        const end = findMatching(src, i + 1, '(', ')');
        const segment = src.slice(i, Math.min(end + 1, n));
        value += segment;
        raw += segment;
        hasSub = true;
        i = Math.min(end + 1, n);
        continue;
      }
      if (ch === '@' && src[i + 1] === '(') {
        const end = findMatching(src, i + 1, '(', ')');
        const segment = src.slice(i, Math.min(end + 1, n));
        value += segment;
        raw += segment;
        i = Math.min(end + 1, n);
        continue;
      }
      if (ch === '@' && src[i + 1] === '{') {
        const end = findMatching(src, i + 1, '{', '}');
        const segment = src.slice(i, Math.min(end + 1, n));
        value += segment;
        raw += segment;
        i = Math.min(end + 1, n);
        continue;
      }
      if (ch === '(' || ch === '{' || ch === '[') {
        const close = ch === '(' ? ')' : ch === '{' ? '}' : ']';
        const end = findMatching(src, i, ch, close);
        const segment = src.slice(i, Math.min(end + 1, n));
        value += segment;
        raw += segment;
        i = Math.min(end + 1, n);
        continue;
      }
      if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') break;
      if (ch === ';' || ch === '|' || ch === ',' || ch === '<' || ch === '>' || ch === '&') break;
      value += ch;
      raw += ch;
      i += 1;
    }

    if (value.length > 0 || raw.length > 0) {
      // PowerShell wildcard expansion applies to the resulting string value
      // regardless of quoting, so classify globs from the value itself.
      const glob = psGlobFromText(value);
      tokens.push({
        value,
        raw,
        quoted: quotedAny,
        hasSub,
        hasGlob: glob.hasGlob,
        globKind: glob.globKind,
      });
    }
    if (i === before) i += 1;
  }

  return tokens;
}

/**
 * Drop redirection operators and their targets from a token list.
 * @param {Array<object>} tokens
 * @returns {Array<object>}
 */
function stripRedirects(tokens) {
  const out = [];
  for (let i = 0; i < tokens.length; i += 1) {
    if (tokens[i].op) {
      if (i + 1 < tokens.length && !tokens[i + 1].op) i += 1;
      continue;
    }
    out.push(tokens[i]);
  }
  return out;
}

/**
 * Split a PowerShell chunk into pipeline stages at top-level `|`.
 * `|` inside quotes, `(...)`, `$(...)` or `{...}` is left untouched.
 * @param {string} src
 * @returns {string[]}
 */
function splitPwshPipeline(src) {
  const stages = [];
  const n = src.length;
  let start = 0;
  let i = 0;
  let quote = null;
  let depth = 0;
  while (i < n) {
    const c = src[i];
    if (quote === "'") {
      if (c === "'") quote = null;
      i += 1;
      continue;
    }
    if (quote === '"') {
      if (c === '`') {
        i += 2;
        continue;
      }
      if (c === '"') quote = null;
      i += 1;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      i += 1;
      continue;
    }
    if (c === '(' || c === '{') {
      depth += 1;
      i += 1;
      continue;
    }
    if (c === ')' || c === '}') {
      if (depth > 0) depth -= 1;
      i += 1;
      continue;
    }
    if (c === '|' && depth === 0) {
      stages.push(src.slice(start, i));
      i += 1;
      start = i;
      continue;
    }
    i += 1;
  }
  stages.push(src.slice(start));
  return stages.map((stage) => stage.trim()).filter((stage) => stage.length > 0);
}

/**
 * Mask quoted strings / comments so heuristic scans do not match text literals.
 * @param {string} src
 * @returns {string}
 */
function maskPwshStrings(src) {
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    if (c === "'") {
      out += ' ';
      i += 1;
      while (i < n) {
        if (src[i] === "'" && src[i + 1] === "'") {
          out += '  ';
          i += 2;
          continue;
        }
        out += src[i] === '\n' ? '\n' : ' ';
        if (src[i] === "'") {
          i += 1;
          break;
        }
        i += 1;
      }
      continue;
    }
    if (c === '"') {
      out += ' ';
      i += 1;
      while (i < n) {
        if (src[i] === '`') {
          out += '  ';
          i += 2;
          continue;
        }
        out += src[i] === '\n' ? '\n' : ' ';
        if (src[i] === '"') {
          i += 1;
          break;
        }
        i += 1;
      }
      continue;
    }
    if (c === '#') {
      while (i < n && src[i] !== '\n') {
        out += ' ';
        i += 1;
      }
      continue;
    }
    out += c;
    i += 1;
  }
  return out;
}

/**
 * Detect `[System.IO.File]::Delete(...)` / `[IO.Directory]::Delete(...,$true)`.
 * Returns a partial statement when the stage is (or contains) such a call.
 * @param {string} stageText
 * @returns {object|null}
 */
function detectDotNetDelete(stageText) {
  const match = /\[\s*(?:System\.)?([A-Za-z0-9_.]+)\s*\]\s*::\s*Delete\s*\(/i.exec(stageText);
  if (!match) return null;
  const className = match[1];
  const direct = /^\s*[\[(]/.test(stageText) && match.index <= stageText.length - stageText.trimStart().length + 2;
  if (!direct) {
    return makePartial({
      text: stageText.trim(),
      command: className.toLowerCase() + '::delete',
      isDelete: true,
      deleteKind: 'io-delete',
      unparsed: true,
      notes: ['在脚本块/嵌套表达式中检测到 .NET Delete 调用，目标无法静态解析'],
      risks: ['unknown-construct'],
    });
  }
  const open = match.index + match[0].length - 1;
  const close = findMatching(stageText, open, '(', ')');
  const argsText = stageText.slice(open + 1, close);
  const args = splitPwshArguments(argsText);
  const literalClass = className.toLowerCase();
  const rawTargets = [];
  const notes = [];
  const risks = [];
  if (args.length > 0 && args[0]) {
    const argTokens = tokenizePwsh(args[0]);
    if (argTokens.length > 0) {
      rawTargets.push(psTarget(argTokens[0], true, { note: '.NET API 删除目标' }));
    }
  }
  let recursive = false;
  if (literalClass.includes('directory')) {
    recursive = args.length > 1 ? booleanValue(args[1]) : false;
    if (recursive) notes.push('Directory.Delete(..., true) 递归删除目录');
  } else if (literalClass.includes('file')) {
    notes.push('File.Delete 删除单个文件');
  } else {
    notes.push('未知 .NET 类型的 Delete 调用（' + className + '）');
    risks.push('unknown-construct');
  }
  if (!rawTargets.length) {
    return makePartial({
      text: stageText.trim(),
      command: literalClass + '::delete',
      isDelete: true,
      recursive,
      deleteKind: 'io-delete',
      unparsed: true,
      notes: notes.concat('Delete 调用缺少可解析的目标参数'),
      risks: risks.concat('unknown-construct'),
    });
  }
  return makePartial({
    text: stageText.trim(),
    command: literalClass + '::delete',
    isDelete: true,
    recursive,
    deleteKind: 'io-delete',
    notes,
    risks,
    rawTargets,
  });
}

/**
 * Parse `Remove-Item` parameters / positional targets.
 * @param {Array<object>} args tokens after the command word
 * @param {string} text stage text
 * @returns {object} partial statement (may set `needsInput` when no target)
 */
function parseRemoveItem(args, text) {
  let recursive = false;
  let force = false;
  let dryRun = false;
  let wildcardFlag = false;
  const notes = [];
  const risks = [];
  const rawTargets = [];
  let i = 0;
  let verbatim = false;

  while (i < args.length) {
    const token = args[i];
    const value = token.value;
    if (verbatim) {
      rawTargets.push(psTarget(token, false));
      i += 1;
      continue;
    }
    if (value === '--%') {
      verbatim = true;
      i += 1;
      continue;
    }
    const param = parseParamName(value);
    if (!param) {
      if (value.startsWith('-') && value.length > 1) {
        notes.push('未识别的参数 ' + value);
        i += 1;
        continue;
      }
      rawTargets.push(psTarget(token, false));
      i += 1;
      continue;
    }
    const resolved = resolveDeleteParam(param.name);
    if (resolved === 'path' || resolved === 'literalpath') {
      const literal = resolved === 'literalpath';
      if (param.inline !== undefined) {
        rawTargets.push(psTargetInline(param.inline, literal));
        i += 1;
        continue;
      }
      i += 1;
      let consumed = false;
      while (i < args.length && !parseParamName(args[i].value) && args[i].value !== '--%') {
        rawTargets.push(psTarget(args[i], literal));
        i += 1;
        consumed = true;
      }
      if (!consumed) notes.push('-' + param.name + ' 缺少路径值');
      continue;
    }
    if (resolved === 'filter' || resolved === 'include' || resolved === 'exclude') {
      let pattern = param.inline;
      if (pattern === undefined && i + 1 < args.length && !parseParamName(args[i + 1].value)) {
        pattern = args[i + 1].value;
        i += 1;
      }
      if (typeof pattern === 'string') {
        const glob = psGlobFromText(pattern);
        if (resolved === 'include') {
          recursive = true;
          notes.push('-Include 隐含 -Recurse');
        }
        if (glob.hasGlob) {
          wildcardFlag = true;
          notes.push('-' + param.name + ' 使用通配符模式：' + unmask(pattern));
        }
      }
      i += 1;
      continue;
    }
    if (resolved === 'recurse') {
      recursive = booleanValue(param.inline);
      i += 1;
      continue;
    }
    if (resolved === 'force') {
      force = booleanValue(param.inline);
      i += 1;
      continue;
    }
    if (resolved === 'whatif') {
      dryRun = booleanValue(param.inline);
      i += 1;
      continue;
    }
    if (resolved === 'confirm') {
      if (param.inline !== undefined && booleanValue(param.inline) === false) {
        notes.push('-Confirm:$false 已禁用确认');
      }
      i += 1;
      continue;
    }
    if (resolved && PARAM_WITH_VALUE.has(resolved) && param.inline === undefined && i + 1 < args.length && !parseParamName(args[i + 1].value)) {
      i += 1; // skip the parameter value
    }
    i += 1;
  }

  const partial = makePartial({
    text,
    command: 'remove-item',
    isDelete: true,
    dryRun,
    recursive,
    force,
    wildcard: wildcardFlag,
    deleteKind: 'remove-item',
    notes,
    risks,
    rawTargets,
  });
  if (!rawTargets.length) partial.needsInput = true;
  return partial;
}

/**
 * Extract pipeline-producer information from Get-ChildItem / Get-Item.
 * @param {string} command canonical command name
 * @param {Array<object>} args
 * @returns {{roots:Array<object>, recursive:boolean, wildcard:boolean}|null}
 */
function pwshProducerInfo(command, args) {
  if (!['get-childitem', 'get-item'].includes(command)) return null;
  const roots = [];
  let recursive = false;
  let wildcard = false;
  let i = 0;
  while (i < args.length) {
    const token = args[i];
    const param = parseParamName(token.value);
    if (!param) {
      if (!token.value.startsWith('-')) roots.push(token);
      i += 1;
      continue;
    }
    const resolved = resolveDeleteParam(param.name);
    if (resolved === 'path' || resolved === 'literalpath') {
      if (param.inline !== undefined) {
        roots.push({ value: param.inline, hasGlob: !(resolved === 'literalpath') && psGlobFromText(param.inline).hasGlob });
        i += 1;
        continue;
      }
      i += 1;
      while (i < args.length && !parseParamName(args[i].value)) {
        roots.push(args[i]);
        i += 1;
      }
      continue;
    }
    if (resolved === 'recurse') {
      recursive = booleanValue(param.inline);
      i += 1;
      continue;
    }
    if (resolved === 'filter' || resolved === 'include' || resolved === 'exclude') {
      let pattern = param.inline;
      if (pattern === undefined && i + 1 < args.length) {
        pattern = args[i + 1].value;
        i += 1;
      }
      if (typeof pattern === 'string') {
        const glob = psGlobFromText(pattern);
        if (glob.hasGlob) wildcard = true;
        // Upstream `-Include` / glob `-Filter` implies a recursive producer
        // per FR-3.1 pipeline backtracking requirements.
        if (resolved === 'include' || (resolved === 'filter' && glob.hasGlob)) recursive = true;
      }
      i += 1;
      continue;
    }
    i += 1;
  }
  if (!roots.length) roots.push(dotToken());
  return {
    roots: roots.map((token) => psTarget(token, false)),
    recursive,
    wildcard,
  };
}

/**
 * Parse one PowerShell pipeline stage.
 * @param {string} stageText
 * @param {number} depth nesting guard for `foreach` statements
 * @returns {{partial: object|null, producer: object|null}}
 */
function parsePwshStage(stageText, depth) {
  const dotnet = detectDotNetDelete(stageText);
  if (dotnet) return { partial: dotnet, producer: null };

  const tokens = stripRedirects(tokenizePwsh(stageText));
  let index = 0;
  while (index < tokens.length) {
    const value = tokens[index].value;
    if (!value || value === '&') {
      index += 1;
      continue;
    }
    // Skip assignment prefixes such as `$x = ...` (not a command invocation).
    if (/^\$[A-Za-z_][A-Za-z0-9_:]*$/.test(value) && tokens[index + 1] && tokens[index + 1].value === '=') {
      index += 3;
      continue;
    }
    break;
  }
  if (index >= tokens.length) return { partial: null, producer: null };
  const commandWord = tokens[index].value;
  let command = baseName(commandWord);
  command = PWSH_ALIASES.get(command) || command;
  const args = tokens.slice(index + 1);
  const stage = stageText.trim();

  if (command === 'remove-item') {
    return { partial: parseRemoveItem(args, stage), producer: null };
  }
  if (command === 'invoke-expression') {
    return {
      partial: makePartial({
        text: stage,
        command: 'invoke-expression',
        isDelete: true,
        deleteKind: 'other',
        unparsed: true,
        notes: ['Invoke-Expression 动态执行命令，无法静态确认删除意图'],
        risks: ['unknown-construct'],
      }),
      producer: null,
    };
  }

  const producer = pwshProducerInfo(command, args);
  if (producer) {
    return {
      partial: makePartial({ text: stage, command }),
      producer,
    };
  }

  // Script blocks / nested pipelines that contain a delete call
  // (`foreach ($d in $dirs) { Remove-Item ... $d }`, `... | ForEach-Object { ... }`).
  const masked = maskPwshStrings(stage);
  const looksLikeDelete = /(?:^|[\s{|;])(?:Remove-Item|ri|rm|del|erase|rd|rmdir)\b/i.test(masked) || /::\s*Delete\s*\(/i.test(masked);
  if (looksLikeDelete && /[{|]/.test(masked)) {
    const ioDelete = /::\s*Delete\s*\(/i.test(masked);
    const recursive = /(?:^|[\s{|;])-recurse\b/i.test(masked);
    const force = /(?:^|[\s{|;])-force\b/i.test(masked);
    let variableName = null;
    const foreachLoop = /foreach\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)/i.exec(masked);
    if (foreachLoop) variableName = '$' + foreachLoop[1];
    else if (/\$_/.test(masked)) variableName = '$_';
    else {
      const varArg = /(?:Remove-Item|ri|rm|del|erase|rd|rmdir)\b[^{}|;]*?(\$[A-Za-z_][A-Za-z0-9_]*)/i.exec(masked);
      if (varArg) variableName = varArg[1];
    }
    const rawTargets = variableName
      ? [{ raw: variableName, text: variableName, hasGlob: false, globKind: 'none', scopeOverride: 'variable' }]
      : [];
    const notes = ['在脚本块或嵌套管道中检测到删除调用，目标无法静态解析'];
    if (recursive) notes.push('脚本块中的删除命令带有 -Recurse');
    return {
      partial: makePartial({
        text: stage,
        command,
        isDelete: true,
        recursive,
        force,
        deleteKind: ioDelete ? 'io-delete' : 'other',
        unparsed: true,
        notes,
        risks: ['unknown-construct'],
        rawTargets,
      }),
      producer: null,
    };
  }

  return { partial: makePartial({ text: stage, command }), producer: null };
}

/**
 * Parse a PowerShell chunk (which may be a pipeline).
 * @param {string} chunkText
 * @param {number} [depth]
 * @returns {object[]} partial statements
 */
export function parsePwshStatements(chunkText, depth) {
  const stages = splitPwshPipeline(String(chunkText || ''));
  const out = [];
  let upstream = null;

  for (const stageText of stages) {
    let parsed;
    try {
      parsed = parsePwshStage(stageText, depth || 0);
    } catch {
      out.push(
        makePartial({
          text: stageText.trim(),
          command: '',
          unparsed: true,
          risks: ['unknown-construct'],
          notes: ['PowerShell 解析异常，已降级为不可解析语句'],
        }),
      );
      continue;
    }
    if (!parsed.partial) continue;
    const partial = parsed.partial;

    if (partial.isDelete && partial.rawTargets.length === 0) {
      if (upstream) {
        const roots = upstream.roots && upstream.roots.length ? upstream.roots : [psTarget(dotToken(), false)];
        partial.rawTargets = roots.map((target) => Object.assign({}, target, { viaPipeline: true, note: '目标来自管道上游' }));
        partial.recursive = partial.recursive || upstream.recursive;
        partial.wildcard = partial.wildcard || upstream.wildcard;
        partial.risks.push('pipeline-generic');
        partial.notes.push('删除目标由管道从上游命令传递，实际范围取决于上游输出');
        delete partial.needsInput;
      } else {
        partial.unparsed = true;
        partial.risks.push('unknown-construct');
        partial.notes.push('删除命令缺少可解析的删除目标');
      }
    } else if (partial.isDelete) {
      delete partial.needsInput;
    }

    out.push(partial);
    if (parsed.producer) upstream = parsed.producer;
  }

  return out;
}

/* ------------------------------------------------------------------------- *
 * cmd.exe support
 * ------------------------------------------------------------------------- */

/**
 * Build a cmd partial statement.
 * @param {object} fields
 * @returns {object}
 */
function makeCmdPartial(fields) {
  return makePartial(Object.assign({ shell: 'cmd' }, fields));
}

/**
 * Build a target from a cmd token.
 * @param {{value:string}} token
 * @param {object} [extra]
 * @returns {object}
 */
function cmdTarget(token, extra) {
  const value = token.value;
  let globKind = 'none';
  const kinds = new Set();
  if (value.includes('*')) kinds.add('asterisk');
  if (value.includes('?')) kinds.add('question');
  if (kinds.size > 1) globKind = 'mixed';
  else if (kinds.size === 1) globKind = kinds.values().next().value;
  return Object.assign(
    {
      raw: value,
      text: value,
      hasGlob: globKind !== 'none',
      globKind,
    },
    extra || {},
  );
}

/**
 * Tokenize a cmd.exe command line (double quotes group words).
 * @param {string} src
 * @returns {Array<{value:string, raw:string}>}
 */
function tokenizeCmd(src) {
  const tokens = [];
  const n = src.length;
  let i = 0;
  while (i < n && tokens.length < MAX_TOKENS) {
    const c = src[i];
    if (/\s/.test(c)) {
      i += 1;
      continue;
    }
    if (c === '|' || c === '&' || c === ';') {
      i += 1;
      continue;
    }
    const before = i;
    let value = '';
    while (i < n) {
      const ch = src[i];
      if (ch === '"') {
        i += 1;
        while (i < n && src[i] !== '"') {
          value += src[i];
          i += 1;
        }
        if (src[i] === '"') i += 1;
        continue;
      }
      if (ch === '^' && i + 1 < n) {
        value += src[i + 1];
        i += 2;
        continue;
      }
      if (/\s/.test(ch) || ch === '|' || ch === '&' || ch === ';') break;
      value += ch;
      i += 1;
    }
    if (value.length > 0) tokens.push({ value, raw: value });
    if (i === before) i += 1;
  }
  return tokens;
}

/**
 * Parse `del` / `erase`.
 * @param {Array<{value:string}>} args
 * @param {string} text
 * @param {string} command
 * @returns {object}
 */
function parseCmdDel(args, text, command) {
  let recursive = false;
  let force = false;
  const notes = [];
  const rawTargets = [];
  for (const token of args) {
    const value = token.value;
    if (/^\/[A-Za-z]/.test(value)) {
      const option = value.slice(1).toLowerCase();
      if (option.startsWith('s')) recursive = true;
      else if (option.startsWith('f') || option.startsWith('q')) force = true;
      else if (option.startsWith('p')) notes.push('/p 为交互确认');
      else if (option.startsWith('a')) notes.push('/a 按文件属性筛选目标');
      else notes.push('未识别的 del 选项 ' + value);
      continue;
    }
    rawTargets.push(cmdTarget(token));
  }
  if (!rawTargets.length) {
    return makeCmdPartial({
      text,
      command,
      isDelete: true,
      recursive,
      force,
      deleteKind: 'del',
      unparsed: true,
      notes: notes.concat(command + ' 缺少可解析的删除目标'),
      risks: ['unknown-construct'],
    });
  }
  return makeCmdPartial({
    text,
    command,
    isDelete: true,
    recursive,
    force,
    deleteKind: 'del',
    notes,
    rawTargets,
  });
}

/**
 * Parse `rd` / `rmdir` (cmd.exe built-in).
 * @param {Array<{value:string}>} args
 * @param {string} text
 * @param {string} command
 * @returns {object}
 */
function parseCmdRd(args, text, command) {
  let recursive = false;
  let force = false;
  const notes = [];
  const rawTargets = [];
  for (const token of args) {
    const value = token.value;
    if (/^\/[A-Za-z]/.test(value)) {
      const option = value.slice(1).toLowerCase();
      if (option.startsWith('s')) recursive = true;
      else if (option.startsWith('q')) force = true;
      else notes.push('未识别的 ' + command + ' 选项 ' + value);
      continue;
    }
    rawTargets.push(cmdTarget(token));
  }
  if (!rawTargets.length) {
    return makeCmdPartial({
      text,
      command,
      isDelete: true,
      recursive,
      force,
      deleteKind: command === 'rd' ? 'rd' : 'rmdir',
      unparsed: true,
      notes: notes.concat(command + ' 缺少可解析的删除目标'),
      risks: ['unknown-construct'],
    });
  }
  return makeCmdPartial({
    text,
    command,
    isDelete: true,
    recursive,
    force,
    deleteKind: command === 'rd' ? 'rd' : 'rmdir',
    notes,
    rawTargets,
  });
}

/**
 * Parse `robocopy SRC DST /MIR` or `/PURGE`.
 * @param {Array<{value:string}>} args
 * @param {string} text
 * @returns {object|null}
 */
function parseRobocopy(args, text) {
  let mirror = false;
  let purge = false;
  let dryRun = false;
  const positional = [];
  const notes = [];
  for (const token of args) {
    const value = token.value;
    if (value.startsWith('/') && value.length > 1) {
      const option = value.slice(1).toLowerCase();
      if (option === 'mir') mirror = true;
      else if (option === 'purge') purge = true;
      else if (option === 'l' || option === 'list') dryRun = true;
      else if (option === 'mov' || option === 'move') notes.push('/MOVE 会从源目录删除已移动的文件');
      continue;
    }
    positional.push(token);
  }
  if (!mirror && !purge) return null;
  if (!positional.length) {
    return makeCmdPartial({
      text,
      command: 'robocopy',
      isDelete: true,
      recursive: true,
      deleteKind: 'robocopy-mirror',
      unparsed: true,
      notes: ['robocopy 缺少源/目标目录参数'],
      risks: ['mirror-delete', 'unknown-construct'],
    });
  }
  const dest = positional.length > 1 ? positional[1] : null;
  notes.push(
    mirror
      ? 'robocopy /MIR 会把目标目录（DST，本例中的删除目标）镜像成源目录，删除 DST 中源端不存在的文件'
      : 'robocopy /PURGE 会删除目标目录（DST）中源端不存在的文件',
  );
  if (!dest) {
    return makeCmdPartial({
      text,
      command: 'robocopy',
      isDelete: true,
      dryRun,
      recursive: true,
      deleteKind: 'robocopy-mirror',
      unparsed: true,
      notes: notes.concat('未找到 robocopy 目标目录（DST）'),
      risks: ['mirror-delete', 'unknown-construct'],
    });
  }
  return makeCmdPartial({
    text,
    command: 'robocopy',
    isDelete: true,
    dryRun,
    recursive: true,
    deleteKind: 'robocopy-mirror',
    notes,
    risks: ['mirror-delete'],
    rawTargets: [cmdTarget(dest, { note: 'robocopy 目标目录 DST' })],
  });
}

/**
 * Parse a cmd `for` loop; the loop variable makes the intent uncertain.
 * @param {Array<{value:string}>} tokens full token list (starting with `for`)
 * @param {string} text
 * @param {number} depth
 * @returns {{partial: object|null, producer: null}}
 */
function parseCmdFor(tokens, text, depth) {
  const doIndex = tokens.findIndex((token) => token.value.toLowerCase() === 'do');
  if (doIndex < 0 || doIndex + 1 >= tokens.length) {
    return {
      partial: makeCmdPartial({
        text: text.trim(),
        command: 'for',
        unparsed: true,
        notes: ['cmd for 循环缺少 do 子句，无法静态解析'],
        risks: ['unknown-construct'],
      }),
      producer: null,
    };
  }
  const innerTokens = tokens.slice(doIndex + 1);
  const innerText = innerTokens.map((token) => token.raw).join(' ');
  const inner = parseCmdStage(innerText, (depth || 0) + 1);
  const loopVarToken = innerTokens.find((token) => /^%%?[A-Za-z]$/.test(token.value));
  const loopVar = loopVarToken ? loopVarToken.value : null;
  if (!inner.partial || !inner.partial.isDelete) {
    return {
      partial: makeCmdPartial({
        text: text.trim(),
        command: 'for',
        notes: ['cmd for 循环中未发现删除命令'],
      }),
      producer: null,
    };
  }
  const rawTargets = (inner.partial.rawTargets || []).map((target) => {
    if (loopVar && target.raw === loopVar) {
      return Object.assign({}, target, { scopeOverride: 'variable' });
    }
    if (/%{1,2}[A-Za-z]/.test(target.raw)) {
      return Object.assign({}, target, { scopeOverride: 'variable' });
    }
    return target;
  });
  if (!rawTargets.length && loopVar) {
    rawTargets.push({ raw: loopVar, text: loopVar, hasGlob: false, globKind: 'none', scopeOverride: 'variable' });
  }
  return {
    partial: makeCmdPartial({
      text: text.trim(),
      command: 'for',
      isDelete: true,
      recursive: Boolean(inner.partial.recursive),
      force: Boolean(inner.partial.force),
      deleteKind: inner.partial.deleteKind,
      unparsed: true,
      notes: (inner.partial.notes || []).concat('cmd for 循环变量无法静态展开，实际删除范围不确定'),
      risks: (inner.partial.risks || []).concat('unknown-construct'),
      rawTargets,
    }),
    producer: null,
  };
}

/**
 * Parse one cmd.exe pipeline stage.
 * @param {string} stageText
 * @param {number} depth
 * @returns {{partial: object|null, producer: null}}
 */
function parseCmdStage(stageText, depth) {
  const tokens = tokenizeCmd(stageText);
  if (!tokens.length) return { partial: null, producer: null };
  const command = baseName(tokens[0].value);
  if (command === 'for') return parseCmdFor(tokens, stageText, depth || 0);
  const args = tokens.slice(1);
  if (command === 'del' || command === 'erase') {
    return { partial: parseCmdDel(args, stageText.trim(), command), producer: null };
  }
  if (command === 'rd' || command === 'rmdir') {
    return { partial: parseCmdRd(args, stageText.trim(), command), producer: null };
  }
  if (command === 'robocopy') {
    const partial = parseRobocopy(args, stageText.trim());
    if (partial) return { partial, producer: null };
  }
  return {
    partial: makeCmdPartial({ text: stageText.trim(), command }),
    producer: null,
  };
}

/**
 * Split a cmd chunk into pipeline stages on unquoted `|`.
 * @param {string} src
 * @returns {string[]}
 */
function splitCmdPipeline(src) {
  const stages = [];
  let start = 0;
  let inQuotes = false;
  for (let i = 0; i < src.length; i += 1) {
    const c = src[i];
    if (c === '"') {
      inQuotes = !inQuotes;
      continue;
    }
    if (c === '|' && !inQuotes) {
      stages.push(src.slice(start, i));
      start = i + 1;
    }
  }
  stages.push(src.slice(start));
  return stages.map((stage) => stage.trim()).filter((stage) => stage.length > 0);
}

/**
 * Parse a cmd.exe chunk (which may be a pipeline).
 * @param {string} chunkText
 * @param {number} [depth]
 * @returns {object[]} partial statements
 */
export function parseCmdStatements(chunkText, depth) {
  const out = [];
  for (const stageText of splitCmdPipeline(String(chunkText || ''))) {
    try {
      const parsed = parseCmdStage(stageText, depth || 0);
      if (parsed.partial) out.push(parsed.partial);
    } catch {
      out.push(
        makeCmdPartial({
          text: stageText.trim(),
          command: '',
          unparsed: true,
          risks: ['unknown-construct'],
          notes: ['cmd 解析异常，已降级为不可解析语句'],
        }),
      );
    }
  }
  return out;
}

