/**
 * @module dsh-vigil/audit/lexer
 *
 * A small, dependency-free, zero-execution lexical masker for JavaScript /
 * TypeScript sources. It never imports, evaluates, or otherwise executes the
 * scanned text. Its only job is to let the rule engine distinguish "code" from
 * "comment" and "string literal" content so regex rules can avoid the most
 * obvious false positives.
 *
 * Two masks are produced in a single pass, both with the exact same length as
 * the source (newlines preserved), so every match offset still maps to the
 * original 1-based line number:
 *
 * - `code`: comments, string/template literal *content* and regex literal
 *   content are replaced by spaces. Use it for API-shaped rules such as
 *   `eval(`, `fetch(`, `child_process.exec(`.
 * - `literals`: comments and regex literal content are replaced, but string /
 *   template literal content is kept. Use it for rules that need values such as
 *   credential paths, URLs, env variable names and shell command strings.
 *
 * This is deliberately a heuristic lexer (not a parser): it handles the common
 * cases (line/block comments, single/double quotes, template literals with
 * `${...}` interpolation, simple regex literals) and recovers gracefully on
 * malformed input. It is NOT a security boundary.
 */

/** Characters that may legally precede a regex literal (expression position). */
const REGEX_LEAD_PUNCT = new Set('([{,;:=!&|?+-*%^~<>');

/** Keywords after which a slash starts a regex literal rather than division. */
const REGEX_LEAD_KEYWORDS = /^(?:return|typeof|instanceof|in|of|case|delete|void|throw|new|yield|await|else|do)$/;

/** Default sanity cap; scanning itself caps files well below this. */
const DEFAULT_MAX_CHARS = 2 * 1024 * 1024;

/**
 * Split a masked string into lines without a trailing `\r`, so line numbers
 * stay aligned with the source split on `\n` (CRLF files included).
 *
 * @param {string} text
 * @returns {string[]}
 */
function splitLines(text) {
  return text.split('\n').map((line) => (line.endsWith('\r') ? line.slice(0, -1) : line));
}

/**
 * Compute the start offset of every line in `source`.
 *
 * @param {string} source
 * @returns {number[]} `lineStarts[0] === 0`; index = 1-based line - 1.
 */
export function lineStartsOf(source) {
  const text = typeof source === 'string' ? source : '';
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) {
    if (text[i] === '\n') starts.push(i + 1);
  }
  return starts;
}

/**
 * Map a UTF-16 offset to a 1-based line number using `lineStarts`.
 *
 * @param {number[]} lineStarts
 * @param {number} index
 * @returns {number}
 */
export function lineNumberAt(lineStarts, index) {
  if (!Array.isArray(lineStarts) || lineStarts.length === 0) return 1;
  const offset = Number.isFinite(index) ? Math.max(0, Math.floor(index)) : 0;
  let low = 0;
  let high = lineStarts.length - 1;
  while (low < high) {
    const mid = (low + high + 1) >> 1;
    if (lineStarts[mid] <= offset) low = mid;
    else high = mid - 1;
  }
  return low + 1;
}

/**
 * Check whether the last significant code character before `index` allows a
 * regex literal to start there (a heuristic used to avoid treating division as
 * a regex, which could otherwise swallow real code).
 *
 * @param {string[]} chars Masked code characters (comments/strings blanked).
 * @param {number} index
 * @param {string} source Original source, used for keyword look-behind.
 * @returns {boolean}
 */
function canStartRegex(chars, index, source) {
  let i = index - 1;
  while (i >= 0 && /\s/.test(chars[i])) i -= 1;
  if (i < 0) return true;
  const ch = chars[i];
  if (REGEX_LEAD_PUNCT.has(ch)) return true;
  if (!/[\w$]/.test(ch)) return false;
  let start = i;
  while (start >= 0 && /[\w$]/.test(chars[start])) start -= 1;
  return REGEX_LEAD_KEYWORDS.test(source.slice(start + 1, i + 1));
}

/**
 * Build masked views of a JS/TS source string without executing it.
 *
 * @param {string} source Raw file text.
 * @param {{ maxChars?: number }} [options]
 * @returns {{
 *   source: string,
 *   code: string,
 *   literals: string,
 *   lineCount: number,
 *   lines: { original: string[], code: string[], literals: string[] },
 *   lineAt: (index: number) => number,
 *   sourceLine: (line: number) => string,
 *   codeLine: (line: number) => string,
 *   literalLine: (line: number) => string
 * }}
 */
export function maskSource(source, options = {}) {
  const text = typeof source === 'string' ? source : '';
  const requested = Number.isFinite(options.maxChars) && options.maxChars > 0
    ? Math.floor(options.maxChars)
    : DEFAULT_MAX_CHARS;
  const end = Math.min(text.length, requested);

  let maskedCode;
  let maskedLiterals;
  try {
    // Working on arrays of UTF-16 code units keeps index offsets (and therefore
    // line numbers) identical to the source.
    const codeChars = text.split('');
    const literalChars = text.split('');

    /** Blank one character in the code mask only (never a newline). */
    const blankCode = (i) => {
      if (i >= end || i < 0) return;
      if (text[i] !== '\n' && text[i] !== '\r') codeChars[i] = ' ';
    };
    /** Blank one character in both masks (never a newline). */
    const blankBoth = (i) => {
      if (i >= end || i < 0) return;
      if (text[i] === '\n' || text[i] === '\r') return;
      codeChars[i] = ' ';
      literalChars[i] = ' ';
    };

    /** 'code' | 'line' | 'block' | 'string' | 'template' | 'regex' */
    let mode = 'code';
    let quote = '';
    /** @type {{ depth: number, inExpr: boolean }[]} */
    const templates = [];
    let inRegexClass = false;

    for (let i = 0; i < end; i += 1) {
      const ch = text[i];

      if (mode === 'code') {
        if (ch === '/' && text[i + 1] === '/') {
          blankBoth(i);
          blankBoth(i + 1);
          mode = 'line';
          i += 1;
          continue;
        }
        if (ch === '/' && text[i + 1] === '*') {
          blankBoth(i);
          blankBoth(i + 1);
          mode = 'block';
          i += 1;
          continue;
        }
        if (ch === "'" || ch === '"') {
          mode = 'string';
          quote = ch;
          continue;
        }
        if (ch === '`') {
          templates.push({ depth: 0, inExpr: false });
          mode = 'template';
          continue;
        }
        if (ch === '/' && canStartRegex(codeChars, i, text)) {
          mode = 'regex';
          inRegexClass = false;
          continue;
        }
        const top = templates[templates.length - 1];
        if (top && top.inExpr) {
          if (ch === '{') {
            top.depth += 1;
            continue;
          }
          if (ch === '}') {
            if (top.depth === 0) {
              top.inExpr = false;
              mode = 'template';
            } else {
              top.depth -= 1;
            }
            continue;
          }
        }
        continue;
      }

      if (mode === 'line') {
        if (ch === '\n') mode = 'code';
        else blankBoth(i);
        continue;
      }

      if (mode === 'block') {
        if (ch === '*' && text[i + 1] === '/') {
          blankBoth(i);
          blankBoth(i + 1);
          mode = 'code';
          i += 1;
        } else {
          blankBoth(i);
        }
        continue;
      }

      if (mode === 'string') {
        if (ch === '\\') {
          blankCode(i);
          blankCode(i + 1);
          i += 1;
        } else if (ch === quote) {
          mode = 'code';
        } else if (ch === '\n') {
          // Unterminated string: recover on the next line instead of failing.
          mode = 'code';
        } else {
          blankCode(i);
        }
        continue;
      }

      if (mode === 'template') {
        if (ch === '\\') {
          blankCode(i);
          blankCode(i + 1);
          i += 1;
        } else if (ch === '`') {
          templates.pop();
          mode = 'code';
        } else if (ch === '$' && text[i + 1] === '{') {
          const top = templates[templates.length - 1];
          if (top) top.inExpr = true;
          // Keep `${` visible in the code mask so structure remains readable.
          i += 1;
          mode = 'code';
        } else {
          blankCode(i);
        }
        continue;
      }

      // mode === 'regex'
      if (ch === '\\') {
        blankBoth(i);
        blankBoth(i + 1);
        i += 1;
      } else if (ch === '[') {
        inRegexClass = true;
        blankBoth(i);
      } else if (ch === ']') {
        inRegexClass = false;
        blankBoth(i);
      } else if (ch === '/' && !inRegexClass) {
        mode = 'code';
        // Flags after the closing slash stay as ordinary code characters.
      } else {
        blankBoth(i);
      }
    }

    maskedCode = codeChars.join('');
    maskedLiterals = literalChars.join('');
  } catch {
    // The masker must never throw; fall back to unmasked views (rules will be
    // looser but line numbers stay correct).
    maskedCode = text;
    maskedLiterals = text;
  }

  const originalLines = splitLines(text);
  const codeLines = splitLines(maskedCode);
  const literalLines = splitLines(maskedLiterals);
  const lineStarts = lineStartsOf(text);
  const lineCount = originalLines.length;

  return {
    source: text,
    code: maskedCode,
    literals: maskedLiterals,
    lineCount,
    lines: { original: originalLines, code: codeLines, literals: literalLines },
    lineAt: (index) => lineNumberAt(lineStarts, index),
    sourceLine: (line) => originalLines[line - 1] ?? '',
    codeLine: (line) => codeLines[line - 1] ?? '',
    literalLine: (line) => literalLines[line - 1] ?? '',
  };
}
