/*
 * Wazuh expression engines → JavaScript, for the in-browser tester.
 *
 *   pcre2    translated to a JS RegExp. Handles leading inline flags, \A \z
 *            \Z \h \H \Q..\E, atomic groups, possessive quantifiers, POSIX
 *            classes, (?P<name>) and branch-reset groups "(?|...)" (with a
 *            JS-group → PCRE-group renumbering table).
 *   osregex  Wazuh's OS_Regex (\w \d \s \p \. ...), approximated with
 *            backtracking JS semantics.
 *   osmatch  Wazuh's OS_Match (literal, ^ $ | and ! negation).
 *
 * compile() returns { exec(str) → null | {start, end, groups[]}, error, approx }.
 * `groups` follows Wazuh: one entry per group up to the highest group that
 * participated; unset groups in between become "".
 */
WDG_MODULE(function (W) {
  'use strict';

  const POSIX = {
    alpha: 'A-Za-z', digit: '0-9', alnum: 'A-Za-z0-9', upper: 'A-Z', lower: 'a-z', space: '\\s', blank: ' \\t',
    punct: '!-\\/:-@\\[-`{-~', xdigit: '0-9A-Fa-f', word: '\\w', cntrl: '\\x00-\\x1f', print: '\\x20-\\x7e', graph: '\\x21-\\x7e',
  };
  const jsEscape = (s) => s.replace(/[\\^$.|?*+()[\]{}\/]/g, '\\$&');

  function pcreToJs(src) {
    let s = src;
    let flags = '';
    let m;
    while ((m = /^\(\?([imsxJU-]+)\)/.exec(s))) {
      flags += m[1].replace(/[xJU-]/g, '');
      s = s.slice(m[0].length);
    }
    while ((m = /^\(\*[A-Z_]+(?:=\d+)?\)/.exec(s))) s = s.slice(m[0].length);

    let out = '';
    const map = [];
    let pcre = 0;
    const frames = [];
    let inClass = false;
    let lastQuant = false;

    for (let i = 0; i < s.length; i++) {
      const ch = s[i];
      if (ch === '\\') {
        const nx = s[i + 1];
        if (nx === undefined) throw new Error('trailing backslash');
        lastQuant = false;
        if (nx === 'Q') {
          const j = s.indexOf('\\E', i + 2);
          const lit = s.slice(i + 2, j < 0 ? s.length : j);
          out += inClass ? lit.replace(/[\]\\^-]/g, '\\$&') : jsEscape(lit);
          i = j < 0 ? s.length : j + 1;
          continue;
        }
        if (nx === 'E') {
          i++;
          continue;
        }
        if (nx === 'h') {
          out += inClass ? ' \\t' : '[ \\t]';
          i++;
          continue;
        }
        if (!inClass) {
          if (nx === 'A') { out += '^'; i++; continue; }
          if (nx === 'z') { out += '$(?![\\s\\S])'; i++; continue; }
          if (nx === 'Z') { out += '(?=\\n?$(?![\\s\\S]))'; i++; continue; }
          if (nx === 'H') { out += '[^ \\t]'; i++; continue; }
          if (nx === 'R') { out += '(?:\\r\\n|[\\n\\v\\f\\r\\x85\\u2028\\u2029])'; i++; continue; }
          if (nx === 'K' || nx === 'G') throw new Error(`\\${nx} is not supported by the simulator`);
        }
        if (nx === 'x' && s[i + 2] === '{') {
          const j = s.indexOf('}', i + 3);
          out += '\\u{' + s.slice(i + 3, j) + '}';
          flags += flags.includes('u') ? '' : 'u';
          i = j;
          continue;
        }
        // a backslash before a non-alphanumeric is always a literal in PCRE2
        if (/[^A-Za-z0-9]/.test(nx)) out += jsEscapeChar(nx, inClass);
        else out += ch + nx;
        i++;
        continue;
      }
      if (inClass) {
        if (ch === '[' && s[i + 1] === ':') {
          const j = s.indexOf(':]', i + 2);
          const name = s.slice(i + 2, j);
          if (j > 0 && POSIX[name] !== undefined) {
            out += POSIX[name];
            i = j + 1;
            continue;
          }
        }
        if (ch === ']') inClass = false;
        out += ch === '[' ? '\\[' : ch;
        continue;
      }
      if (ch === '[') {
        inClass = true;
        lastQuant = false;
        out += '[';
        if (s[i + 1] === '^') {
          out += '^';
          i++;
        }
        if (s[i + 1] === ']') {
          out += '\\]';
          i++;
        }
        continue;
      }
      if (ch === '(') {
        lastQuant = false;
        if (s[i + 1] === '?') {
          const a = s[i + 2];
          if (a === '|') {
            frames.push({ type: 'reset', start: pcre, max: pcre });
            out += '(?:';
            i += 2;
            continue;
          }
          if (a === '>') {
            frames.push({ type: 'nc' });
            out += '(?:';
            i += 2;
            continue;
          }
          if (a === 'P' && s[i + 3] === '<') {
            pcre++;
            map.push(pcre);
            frames.push({ type: 'cap' });
            out += '(?<';
            i += 3;
            continue;
          }
          if ((a === '<' && s[i + 3] !== '=' && s[i + 3] !== '!') || a === "'") {
            pcre++;
            map.push(pcre);
            frames.push({ type: 'cap' });
            if (a === "'") {
              const j = s.indexOf("'", i + 3);
              out += '(?<' + s.slice(i + 3, j) + '>';
              i = j;
            } else {
              out += '(?<';
              i += 2;
            }
            continue;
          }
          if (a === '#') {
            const j = s.indexOf(')', i);
            i = j;
            continue;
          }
          frames.push({ type: 'nc' });
          out += '(';
          continue;
        }
        if (s[i + 1] === '*') throw new Error('PCRE2 verbs are not supported by the simulator');
        pcre++;
        map.push(pcre);
        frames.push({ type: 'cap' });
        out += '(';
        continue;
      }
      if (ch === ')') {
        const f = frames.pop();
        if (f && f.type === 'reset') pcre = Math.max(f.max, pcre);
        lastQuant = false;
        out += ')';
        continue;
      }
      if (ch === '|') {
        const f = frames[frames.length - 1];
        if (f && f.type === 'reset') {
          f.max = Math.max(f.max, pcre);
          pcre = f.start;
        }
        lastQuant = false;
        out += '|';
        continue;
      }
      if (ch === '+' && lastQuant) {
        lastQuant = false; // possessive → plain
        continue;
      }
      if (ch === '?' && lastQuant) {
        lastQuant = false; // lazy
        out += '?';
        continue;
      }
      if (ch === '*' || ch === '+' || ch === '?') {
        lastQuant = true;
        out += ch;
        continue;
      }
      if (ch === '{' && /^\{\d+(?:,\d*)?\}/.test(s.slice(i))) {
        const q = /^\{\d+(?:,\d*)?\}/.exec(s.slice(i))[0];
        out += q;
        i += q.length - 1;
        lastQuant = true;
        continue;
      }
      lastQuant = false;
      out += ch === '/' ? '\\/' : ch;
    }
    return { source: out, flags: [...new Set(flags)].join(''), map, groups: Math.max(0, ...map, 0) };
  }

  function jsEscapeChar(c, inClass) {
    if (inClass) return /[\]\\^-]/.test(c) ? '\\' + c : c;
    return /[\\^$.|?*+()[\]{}\/]/.test(c) ? '\\' + c : c;
  }

  // ---------------------------------------------------------------- OS_Regex
  const OS_CLASSES = {
    w: '[A-Za-z0-9@_\\-]', W: '[^A-Za-z0-9@_\\-]', d: '[0-9]', D: '[^0-9]', s: '[ ]', S: '[^ ]', t: '\\t',
    p: '[()*+,\\-.:;<=>?\\[\\]!"\'#$%&|{}]', '.': '[\\s\\S]',
  };

  function osRegexToJs(src) {
    const alts = splitUnescaped(src, '|');
    const parts = alts.map((a) => {
      let out = '';
      for (let i = 0; i < a.length; i++) {
        const ch = a[i];
        if (ch === '\\') {
          const nx = a[i + 1];
          i++;
          if (OS_CLASSES[nx]) {
            out += OS_CLASSES[nx];
            if (a[i + 1] === '+' || a[i + 1] === '*') {
              out += a[i + 1];
              i++;
            }
          } else out += jsEscape(nx || '\\');
          continue;
        }
        if (ch === '(' || ch === ')' || ch === '^' || ch === '$') out += ch;
        else out += jsEscape(ch);
      }
      return out;
    });
    // Decoders compile OS_Regex without OS_CASE_SENSITIVE → case-insensitive.
    return { source: parts.length > 1 ? parts.map((p) => `(?:${p})`).join('|') : parts[0], flags: 'i', map: null };
  }

  function splitUnescaped(s, sep) {
    const out = [];
    let cur = '';
    for (let i = 0; i < s.length; i++) {
      if (s[i] === '\\' && i + 1 < s.length) {
        cur += s[i] + s[i + 1];
        i++;
      } else if (s[i] === sep) {
        out.push(cur);
        cur = '';
      } else cur += s[i];
    }
    out.push(cur);
    return out;
  }

  function osMatch(src) {
    const alts = splitUnescaped(src, '|').map((a) => {
      let neg = false;
      if (a.startsWith('!')) {
        neg = true;
        a = a.slice(1);
      }
      const start = a.startsWith('^');
      const end = a.endsWith('$') && !a.endsWith('\\$');
      let lit = a.slice(start ? 1 : 0, end ? -1 : undefined).replace(/\\(.)/g, '$1');
      return { neg, re: new RegExp((start ? '^' : '') + jsEscape(lit) + (end ? '$' : ''), 'i') };
    });
    return {
      exec(str) {
        const ok = alts.some((a) => a.re.test(str) !== a.neg);
        return ok ? { start: 0, end: null, groups: [] } : null;
      },
      error: null,
      approx: false,
    };
  }

  /**
   * @param {{value:string, type?:string}} expr
   * @param {'regex'|'prematch'|'program_name'} role  decides the default type
   */
  function compile(expr, role) {
    const type = (expr.type || (role === 'program_name' ? 'osmatch' : 'osregex')).toLowerCase();
    if (type === 'osmatch') {
      try {
        return Object.assign(osMatch(expr.value), { type });
      } catch (e) {
        return { exec: () => null, error: e.message, type };
      }
    }
    let t;
    try {
      t = type === 'pcre2' ? pcreToJs(expr.value) : osRegexToJs(expr.value);
    } catch (e) {
      return { exec: () => null, error: e.message, type };
    }
    let re;
    try {
      re = new RegExp(t.source, t.flags);
    } catch (e) {
      return { exec: () => null, error: e.message.replace(/^Invalid regular expression: /, ''), type };
    }
    return {
      type,
      approx: type === 'osregex',
      error: null,
      source: t.source,
      groupCount: t.map ? t.groups : countGroups(t.source),
      exec(str) {
        const m = re.exec(str);
        if (!m) return null;
        let groups;
        if (t.map) {
          groups = [];
          for (let j = 1; j < m.length; j++) {
            const idx = t.map[j - 1];
            if (m[j] !== undefined && groups[idx - 1] === undefined) groups[idx - 1] = m[j];
          }
        } else groups = m.slice(1);
        let last = groups.length;
        while (last > 0 && groups[last - 1] === undefined) last--;
        groups = groups.slice(0, last).map((g) => (g === undefined ? '' : g));
        return { start: m.index, end: m.index + m[0].length, groups };
      },
    };
  }

  function countGroups(source) {
    try {
      return new RegExp(source + '|').exec('').length - 1;
    } catch (e) {
      return 0;
    }
  }

  /**
   * Heuristic for catastrophic backtracking: a group that contains an
   * unbounded quantifier and is itself repeated without bound, e.g. (a+)+,
   * (?:x|\S+?)*, ((?:[^,]|\\,)+?)+. PCRE2 in Wazuh aborts such matches at its
   * match limit (the event is then simply not decoded); a JS engine can hang.
   */
  function backtrackRisk(src) {
    const stack = [];
    let inClass = false;
    for (let i = 0; i < src.length; i++) {
      const c = src[i];
      if (c === '\\') {
        i++;
        continue;
      }
      if (inClass) {
        if (c === ']') inClass = false;
        continue;
      }
      if (c === '[') {
        inClass = true;
        continue;
      }
      if (c === '(') stack.push({ unbounded: false });
      else if (c === ')') {
        const g = stack.pop() || { unbounded: false };
        const q = src[i + 1];
        const repeated = q === '+' || q === '*' || (q === '{' && /^\{\d+,\}/.test(src.slice(i + 1)));
        if (g.unbounded && repeated) return true;
        if (stack.length && (g.unbounded || repeated)) stack[stack.length - 1].unbounded = true;
      } else if ((c === '+' || c === '*') && stack.length) stack[stack.length - 1].unbounded = true;
      else if (c === '{' && stack.length && /^\{\d+,\}/.test(src.slice(i))) stack[stack.length - 1].unbounded = true;
    }
    return false;
  }

  /** Number of unanchored wildcards (.* .+ .*? .+?) outside character classes. */
  function wildcardCount(src) {
    let n = 0;
    let inClass = false;
    for (let i = 0; i < src.length; i++) {
      const c = src[i];
      if (c === '\\') {
        i++;
        continue;
      }
      if (inClass) {
        if (c === ']') inClass = false;
        continue;
      }
      if (c === '[') inClass = true;
      else if (c === '.' && (src[i + 1] === '*' || src[i + 1] === '+')) n++;
    }
    return n;
  }

  W.regex = { compile, pcreToJs, osRegexToJs, backtrackRisk, wildcardCount };
});
