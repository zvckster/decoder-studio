/*
 * Helpers shared by the format modules.
 *
 * Every generated pattern is PCRE2 that:
 *   - has exactly one capture group per extracted field,
 *   - never contains a raw '<' (Wazuh's XML reader would treat it as a tag),
 *     so no lookbehinds / named groups; literal '<' is written \x3c,
 *   - is unanchored unless the format is positional, so it works whether or
 *     not a syslog header was stripped by the pre-decoder.
 */
WDG_MODULE(function (W) {
  'use strict';
  const U = W.util;

  // Character that cannot be part of a key: used as a key boundary instead of
  // a lookbehind (which would need '<').
  const KEY_BOUNDARY = '(?:^|[^\\w.\\-])';

  /** PCRE2 body for a quoted string (without the capture). */
  function quotedBody(q) {
    const e = U.escapeClassChar(q);
    return `(?:[^${e}\\\\]|\\\\.)*`;
  }

  /**
   * Capture group for a value that may be quoted, never quoted, or both.
   * Uses a PCRE2 branch-reset group "(?|...)" for the mixed case so the
   * decoder still exposes a single field.
   */
  function valueCapture({ quoting, quote = '"', unquoted, typed }) {
    const q = U.escapeRegex(quote);
    const inner = typed || unquoted;
    if (quoting === 'always') return `${q}(${typed || quotedBody(quote)})${q}`;
    if (quoting === 'mixed') return `(?|${q}(${quotedBody(quote)})${q}|(${inner}))`;
    return `(${inner})`;
  }

  /** Strict typed pattern for a field type, or null when none is safe. */
  function typedPattern(type) {
    const t = W.types.info(type);
    return t && t.pattern ? t.pattern : null;
  }

  /**
   * Common literal prefix of the bodies, cut back to a "safe" boundary so it
   * never ends in the middle of a variable token.
   */
  function literalPrefix(bodies, maxLen = 64) {
    let p = U.commonPrefix(bodies);
    if (!p) return '';
    // If every body continues past the prefix, the next char differs → the
    // last token is partial; cut back to the previous delimiter.
    const allLonger = bodies.every((b) => b.length > p.length);
    if (allLonger) {
      const m = /^(.*[\s|,;:=\[\](){}"'\/])/.exec(p);
      p = m ? m[1] : '';
    }
    // Digits in the prefix are almost always sample coincidences (dates…)
    const digit = p.search(/\d/);
    if (digit >= 0) {
      const cut = p.slice(0, digit);
      const m = /^(.*[\s|,;:=\[\](){}"'\/])/.exec(cut);
      p = m ? m[1] : cut.length >= 4 ? cut : '';
    }
    // Day and month names ("Mon Sep ...") come from dates: they change.
    const dayMonth = p.search(/\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\b/);
    if (dayMonth >= 0) p = p.slice(0, dayMonth);
    return p.slice(0, maxLen);
  }

  /** Rank keys by how distinctive they are for a source fingerprint. */
  const GENERIC_KEYS = new Set(['date', 'time', 'msg', 'message', 'type', 'level', 'user', 'src', 'dst', 'action', 'id', 'host', 'name', 'status', 'result', 'severity', 'timestamp', 'ts', 'event', 'data', 'value', 'info']);
  function distinctiveness(key) {
    let s = key.length;
    if (GENERIC_KEYS.has(key.toLowerCase())) s -= 10;
    if (/\d/.test(key)) s -= 2;
    return s;
  }

  W.formatsCommon = { KEY_BOUNDARY, quotedBody, valueCapture, typedPattern, literalPrefix, distinctiveness };
});
