/*
 * Wazuh Decoder Studio: engine core.
 *
 * Every engine file is a plain script that registers itself on the global
 * `WDG` namespace, so the app runs straight from index.html (no build step,
 * no server, nothing leaves the browser) and the same files load in Node for
 * the test-suite and the CLI.
 */
/*
 * Module loader: every engine file calls WDG_MODULE(fn). The function runs
 * immediately against the shared namespace and is kept, so the UI can rebuild
 * the engine inside a Web Worker (Function#toString) even from file:// pages.
 */
(function (g) {
  if (g.WDG_MODULE) return;
  const loader = function (fn) {
    const W = (g.WDG = g.WDG || {});
    (W.__sources = W.__sources || []).push(fn);
    fn(W);
  };
  g.WDG_MODULE = loader;
})(globalThis);

WDG_MODULE(function (W) {
  'use strict';

  W.version = '2.0.0';
  W.formats = W.formats || {};

  // Characters that are special in PCRE2 outside a character class.
  const PCRE_META = /[\\^$.|?*+()[\]{}\/]/g;

  const util = {
    /** Split pasted text into log lines, dropping blank lines and CR. */
    splitLines(text) {
      return String(text || '')
        .split(/\r?\n|\r/)
        .map((l) => l.replace(/\s+$/, ''))
        .filter((l) => l.trim() !== '');
    },

    /**
     * Escape a literal for a PCRE2 pattern that will live inside a Wazuh XML
     * element. Wazuh's XML reader does not decode entities (&lt; stays
     * "&lt;"), so '<' must never appear raw: we emit \x3c instead.
     */
    escapeRegex(str) {
      let out = '';
      for (const ch of String(str)) {
        const code = ch.codePointAt(0);
        if (ch === '<') out += '\\x3c';
        else if (ch === '>') out += '\\x3e';
        else if (ch === '\t') out += '\\t';
        else if (code < 0x20 || code === 0x7f) out += '\\x' + code.toString(16).padStart(2, '0');
        else out += ch.replace(PCRE_META, '\\$&');
      }
      return out;
    },

    /** Escape a character for use inside a PCRE2 character class. */
    escapeClassChar(ch) {
      if (ch === '<') return '\\x3c';
      if (ch === '>') return '\\x3e';
      if (ch === '\t') return '\\t';
      if (/[\\\]\[^-]/.test(ch)) return '\\' + ch;
      return ch;
    },

    /** Text safe for an XML comment (no "--", no raw control chars). */
    xmlComment(str) {
      return String(str).replace(/-{2,}/g, '-').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, ' ');
    },

    /** Attribute-safe text for XML attributes (decoder names are validated anyway). */
    xmlAttr(str) {
      return String(str).replace(/[<>&"]/g, (c) => ({ '<': '', '>': '', '&': '', '"': '' }[c]));
    },

    /** Longest common prefix of a list of strings. */
    commonPrefix(list) {
      if (!list.length) return '';
      let prefix = list[0];
      for (let i = 1; i < list.length && prefix; i++) {
        const s = list[i];
        let j = 0;
        while (j < prefix.length && j < s.length && prefix[j] === s[j]) j++;
        prefix = prefix.slice(0, j);
      }
      return prefix;
    },

    uniq(arr) {
      return [...new Set(arr)];
    },

    /** Most common element of an array (ties → first seen). */
    mode(arr) {
      const counts = new Map();
      let best = undefined;
      let bestN = 0;
      for (const v of arr) {
        const n = (counts.get(v) || 0) + 1;
        counts.set(v, n);
        if (n > bestN) {
          best = v;
          bestN = n;
        }
      }
      return best;
    },

    /** Decoder / field name sanitation. */
    sanitizeDecoderName(name) {
      return String(name || '')
        .trim()
        .replace(/\s+/g, '-')
        .replace(/[^A-Za-z0-9_.\-]/g, '')
        .slice(0, 64);
    },

    sanitizeFieldName(name) {
      return String(name || '')
        .trim()
        .replace(/\s+/g, '_')
        .replace(/[^A-Za-z0-9_.\-@]/g, '_')
        .replace(/^[.]+|[.]+$/g, '')
        .replace(/_{2,}/g, '_');
    },

    truncate(str, n) {
      str = String(str);
      return str.length > n ? str.slice(0, n - 1) + '…' : str;
    },

    clone(obj) {
      return JSON.parse(JSON.stringify(obj));
    },
  };

  W.util = util;
});
