/*
 * JSON logs.
 *
 * Wazuh ships a root decoder "json" (0006-json_decoders.xml, prematch ^{\s*")
 * that is loaded before any custom decoder. Consequences the generator
 * handles for you:
 *   - pure JSON without a program name  → the built-in decoder always wins;
 *     the right deliverable is *rules* (<decoded_as>json</decoded_as>), not a
 *     decoder. Field names are the JSON paths ("alert.severity").
 *   - JSON after a syslog program name  → root with <program_name> and the
 *     JSON_Decoder plugin.
 *   - JSON after a text prefix          → root whose prematch consumes the
 *     prefix, plugin with offset="after_prematch".
 * Optionally, "regex" mode extracts selected keys with siblings so they can be
 * renamed (only when the built-in decoder does not take the log).
 */
WDG_MODULE(function (W) {
  'use strict';
  const U = W.util;
  const C = W.formatsCommon;

  function locate(body) {
    const i = body.indexOf('{');
    if (i < 0) return null;
    const txt = body.slice(i);
    let obj = tryParse(txt);
    if (obj === undefined) {
      const j = txt.lastIndexOf('}');
      if (j > 0) obj = tryParse(txt.slice(0, j + 1));
    }
    if (obj === undefined || obj === null || typeof obj !== 'object' || Array.isArray(obj)) return null;
    return { prefix: body.slice(0, i), obj };
  }

  function tryParse(s) {
    try {
      return JSON.parse(s);
    } catch (e) {
      return undefined;
    }
  }

  /** Flatten like Wazuh's JSON_Decoder: nested keys joined with '.', arrays kept whole. */
  function flatten(obj, prefix, out) {
    for (const [k, v] of Object.entries(obj)) {
      const key = prefix ? `${prefix}.${k}` : k;
      if (v !== null && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, out);
      else {
        const value = v === null ? 'null' : Array.isArray(v) ? JSON.stringify(v) : String(v);
        out.push({ key, value, quoted: typeof v === 'string', spaces: typeof v === 'string' && /\s/.test(v), group: 'body' });
      }
    }
    return out;
  }

  function commonSuffix(list) {
    const rev = list.map((s) => [...s].reverse().join(''));
    return [...U.commonPrefix(rev)].reverse().join('');
  }

  const json = {
    id: 'json',
    label: 'JSON',
    long: 'JSON objects (NDJSON, JSON after a syslog header or a text prefix)',

    detect(body) {
      const r = locate(body);
      if (!r) return 0;
      return r.prefix.trim() === '' ? 1 : 0.92;
    },

    configure() {
      return { mode: 'plugin' };
    },

    parse(body) {
      const r = locate(body);
      if (!r) return null;
      return { fields: flatten(r.obj, '', []), meta: { prefix: r.prefix } };
    },

    /**
     * Strategy for one root group:
     *   builtin: leave decoding to Wazuh's "json" decoder
     *   program: <program_name> root + JSON_Decoder
     *   prefix:  prematch eats the prefix, plugin offset="after_prematch"
     */
    prematch(items, options, programName) {
      const prefixes = items.map((it) => (it.parsed ? it.parsed.meta.prefix : ''));
      if (programName) {
        return { pattern: '^\\s*\\{', description: `JSON from program ${programName}`, strategy: 'program', plugin: { offset: null } };
      }
      if (prefixes.every((p) => p.trim() === '')) {
        return { pattern: null, description: 'handled by the built-in "json" decoder', strategy: 'builtin' };
      }
      const head = C.literalPrefix(prefixes);
      const tail = commonSuffix(prefixes);
      let pattern;
      if (prefixes.every((p) => p === prefixes[0])) {
        pattern = '^' + U.escapeRegex(prefixes[0]);
      } else if (tail && head.length + tail.length <= Math.min(...prefixes.map((p) => p.length))) {
        pattern = '^' + U.escapeRegex(head) + '[^{]*?' + U.escapeRegex(tail);
      } else {
        pattern = '^' + U.escapeRegex(head) + '[^{]*';
      }
      pattern += '(?=\\{)';
      return {
        pattern,
        description: `JSON after the prefix "${U.truncate(head || tail || '…', 30)}"`,
        strategy: 'prefix',
        plugin: { offset: 'after_prematch' },
      };
    },

    /** Regex mode: extract one key's value (leaf name) so it can be renamed. */
    fieldRegex(field, options, mode) {
      const leaf = field.key.split('.').pop();
      const key = `"${U.escapeRegex(leaf)}"\\s*:\\s*`;
      const typed = mode === 'strict' ? C.typedPattern(field.type) : null;
      // arrays of scalars: capture the whole [...] like the JSON plugin shows it
      if (field.samples.length && field.samples.every((s) => s.startsWith('['))) return key + '(\\[[^\\]]*\\])';
      if (field.quoting === 'always') return key + `"(${typed || C.quotedBody('"')})"`;
      if (field.quoting === 'never') return key + `(${typed || '[^,}\\]\\s]*'})`;
      return key + `(?|"(${C.quotedBody('"')})"|([^,}\\]\\s]*))`;
    },

    /** Constant key/value pairs usable as a rule discriminator. */
    discriminators(analysis) {
      return analysis.fields
        .filter((f) => f.presence === 1 && f.distinct === 1 && f.samples[0] !== '' && f.samples[0].length <= 64)
        .sort((a, b) => C.distinctiveness(b.key) - C.distinctiveness(a.key));
    },
  };

  W.formats.json = json;
});
