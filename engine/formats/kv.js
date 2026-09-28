/*
 * Key/Value logs: Fortinet, Sophos, Palo Alto (syslog KV), Check Point,
 * Barracuda, Zscaler NSS, auditd, and most "key=value" application logs.
 *
 * Auto-detects the pair separator (whitespace , ; | tab), the key/value
 * delimiter (= or :), quoting (" or ') and whether unquoted values may
 * contain spaces (then a value runs until the next "key=").
 */
WDG_MODULE(function (W) {
  'use strict';
  const U = W.util;
  const C = W.formatsCommon;

  const SEPARATORS = [' ', ',', ';', '|', '\t'];
  const KV_DELIMS = ['=', ':'];
  const KEY_RE = /[A-Za-z_@][\w.\-\[\]@\/]*/y;
  const GENERIC_PROGRAMS = new Set(['CEF', 'LEEF', 'date', 'time', 'id', 'msg', 'log', 'logver', 'kernel', 'devname', 'type']);

  const isSep = (ch, sep) => (sep === ' ' ? /\s/.test(ch) : ch === sep || ch === ' ');

  /** Scan one body. Returns {pairs, noise, prefix}. */
  function scan(body, sep, kvd) {
    const n = body.length;
    const pairs = [];
    let noise = 0;
    let prefixEnd = -1;
    let i = 0;
    while (i < n) {
      while (i < n && isSep(body[i], sep)) i++;
      if (i >= n) break;
      KEY_RE.lastIndex = i;
      const m = KEY_RE.exec(body);
      let j = m ? i + m[0].length : i;
      if (m && body[j] === kvd && !(kvd === ':' && body[j + 1] === '/' && body[j + 2] === '/')) {
        const key = m[0];
        j++;
        if (kvd === ':') while (body[j] === ' ') j++;
        let value = '';
        let quoted = false;
        const q = body[j];
        if (q === '"' || q === "'") {
          let k = j + 1;
          let v = '';
          while (k < n) {
            if (body[k] === '\\' && k + 1 < n) {
              v += body[k] + body[k + 1];
              k += 2;
              continue;
            }
            if (body[k] === q) {
              if (body[k + 1] === q) {
                v += q;
                k += 2;
                continue;
              }
              break;
            }
            v += body[k++];
          }
          if (k < n) {
            value = v;
            quoted = q;
            j = k + 1;
          } else {
            // unterminated quote: treat as unquoted
            let k2 = j;
            while (k2 < n && !isSep(body[k2], sep)) k2++;
            value = body.slice(j, k2);
            j = k2;
          }
        } else {
          let k = j;
          if (sep === ' ') while (k < n && !/\s/.test(body[k])) k++;
          else while (k < n && body[k] !== sep) k++;
          value = body.slice(j, k);
          if (sep !== ' ') value = value.trim();
          j = k;
        }
        pairs.push({ key, value, quoted, start: i, end: j });
        i = j;
      } else {
        // not a pair: skip one token
        let k = i;
        while (k < n && !isSep(body[k], sep)) k++;
        const tok = body.slice(i, k);
        if (pairs.length === 0) prefixEnd = k;
        else if (!quotedEnd(pairs) && sep === ' ') {
          // unquoted value containing spaces: glue the token back
          const last = pairs[pairs.length - 1];
          last.value += body.slice(last.end, k);
          last.end = k;
          last.spaces = true;
        } else noise++;
        i = k === i ? i + 1 : k;
      }
    }
    return { pairs, noise, prefix: prefixEnd > 0 ? body.slice(0, prefixEnd) : '' };
  }
  const quotedEnd = (pairs) => !!pairs[pairs.length - 1].quoted;

  /**
   * Prematch built from the first keys shared, in order, by every line:
   *   ^date=(value)\s+time=(value)\s+devname=
   * Returns null when fewer than two leading keys are common, or when the
   * lines do not start directly with a key.
   */
  function leadingKeys(items, options) {
    const o = Object.assign({ sep: ' ', kvd: '=', quote: '"' }, options);
    const parsed = items.map((it) => it.parsed).filter(Boolean);
    if (!parsed.length || parsed.some((p) => p.meta.prefix !== '')) return null;
    const seqs = parsed.map((p) => p.fields);
    const keys = [];
    for (let i = 0; i < 3; i++) {
      const k = seqs[0][i] && seqs[0][i].key;
      if (!k || !seqs.every((s) => s[i] && s[i].key === k)) break;
      keys.push(k);
      // a value that may hold unquoted spaces cannot be skipped reliably
      if (seqs.some((s) => !s[i].quoted && s[i].spaces)) break;
    }
    if (keys.length < 2) return null;
    const kvd = o.kvd === ':' ? ':\\s*' : U.escapeRegex(o.kvd);
    const q = U.escapeRegex(o.quote);
    const qc = U.escapeClassChar(o.quote);
    const value = o.sep === ' ' ? `(?:${q}(?:[^${qc}\\\\]|\\\\.)*${q}|\\S*)\\s+` : `(?:${q}(?:[^${qc}\\\\]|\\\\.)*${q}|[^${U.escapeClassChar(o.sep)}]*)${U.escapeRegex(o.sep)}\\s*`;
    const pattern = '^' + keys.map((k, i) => U.escapeRegex(k) + kvd + (i < keys.length - 1 ? value : '')).join('');
    return { pattern, description: `logs starting with ${keys.map((k) => k + o.kvd).join(' ')}` };
  }

  function bestConfig(bodies) {
    let best = null;
    for (const kvd of KV_DELIMS) {
      for (const sep of SEPARATORS) {
        let score = 0;
        const keysPerLine = [];
        for (const b of bodies) {
          const r = scan(b, sep, kvd);
          const good = r.pairs.filter((p) => p.key.length <= 64).length;
          score += good - r.noise * 0.75;
          keysPerLine.push(good);
        }
        // ':' matches timestamps and URLs too easily, so it needs clearly more pairs
        if (kvd === ':') score *= 0.8;
        if (sep !== ' ') score *= 0.97; // prefer whitespace on ties
        if (!best || score > best.score) best = { score, sep, kvd, keysPerLine };
      }
    }
    return best;
  }

  const kv = {
    id: 'kv',
    label: 'Key=Value',
    long: 'Generic key/value pairs (Fortinet, Sophos, Check Point, auditd...)',

    detect(body) {
      if (/^\s*[{[]/.test(body)) return 0;
      const r = scan(body, ' ', '=');
      const r2 = scan(body, ',', '=');
      const r3 = scan(body, ';', ':');
      const pairs = Math.max(r.pairs.length, r2.pairs.length, r3.pairs.length * 0.8);
      if (pairs < 2) return 0;
      return Math.min(0.85, 0.35 + 0.1 * pairs);
    },

    configure(items) {
      const bodies = items.map((it) => it.body);
      const best = bestConfig(bodies) || { sep: ' ', kvd: '=' };
      const quotes = [];
      for (const b of bodies) for (const p of scan(b, best.sep, best.kvd).pairs) if (p.quoted) quotes.push(p.quoted);
      return { sep: best.sep, kvd: best.kvd, quote: U.mode(quotes) || '"' };
    },

    parse(body, options) {
      const o = options || { sep: ' ', kvd: '=' };
      const r = scan(body, o.sep, o.kvd);
      if (!r.pairs.length) return null;
      const seen = new Set();
      const fields = [];
      for (const p of r.pairs) {
        if (seen.has(p.key)) continue; // first occurrence wins, like the regex
        seen.add(p.key);
        fields.push({ key: p.key, value: p.value, quoted: !!p.quoted, spaces: !!p.spaces || (!p.quoted && /\s/.test(p.value)), group: 'body' });
      }
      return { fields, meta: { prefix: r.prefix } };
    },

    prematch(items, options, programName) {
      if (programName && !GENERIC_PROGRAMS.has(programName)) {
        return { pattern: null, description: `program_name ${programName}` };
      }
      const bodies = items.map((it) => it.body);
      const kvdRaw = options.kvd || '=';

      // Preferred: anchor on the earliest fields. When every line starts
      // with the same keys in the same order ("date=… time=… devname=…"),
      // match them from the start of the line: precise, and a log from
      // another source is rejected on its very first characters.
      const early = leadingKeys(items, options);
      if (early) return early;

      let prefix = C.literalPrefix(bodies);
      // A prefix that is only the first key ("date=") is not a fingerprint.
      const prefixIsKey = new RegExp('^[\\w.\\-]+' + U.escapeRegex(kvdRaw) + '$').test(prefix);
      if (prefixIsKey) prefix = '';
      // Fingerprint: keys present in every line, most distinctive first,
      // emitted in their natural order.
      const parsed = items.map((it) => it.parsed).filter(Boolean);
      const first = parsed.length ? parsed[0].fields.map((f) => f.key) : [];
      const always = first.filter((k) => parsed.every((p) => p.fields.some((f) => f.key === k)) && !prefix.includes(k + kvdRaw));
      const chosen = always
        .slice()
        .sort((a, b) => C.distinctiveness(b) - C.distinctiveness(a))
        .slice(0, 2)
        .sort((a, b) => first.indexOf(a) - first.indexOf(b));
      const ordered = parsed.every((p) => {
        const keys = p.fields.map((f) => f.key);
        return chosen.length < 2 || keys.indexOf(chosen[0]) < keys.indexOf(chosen[1]);
      });
      const kvd = U.escapeRegex(kvdRaw);
      const keyParts = (ordered ? chosen : chosen.slice(0, 1)).map((k) => U.escapeRegex(k) + kvd);
      const hasPrefix = prefix.replace(/\W/g, '').length >= 3;
      if (!hasPrefix && !keyParts.length) return { pattern: null, description: 'none' };
      let pattern = hasPrefix ? '^' + U.escapeRegex(prefix) : '';
      keyParts.forEach((k, i) => {
        pattern += i === 0 && !hasPrefix ? C.KEY_BOUNDARY + k : '.*?[^\\w.\\-]' + k;
      });
      const desc = [hasPrefix ? `starting with "${U.truncate(prefix, 30)}"` : '', chosen.length ? `containing ${chosen.map((k) => k + kvdRaw).join(' … ')}` : ''].filter(Boolean).join(', ');
      return { pattern, description: `logs ${desc}` };
    },

    fieldRegex(field, options, mode) {
      const o = Object.assign({ sep: ' ', kvd: '=', quote: '"' }, options);
      const kvd = o.kvd === ':' ? ':\\s*' : U.escapeRegex(o.kvd);
      const key = C.KEY_BOUNDARY + U.escapeRegex(field.key) + kvd;
      let unquoted;
      if (o.sep === ' ') {
        unquoted = field.spaces ? `.*?(?=\\s+[\\w.\\-]+${kvd}|\\s*$)` : '\\S*';
      } else {
        unquoted = `[^${U.escapeClassChar(o.sep)}]*`;
      }
      const quoting = field.quoting || 'never';
      const typed = mode === 'strict' ? C.typedPattern(field.type) : null;
      return key + C.valueCapture({ quoting, quote: o.quote, unquoted, typed });
    },
  };

  W.formats.kv = kv;
  W.formats.kv._scan = scan;
});
