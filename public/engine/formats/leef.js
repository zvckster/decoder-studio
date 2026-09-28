/*
 * LEEF (IBM QRadar Log Event Extended Format).
 *   LEEF:1.0|Vendor|Product|Version|EventID|key=value<TAB>key=value
 *   LEEF:2.0|Vendor|Product|Version|EventID|DelimiterChar|key=value^key=value
 * The 2.0 delimiter may be a character ("^"), hex ("x5E" / "0x5E") or be
 * omitted by non-compliant senders. Some senders also write a literal "\t"
 * instead of a real tab. Both are handled.
 */
WDG_MODULE(function (W) {
  'use strict';
  const U = W.util;
  const C = W.formatsCommon;

  const HEADER_KEYS = ['leef.version', 'leef.vendor', 'leef.product', 'leef.product_version', 'leef.event_id'];
  const HEADER_LABELS = ['LEEF Version', 'Vendor', 'Product', 'Product Version', 'Event ID'];

  function leefText(body, pre) {
    if (pre && pre.program_name === 'LEEF' && /^[12](?:\.\d+)?\|/.test(body)) return 'LEEF:' + body;
    const i = body.indexOf('LEEF:');
    return i >= 0 ? body.slice(i) : null;
  }

  function parseDelimiter(spec) {
    if (spec === undefined || spec === null) return null;
    const s = spec.trim();
    if (s === '' && spec.length === 1) return spec; // a real tab / space
    if (/^(?:0?x)[0-9A-Fa-f]{2,4}$/i.test(s)) return String.fromCharCode(parseInt(s.replace(/^0?x/i, ''), 16));
    if (s === '\\t') return '\t';
    if (s.length === 1) return s;
    return null;
  }

  /** Split a LEEF line into header cells, delimiter and attribute text. */
  function split(text) {
    const s = text.slice(5);
    const cells = [];
    let cur = '';
    let i = 0;
    for (; i < s.length && cells.length < 5; i++) {
      const ch = s[i];
      if (ch === '\\' && s[i + 1] === '|') {
        cur += '|';
        i++;
      } else if (ch === '|') {
        cells.push(cur);
        cur = '';
      } else cur += ch;
    }
    if (cells.length < 5) return null;
    let rest = s.slice(i);
    let delimiter = '\t';
    let delimiterSpec = null;
    if (/^2/.test(cells[0])) {
      const bar = rest.indexOf('|');
      if (bar >= 0 && bar <= 6 && !rest.slice(0, bar).includes('=')) {
        const d = parseDelimiter(rest.slice(0, bar));
        if (d !== null) {
          delimiter = d;
          delimiterSpec = rest.slice(0, bar);
          rest = rest.slice(bar + 1);
        }
      }
    }
    // Literal "\t" (backslash + t) used as a separator by some senders
    if (delimiter === '\t' && !rest.includes('\t') && /\\t[\w.-]+=/.test(rest)) delimiter = '\\t';
    return { cells, delimiter, delimiterSpec, attrs: rest };
  }

  function delimiterRegex(d) {
    return U.escapeRegex(d);
  }

  const leef = {
    id: 'leef',
    label: 'LEEF',
    long: 'IBM QRadar Log Event Extended Format',
    headerKeys: HEADER_KEYS,
    headerLabels: HEADER_LABELS,

    detect(body, pre) {
      const t = leefText(body, pre);
      if (!t) return 0;
      return split(t) ? 1 : 0.3;
    },

    configure(items) {
      const delims = [];
      for (const it of items) {
        const t = leefText(it.body, it.pre);
        const sp = t && split(t);
        if (sp) delims.push(sp.delimiter);
      }
      return { delimiter: U.mode(delims) || '\t' };
    },

    parse(body, options, pre) {
      const t = leefText(body, pre);
      if (!t) return null;
      const sp = split(t);
      if (!sp) return null;
      const fields = sp.cells.map((v, i) => ({ key: HEADER_KEYS[i], value: v, group: 'header', quoted: false }));
      for (const piece of sp.attrs.split(sp.delimiter)) {
        const eq = piece.indexOf('=');
        if (eq <= 0) continue;
        const key = piece.slice(0, eq).trim();
        if (!/^[\w.\-\[\]:]+$/.test(key)) continue;
        const value = piece.slice(eq + 1);
        fields.push({ key, value, group: 'body', quoted: false, spaces: /\s/.test(value) });
      }
      return { fields, meta: { vendor: sp.cells[1], product: sp.cells[2], delimiter: sp.delimiter } };
    },

    prematch(items, options, programName) {
      const parsed = items.map((it) => it.parsed).filter(Boolean);
      const vendors = U.uniq(parsed.map((p) => p.meta.vendor));
      const products = U.uniq(parsed.map((p) => p.meta.product));
      let tail = '[\\d.]+\\|';
      let desc = 'any LEEF event';
      if (vendors.length === 1) {
        tail += U.escapeRegex(vendors[0]) + '\\|';
        desc = `LEEF from ${vendors[0]}`;
        if (products.length === 1) {
          tail += U.escapeRegex(products[0]) + '\\|';
          desc += ` ${products[0]}`;
        }
      }
      if (programName === 'LEEF') return { pattern: '^' + tail, description: desc };
      const anchored = items.every((it) => it.body.startsWith('LEEF:'));
      return { pattern: (anchored ? '^' : '') + 'LEEF:' + tail, description: desc };
    },

    fieldRegex(field, options, mode) {
      const d = options.delimiter || '\t';
      const D = delimiterRegex(d);
      const key = U.escapeRegex(field.key);
      // A value can never contain the delimiter (LEEF spec).
      const until = d.length === 1 ? `[^${U.escapeClassChar(d)}]*` : `(?:(?!${D}).)*`;
      const typed = mode === 'strict' ? C.typedPattern(field.type) : null;
      if (typed) return `(?:${D}|\\|)${key}=(${typed})(?=${D}|$)`;
      return `(?:${D}|\\|)${key}=(${until})`;
    },

    headerRegex(selectedKeys) {
      const cell = '[^|]*';
      const parts = HEADER_KEYS.map((k, i) => {
        const body = i === 0 ? '[\\d.]+' : cell;
        return selectedKeys.includes(k) ? `(${body})` : body;
      });
      return {
        pattern: '(?:^|LEEF:)' + parts.join('\\|') + '\\|',
        keys: HEADER_KEYS.filter((k) => selectedKeys.includes(k)),
      };
    },
  };

  W.formats.leef = leef;
});
