/*
 * CEF (ArcSight Common Event Format).
 *   CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
 * Header cells escape '|' and '\' with a backslash; extension values escape
 * '=' and '\' and may contain spaces (a value runs until the next " key=").
 */
WDG_MODULE(function (W) {
  'use strict';
  const U = W.util;
  const C = W.formatsCommon;

  const HEADER_KEYS = ['cef.version', 'cef.vendor', 'cef.product', 'cef.device_version', 'cef.signature_id', 'cef.name', 'cef.severity'];
  const HEADER_LABELS = ['Version', 'Device Vendor', 'Device Product', 'Device Version', 'Signature ID', 'Name', 'Severity'];
  const EXT_KEY = /(?:^|\s)([A-Za-z0-9_.\[\]-]+)=/g;
  // Custom-field slots whose meaning is carried by a companion "<slot>Label" key.
  const LABELLED = /^(?:c[sn]\d+|cfp\d+|c6a\d+|flexString\d+|flexNumber\d+|flexDate\d+|deviceCustomDate\d+|deviceCustomNumber\d+|deviceCustomString\d+)$/;

  /** Recover the CEF text even when the pre-decoder ate "CEF:" as program_name. */
  function cefText(body, pre) {
    if (pre && pre.program_name === 'CEF' && /^\d+\|/.test(body)) return 'CEF:' + body;
    const i = body.indexOf('CEF:');
    return i >= 0 ? body.slice(i) : null;
  }

  function splitHeader(s) {
    const cells = [];
    let cur = '';
    let i = 0;
    for (; i < s.length && cells.length < 7; i++) {
      const ch = s[i];
      if (ch === '\\' && i + 1 < s.length) {
        cur += ch + s[i + 1];
        i++;
      } else if (ch === '|') {
        cells.push(cur);
        cur = '';
      } else cur += ch;
    }
    if (cells.length < 7) return null;
    return { cells, extension: s.slice(i) };
  }

  const unescapeHeader = (v) => v.replace(/\\([|\\])/g, '$1');
  const unescapeExt = (v) => v.replace(/\\([=\\])/g, '$1').replace(/\\n/g, '\n').replace(/\\r/g, '\r');

  function parseExtension(ext) {
    const out = [];
    const marks = [];
    EXT_KEY.lastIndex = 0;
    let m;
    while ((m = EXT_KEY.exec(ext))) {
      marks.push({ key: m[1], keyStart: m.index + (m[0].length - m[1].length - 1), valStart: m.index + m[0].length });
    }
    for (let i = 0; i < marks.length; i++) {
      const end = i + 1 < marks.length ? marks[i + 1].keyStart : ext.length;
      const raw = ext.slice(marks[i].valStart, end).replace(/\s+$/, '');
      out.push({ key: marks[i].key, value: unescapeExt(raw), quoted: false, spaces: /\s/.test(raw) });
    }
    return out;
  }

  const cef = {
    id: 'cef',
    label: 'CEF',
    long: 'ArcSight Common Event Format',
    headerKeys: HEADER_KEYS,
    headerLabels: HEADER_LABELS,

    detect(body, pre) {
      const t = cefText(body, pre);
      if (!t) return 0;
      return splitHeader(t.slice(4)) ? 1 : 0.3;
    },

    configure() {
      return {};
    },

    parse(body, options, pre) {
      const t = cefText(body, pre);
      if (!t) return null;
      const h = splitHeader(t.slice(4));
      if (!h) return null;
      const fields = h.cells.map((v, i) => ({ key: HEADER_KEYS[i], value: unescapeHeader(v), group: 'header', quoted: false }));
      const ext = parseExtension(h.extension);
      const labels = {};
      for (const f of ext) {
        const lm = /^(.+)Label$/.exec(f.key);
        if (lm && LABELLED.test(lm[1])) labels[lm[1]] = f.value;
      }
      for (const f of ext) {
        f.group = 'body';
        if (labels[f.key]) f.label = labels[f.key];
        fields.push(f);
      }
      return { fields, meta: { vendor: fields[1].value, product: fields[2].value, rawVendor: h.cells[1], rawProduct: h.cells[2] } };
    },

    /**
     * Parent-decoder prematch for one root group.
     * With program_name "CEF" the body starts at the version ("0|Vendor|...").
     */
    prematch(items, options, programName) {
      const parsed = items.map((it) => it.parsed).filter(Boolean);
      const vendors = U.uniq(parsed.map((p) => p.meta.rawVendor));
      const products = U.uniq(parsed.map((p) => p.meta.rawProduct));
      let tail = '\\d+\\|';
      let desc = 'any CEF event';
      if (vendors.length === 1) {
        tail += U.escapeRegex(vendors[0]) + '\\|';
        desc = `CEF from ${vendors[0]}`;
        if (products.length === 1) {
          tail += U.escapeRegex(products[0]) + '\\|';
          desc += ` ${products[0]}`;
        }
      }
      if (programName === 'CEF') return { pattern: '^' + tail, description: desc };
      const anchored = items.every((it) => it.body.startsWith('CEF:'));
      return { pattern: (anchored ? '^' : '') + 'CEF:' + tail, description: desc };
    },

    fieldRegex(field, options, mode) {
      const key = U.escapeRegex(field.key);
      const typed = mode === 'strict' && !field.spaces ? C.typedPattern(field.type) : null;
      if (typed) return `(?:\\||\\s)${key}=(${typed})(?=\\s|$)`;
      // Grammar-driven (robust): the value runs until the next " key=" or the
      // end of the line, so values with spaces are never truncated.
      return `(?:\\||\\s)${key}=(.*?)(?=\\s+[\\w.\\[\\]-]+=|\\s*$)`;
    },

    /** One regex that captures the selected header cells. */
    headerRegex(selectedKeys) {
      const cell = '(?:[^|\\\\]|\\\\.)*';
      const parts = HEADER_KEYS.map((k, i) => {
        const body = i === 0 ? '\\d+' : cell;
        return selectedKeys.includes(k) ? `(${body})` : body;
      });
      return {
        pattern: '(?:^|CEF:)' + parts.join('\\|') + '\\|',
        keys: HEADER_KEYS.filter((k) => selectedKeys.includes(k)),
      };
    },
  };

  W.formats.cef = cef;
});
