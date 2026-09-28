/*
 * Delimited logs: CSV / TSV / semicolon / pipe (Palo Alto CSV syslog, Squid
 * custom formats, database audit exports...).
 *
 * Fields are positional. Each selected column gets its own sibling decoder
 * that skips the preceding N cells, so a missing trailing column only loses
 * that column, and no regex comes close to Wazuh's 1024-char limit.
 */
WDG_MODULE(function (W) {
  'use strict';
  const U = W.util;
  const C = W.formatsCommon;

  const DELIMS = [',', ';', '\t', '|'];

  /** Quote-aware split. Returns [{value, quoted}]. */
  function splitCells(line, d) {
    const cells = [];
    let i = 0;
    const n = line.length;
    while (i <= n) {
      if (line[i] === '"') {
        let v = '';
        let k = i + 1;
        while (k < n) {
          if (line[k] === '"' && line[k + 1] === '"') {
            v += '"';
            k += 2;
          } else if (line[k] === '"') break;
          else v += line[k++];
        }
        if (k < n && (line[k + 1] === d || k + 1 === n)) {
          cells.push({ value: v, quoted: true });
          i = k + 2;
          continue;
        }
      }
      let k = line.indexOf(d, i);
      if (k < 0) k = n;
      cells.push({ value: line.slice(i, k), quoted: false });
      i = k + 1;
    }
    return cells;
  }

  const looksLikeHeader = (cells) =>
    cells.length >= 3 && cells.every((c) => /^[A-Za-z_][\w .()\/-]{0,40}$/.test(c.value.trim())) && new Set(cells.map((c) => c.value)).size === cells.length;

  const csv = {
    id: 'csv',
    label: 'Delimited / CSV',
    long: 'Positional CSV, TSV, semicolon or pipe separated logs',

    detect(body) {
      if (/^\s*[{<]/.test(body) || /(?:^|\|)(?:CEF|LEEF):/.test(body)) return 0;
      let best = 0;
      for (const d of DELIMS) {
        const cells = splitCells(body, d);
        if (cells.length < 4) continue;
        const eq = cells.filter((c) => /^[\w.-]+=/.test(c.value)).length;
        if (eq > cells.length / 3) continue; // that's key=value
        // A quote in the middle of an unquoted cell means the delimiter sits
        // inside quoted text (e.g. "Windows NT 6.1; Win64" in a user agent):
        // this is not a well-formed delimited line.
        if (cells.some((c) => !c.quoted && c.value.includes('"'))) continue;
        best = Math.max(best, Math.min(0.8, 0.3 + cells.length * 0.02));
      }
      return best;
    },

    configure(items) {
      const bodies = items.map((it) => it.body);
      let best = null;
      for (const d of DELIMS) {
        const counts = bodies.map((b) => {
          const cells = splitCells(b, d);
          return cells.some((c) => !c.quoted && c.value.includes('"')) ? 0 : cells.length;
        });
        const m = U.mode(counts);
        const share = counts.filter((c) => c === m).length / counts.length;
        const score = m >= 3 ? share * Math.log(m) : 0;
        if (!best || score > best.score) best = { d, score, columns: Math.max(...counts) };
      }
      const d = best ? best.d : ',';
      const first = splitCells(bodies[0] || '', d);
      let header = null;
      if (bodies.length > 1 && looksLikeHeader(first)) {
        const second = splitCells(bodies[1], d);
        const differs = second.some((c, i) => first[i] && c.value !== first[i].value && !looksLikeHeader([c, c, c]));
        if (differs) header = first.map((c) => c.value.trim());
      }
      const anyQuoted = bodies.some((b) => splitCells(b, d).some((c) => c.quoted));
      return { delimiter: d, header, headerLine: header ? bodies[0] : null, columns: best ? best.columns : first.length, anyQuoted };
    },

    parse(body, options) {
      const d = options.delimiter || ',';
      if (options.headerLine && body === options.headerLine) return { fields: [], meta: { isHeader: true } };
      const cells = splitCells(body, d);
      if (cells.length < 2) return null;
      const fields = cells.map((c, i) => {
        const name = options.header && options.header[i] ? U.sanitizeFieldName(options.header[i]) : `col_${i + 1}`;
        return { key: name, value: c.value, quoted: c.quoted, spaces: /\s/.test(c.value), group: 'body', hint: { index: i } };
      });
      return { fields, meta: { columns: cells.length } };
    },

    prematch(items, options, programName) {
      const bodies = items.map((it) => it.body).filter((b) => b !== options.headerLine);
      if (programName && !['CEF', 'LEEF'].includes(programName)) return { pattern: null, description: `program_name ${programName}` };
      const d = options.delimiter || ',';
      const D = U.escapeRegex(d);
      const cell = `(?:"(?:[^"]|"")*"|[^${U.escapeClassChar(d)}"]*)`;
      const prefix = C.literalPrefix(bodies);
      if (prefix.replace(/\W/g, '').length >= 3) return { pattern: '^' + U.escapeRegex(prefix), description: `lines starting with "${U.truncate(prefix, 40)}"` };
      // A constant, alphabetic column is a great fingerprint (e.g. PAN-OS "TRAFFIC").
      const rows = bodies.map((b) => splitCells(b, d));
      const width = Math.min(...rows.map((r) => r.length));
      for (let i = 0; i < Math.min(width, 12); i++) {
        const v = rows[0][i].value;
        if (/^[A-Za-z][\w-]{2,}$/.test(v) && rows.every((r) => r[i].value === v)) {
          const skip = i ? `(?:${cell}${D}){${i}}` : '';
          return { pattern: `^${skip}${U.escapeRegex(v)}(?:${D}|$)`, description: `column ${i + 1} = "${v}"` };
        }
      }
      return { pattern: `^(?:${cell}${D}){${Math.max(1, width - 1)}}`, description: `lines with at least ${width} columns` };
    },

    fieldRegex(field, options, mode) {
      const d = options.delimiter || ',';
      const D = U.escapeRegex(d);
      const dc = U.escapeClassChar(d);
      const i = field.hint ? field.hint.index : 0;
      const cell = field.anyQuoted || options.anyQuoted ? `(?:"(?:[^"]|"")*"|[^${dc}"]*)` : `[^${dc}]*`;
      const skip = i === 0 ? '' : i === 1 ? `${cell}${D}` : `(?:${cell}${D}){${i}}`;
      const typed = mode === 'strict' ? C.typedPattern(field.type) : null;
      let cap;
      if (field.quoting === 'always') cap = `"(${typed || '(?:[^"]|"")*'})"`;
      else if (field.quoting === 'mixed') cap = `(?|"((?:[^"]|"")*)"|([^${dc}"]*))`;
      else cap = `(${typed || `[^${dc}]*`})`;
      return `^${skip}${cap}`;
    },
  };

  W.formats.csv = csv;
  W.formats.csv._split = splitCells;
});
