/*
 * Single-line XML events (Windows events / Sysmon forwarded over syslog,
 * appliance XML exports...). Leaf element texts become "Path.To.Leaf",
 * attributes "Path.To.Element.attr", and Windows <Data Name="X">v</Data>
 * becomes "X".
 *
 * Generated patterns write '<' as \x3c, because Wazuh's XML reader would otherwise
 * take it as the start of a tag.
 */
WDG_MODULE(function (W) {
  'use strict';
  const U = W.util;
  const C = W.formatsCommon;

  const TAG = /<(\/?)([A-Za-z_][\w:.\-]*)((?:\s+[\w:.\-]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>|<!\[CDATA\[([\s\S]*?)\]\]>|<[!?][^>]*>|([^<]+)/g;
  const ATTR = /([\w:.\-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;

  function parseXml(text) {
    const out = [];
    const stack = [];
    const texts = [];
    TAG.lastIndex = 0;
    let m;
    let sawTag = false;
    while ((m = TAG.exec(text))) {
      const [, close, name, attrs, selfClose, cdata, txt] = m;
      if (name) {
        sawTag = true;
        if (close) {
          const top = stack.pop();
          const t = texts.pop();
          if (!top) return null;
          if (top.leaf && t && t.trim() !== '') push(out, top, t.trim());
          else if (top.leaf && top.dataName) push(out, top, '');
          continue;
        }
        const node = { name, path: [...stack.map((s) => s.name), name].join('.'), leaf: true, dataName: null };
        if (stack.length) stack[stack.length - 1].leaf = false;
        ATTR.lastIndex = 0;
        let a;
        while ((a = ATTR.exec(attrs || ''))) {
          const val = a[2] !== undefined ? a[2] : a[3];
          if (name === 'Data' && a[1] === 'Name') node.dataName = val;
          else out.push({ key: `${node.path}.${a[1]}`, value: val, group: 'body', quoted: true, spaces: /\s/.test(val), hint: { tag: name, attr: a[1] } });
        }
        if (selfClose) continue;
        stack.push(node);
        texts.push('');
      } else if (cdata !== undefined || txt !== undefined) {
        if (texts.length) texts[texts.length - 1] += cdata !== undefined ? cdata : txt;
      }
    }
    return sawTag ? out : null;
  }

  function push(out, node, value) {
    if (node.dataName) out.push({ key: node.dataName, value, group: 'body', quoted: false, spaces: /\s/.test(value), hint: { tag: 'Data', dataName: node.dataName } });
    else out.push({ key: node.path, value, group: 'body', quoted: false, spaces: /\s/.test(value), hint: { tag: node.name } });
  }

  const xml = {
    id: 'xml',
    label: 'XML',
    long: 'Single-line XML events (Windows / Sysmon over syslog, appliance exports)',

    detect(body) {
      const i = body.indexOf('<');
      if (i < 0 || !/<\/[A-Za-z]/.test(body)) return 0;
      const r = parseXml(body.slice(i));
      if (!r || !r.length) return 0;
      return i === 0 ? 0.95 : 0.8;
    },

    configure() {
      return {};
    },

    parse(body) {
      const i = body.indexOf('<');
      if (i < 0) return null;
      const fields = parseXml(body.slice(i));
      if (!fields) return null;
      const seen = new Set();
      return { fields: fields.filter((f) => (seen.has(f.key) ? false : seen.add(f.key))), meta: { prefix: body.slice(0, i) } };
    },

    prematch(items) {
      const bodies = items.map((it) => it.body);
      const prefix = C.literalPrefix(bodies);
      if (prefix.replace(/\W/g, '').length >= 3) return { pattern: '^' + U.escapeRegex(prefix), description: `lines starting with "${U.truncate(prefix, 40)}"` };
      const root = /<([A-Za-z_][\w:.\-]*)/.exec(bodies[0] || '');
      return root
        ? { pattern: `\\x3c${U.escapeRegex(root[1])}[\\s\\x3e]`, description: `XML <${root[1]}> events` }
        : { pattern: null, description: 'none' };
    },

    fieldRegex(field, options, mode) {
      const h = field.hint || {};
      const typed = mode === 'strict' ? C.typedPattern(field.type) : null;
      const val = typed || '[^\\x3c]*';
      if (h.dataName) return `\\x3cData\\s[^\\x3e]*?Name=["']${U.escapeRegex(h.dataName)}["'][^\\x3e]*\\x3e(${val})`;
      if (h.attr) return `\\x3c${U.escapeRegex(h.tag)}\\s[^\\x3e]*?\\b${U.escapeRegex(h.attr)}=["']([^"']*)["']`;
      return `\\x3c${U.escapeRegex(h.tag || field.key.split('.').pop())}(?:\\s[^\\x3e]*)?\\x3e(${val})\\x3c/`;
    },
  };

  W.formats.xml = xml;
});
