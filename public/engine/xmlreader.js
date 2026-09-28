/*
 * Reads a Wazuh decoder file the way os_xml + decode-xml.c do:
 *   - no XML entity decoding (&lt; stays "&lt;")
 *   - a '<' preceded by an odd number of backslashes is content ("\<")
 *   - comments and <?xml ?> declarations are skipped
 *   - <var name="X">v</var> defines $X, substituted in element contents
 *   - repeated <regex>/<prematch> elements are concatenated
 * Produces the same decoder model the generator emits, so user-written or
 * hand-edited decoders can be tested in the simulator.
 */
WDG_MODULE(function (W) {
  'use strict';

  function parse(text) {
    let i = 0;
    const n = text.length;
    const errors = [];

    function skipMisc() {
      for (;;) {
        while (i < n && /\s/.test(text[i])) i++;
        if (text.startsWith('<!--', i)) {
          const j = text.indexOf('-->', i + 4);
          if (j < 0) {
            errors.push('Comment not closed.');
            i = n;
            return;
          }
          i = j + 3;
        } else if (text.startsWith('<?', i) || text.startsWith('<!', i)) {
          const j = text.indexOf('>', i);
          i = j < 0 ? n : j + 1;
        } else return;
      }
    }

    function element() {
      // at '<'
      const m = /^<([A-Za-z_][\w:.\-]*)((?:\s+[\w:.\-]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>/.exec(text.slice(i, i + 4096));
      if (!m) {
        errors.push(`Malformed tag near: ${text.slice(i, i + 40)}`);
        i = n;
        return null;
      }
      const node = { name: m[1], attrs: {}, content: '', children: [] };
      const ar = /([\w:.\-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
      let a;
      while ((a = ar.exec(m[2]))) node.attrs[a[1]] = a[2] !== undefined ? a[2] : a[3];
      i += m[0].length;
      if (m[3]) return node;
      let content = '';
      let bs = 0;
      while (i < n) {
        const ch = text[i];
        if (ch === '<' && bs % 2 === 0) {
          if (text.startsWith('<!--', i)) {
            const j = text.indexOf('-->', i + 4);
            i = j < 0 ? n : j + 3;
            continue;
          }
          if (text[i + 1] === '/') {
            const j = text.indexOf('>', i);
            const closing = text.slice(i + 2, j).trim();
            if (closing !== node.name) errors.push(`Element '${node.name}' not closed (found </${closing}>).`);
            i = j + 1;
            node.content = content;
            return node;
          }
          const child = element();
          if (child) node.children.push(child);
          bs = 0;
          continue;
        }
        bs = ch === '\\' ? bs + 1 : 0;
        content += ch;
        i++;
      }
      errors.push(`Element '${node.name}' not closed.`);
      node.content = content;
      return node;
    }

    const nodes = [];
    while (i < n) {
      skipMisc();
      if (i >= n) break;
      if (text[i] !== '<') {
        const j = text.indexOf('<', i);
        errors.push(`Unexpected text outside elements: "${text.slice(i, j < 0 ? n : j).trim().slice(0, 40)}"`);
        i = j < 0 ? n : j;
        continue;
      }
      const el = element();
      if (el) nodes.push(el);
    }
    return { nodes, errors };
  }

  /** Parse a decoder file into the decoder model. */
  function readDecoders(text) {
    const { nodes, errors } = parse(text);
    const vars = {};
    const decoders = [];
    const warnings = [];
    const flat = [];
    for (const nd of nodes) {
      if (nd.name === 'decoder' || nd.name === 'var') flat.push(nd);
      else if (nd.children.length) flat.push(...nd.children.filter((c) => c.name === 'decoder' || c.name === 'var'));
    }
    const sub = (s) => s.replace(/\$([A-Za-z_]\w*)/g, (m, k) => (vars[k] !== undefined ? vars[k] : m));

    for (const nd of flat) {
      if (nd.name === 'var') {
        if (nd.attrs.name) vars[nd.attrs.name] = nd.content;
        continue;
      }
      const d = { name: nd.attrs.name || '', source: 'xml' };
      if (!d.name) errors.push('A <decoder> has no name attribute.');
      for (const c of nd.children) {
        const v = sub(c.content);
        switch (c.name) {
          case 'parent':
            d.parent = v.trim();
            break;
          case 'program_name':
            d.programName = { value: (d.programName ? d.programName.value : '') + v, type: c.attrs.type || (d.programName && d.programName.type) || null };
            break;
          case 'prematch':
            d.prematch = { value: (d.prematch ? d.prematch.value : '') + v, type: c.attrs.type || (d.prematch && d.prematch.type) || null, offset: c.attrs.offset || (d.prematch && d.prematch.offset) || null };
            break;
          case 'regex':
            d.regex = { value: (d.regex ? d.regex.value : '') + v, type: c.attrs.type || (d.regex && d.regex.type) || null, offset: c.attrs.offset || (d.regex && d.regex.offset) || null };
            break;
          case 'order':
            d.order = v.split(',').map((x) => x.trim().split(' ')[0]).filter(Boolean);
            break;
          case 'plugin_decoder':
            d.plugin = { name: v.trim(), offset: c.attrs.offset || null };
            break;
          case 'use_own_name':
            d.useOwnName = v.trim() === 'true';
            break;
          case 'type':
          case 'fts':
          case 'ftscomment':
          case 'accumulate':
          case 'json_null_field':
          case 'json_array_structure':
          case 'var':
            break;
          default:
            warnings.push(`Unknown element <${c.name}> in decoder "${d.name}".`);
        }
      }
      decoders.push(d);
    }
    return { decoders, errors, warnings };
  }

  W.xmlreader = { parse, readDecoders };
});
