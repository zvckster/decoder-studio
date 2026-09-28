/*
 * Companion rules. A decoder alone never raises an alert: this produces a
 * ready-to-tune local rules file.
 *
 *   base rule         <decoded_as> (or the built-in json decoder + a
 *                     discriminator field), groups every event of the source
 *   event-ID rules    one per event/signature ID seen in the samples, labelled
 *                     with the event name found next to it (CEF "Name"...),
 *                     level derived from the severity seen for that ID
 *   severity rules    fallback tiers for IDs not seen in the samples
 *
 * Custom rule IDs must live in 100000-120000.
 */
WDG_MODULE(function (W) {
  'use strict';
  const U = W.util;

  const DEFAULTS = { baseId: 100100, baseLevel: 3, eventRules: true, severityRules: true, maxEventRules: 40 };
  const STATIC_RULE_TAG = { srcip: 'srcip', dstip: 'dstip', srcport: 'srcport', dstport: 'dstport', protocol: 'protocol', action: 'action', id: 'id', url: 'url', status: 'status', srcuser: 'srcuser', dstuser: 'dstuser', user: 'user', system_name: 'system_name', data: 'data', extra_data: 'extra_data' };

  const WORD_TIERS = [
    { re: '(?i)^(?:debug|info|informational|notice|low|minor|0|1|2|3)$', level: 3, label: 'low' },
    { re: '(?i)^(?:warn|warning|medium|moderate|4|5|6)$', level: 6, label: 'medium' },
    { re: '(?i)^(?:err|error|high|major|7|8)$', level: 10, label: 'high' },
    { re: '(?i)^(?:crit|critical|alert|emerg|emergency|fatal|severe|very-high|9|10)$', level: 12, label: 'critical' },
  ];

  function tierOf(value) {
    const v = String(value).trim();
    for (const t of WORD_TIERS) if (new RegExp(t.re.replace('(?i)', ''), 'i').test(v)) return t;
    return null;
  }

  /**
   * XML for "field equals value". Static fields use their own rule option,
   * which is OS_Match (^ and $ anchors, no escaping); dynamic fields use
   * <field> with PCRE2.
   */
  const JSON_RULE_TAG = { srcip: 'srcip', dstip: 'dstip', srcport: 'srcport', dstport: 'dstport', protocol: 'protocol', action: 'action', srcuser: 'srcuser', dstuser: 'dstuser', id: 'id', status: 'status', url: 'url', data: 'data', extra_data: 'extra_data', systemname: 'system_name' };
  let TAGS = STATIC_RULE_TAG;

  function equals(field, value) {
    const tag = TAGS[field];
    if (tag) return `<${tag}>^${value}$</${tag}>`;
    return `<field name="${U.xmlAttr(field)}" type="pcre2">^${U.escapeRegex(value)}$</field>`;
  }
  function matches(field, pcre) {
    if (TAGS[field]) return null;
    return `<field name="${U.xmlAttr(field)}" type="pcre2">${pcre}</field>`;
  }

  function pickField(analysis, concept) {
    return analysis.fields.find((f) => f.selected && f.name && W.fieldmap.conceptOf(f.key) === concept) || null;
  }

  /**
   * @param analysis  output of analyze()
   * @param model     output of generate()
   * @param options   see DEFAULTS
   */
  function generateRules(analysis, model, options) {
    const o = Object.assign({}, DEFAULTS, options);
    const name = model.name;
    const lines = [];
    const rules = [];
    let id = o.baseId;
    const baseId = id++;

    const builtin = model.builtinJson;
    // JSON_Decoder fills static fields only for its own key list
    TAGS = analysis.format === 'json' && !model.decoders.some((d) => d.regex) ? JSON_RULE_TAG : STATIC_RULE_TAG;
    const base = [`  <rule id="${baseId}" level="${o.baseLevel}">`];
    if (builtin) {
      base.push('    <decoded_as>json</decoded_as>');
      const disc = W.formats.json.discriminators(analysis).slice(0, 2);
      for (const f of disc) base.push(`    ${equals(f.key, f.samples[0])}`);
      if (!disc.length) base.push('    <!-- TODO: add a <field name="..."> that identifies this source -->');
    } else {
      base.push(`    <decoded_as>${name}</decoded_as>`);
    }
    base.push(`    <description>${name}: event received</description>`);
    base.push('  </rule>');
    rules.push(base.join('\n'));

    const lf = (f) => (TAGS === JSON_RULE_TAG ? f.key : f.name);
    const sev = pickField(analysis, 'severity');
    const evt = pickField(analysis, 'event_id');
    const msg = pickField(analysis, 'message');
    // label event-ID rules with the event's name (CEF "Name"...) when there is one
    const label = pickField(analysis, 'event_name') || msg;

    // Event-ID rules
    if (o.eventRules && evt && evt.distinct <= o.maxEventRules) {
      const byId = new Map();
      for (const it of analysis.lines) {
        if (!it.ok || !it.parsed) continue;
        const get = (k) => {
          const f = it.parsed.fields.find((x) => x.key === k) || (it.envelope && it.envelope.fields.find((x) => x.key === k));
          return f ? f.value : undefined;
        };
        const v = get(evt.key);
        if (v === undefined || v === '') continue;
        if (!byId.has(v)) byId.set(v, { names: [], sev: [] });
        const e = byId.get(v);
        if (label) {
          const m = get(label.key);
          if (m) e.names.push(m);
        }
        if (sev) {
          const s = get(sev.key);
          if (s !== undefined) e.sev.push(s);
        }
      }
      for (const [value, e] of byId) {
        const tiers = e.sev.map(tierOf).filter(Boolean);
        const level = tiers.length ? Math.max(...tiers.map((t) => t.level)) : o.baseLevel;
        const text = e.names.length ? U.mode(e.names) : `event ${value}`;
        rules.push(
          [
            `  <rule id="${id++}" level="${level}">`,
            `    <if_sid>${baseId}</if_sid>`,
            `    ${equals(lf(evt), value)}`,
            `    <description>${name}: ${xmlText(U.truncate(text, 120))}</description>`,
            '  </rule>',
          ].join('\n')
        );
      }
    }

    // Severity fallback tiers
    if (o.severityRules && sev && matches(lf(sev), '')) {
      for (const t of WORD_TIERS) {
        rules.push(
          [
            `  <rule id="${id++}" level="${t.level}">`,
            `    <if_sid>${baseId}</if_sid>`,
            `    ${matches(lf(sev), t.re)}`,
            `    <description>${name}: ${t.label} severity event${msg ? ' - $(' + lf(msg) + ')' : ''}</description>`,
            '  </rule>',
          ].join('\n')
        );
      }
    }

    lines.push('<!--');
    lines.push(`  Rules for ${name}, generated by Decoder Studio ${W.version}`);
    lines.push(`  Install: /var/ossec/etc/rules/${name}_rules.xml, then restart wazuh-manager`);
    lines.push('  Custom rule IDs must stay within 100000-120000; adjust the base ID if it collides.');
    if (evt && o.eventRules) lines.push('  Event-ID rules come first: Wazuh evaluates child rules in file order.');
    lines.push('-->');
    lines.push('');
    lines.push(`<group name="${U.xmlAttr(name)},">`);
    lines.push('');
    lines.push(rules.join('\n\n'));
    lines.push('');
    lines.push('</group>');
    return { xml: lines.join('\n') + '\n', count: rules.length, lastId: id - 1 };
  }

  const xmlText = (s) => String(s).replace(/</g, '(').replace(/>/g, ')').replace(/&/g, 'and');

  W.generateRules = generateRules;
  W.rules = { generateRules, DEFAULTS, tierOf };
});
