/*
 * Field naming. Maps vendor keys (CEF dictionary, LEEF attributes, Fortinet,
 * Palo Alto, Check Point, Windows, common JSON...) to a canonical concept,
 * then to a name in the chosen naming scheme:
 *
 *   wazuh    : Wazuh static fields where one exists (srcip, dstip, srcport,
 *              srcuser, action, id, url, status, protocol...). Static fields
 *              unlock <srcip>/<user> rule options, GeoIP enrichment of srcip,
 *              active response and the built-in dashboards. Recommended.
 *   ecs      : Elastic Common Schema-style dotted dynamic fields.
 *   original : keep the vendor key as-is.
 */
WDG_MODULE(function (W) {
  'use strict';

  // The static fields analysisd understands in <order> (decode-xml.c).
  const STATIC_FIELDS = ['srcuser', 'dstuser', 'user', 'srcip', 'dstip', 'srcport', 'dstport', 'protocol', 'action', 'id', 'url', 'data', 'extra_data', 'status', 'system_name'];

  // concept: [wazuh name, ecs name, ...aliases (case-insensitive)]
  const CONCEPTS = {
    src_ip: ['srcip', 'source.ip', 'src', 'srcip', 'src_ip', 'sourceip', 'source_ip', 'sourceaddress', 'source_address', 'sip', 'clientip', 'client_ip', 'c-ip', 'ipaddress', 'ip_address', 'remote_addr', 'remoteip', 'remote_ip', 'callingstationid', 'identsrc', 'client_addr', 'saddr', 'orig_h', 'id.orig_h'],
    dst_ip: ['dstip', 'destination.ip', 'dst', 'dstip', 'dst_ip', 'dest_ip', 'destip', 'destinationip', 'destination_ip', 'destinationaddress', 'destination_address', 'dip', 'serverip', 'server_ip', 's-ip', 'daddr', 'resp_h', 'id.resp_h'],
    src_port: ['srcport', 'source.port', 'spt', 'srcport', 'src_port', 'sport', 'sourceport', 'source_port', 's_port', 'clientport', 'client_port', 'ipport', 'orig_p', 'id.orig_p'],
    dst_port: ['dstport', 'destination.port', 'dpt', 'dstport', 'dst_port', 'dport', 'destport', 'dest_port', 'destinationport', 'destination_port', 'serverport', 'server_port', 's-port', 'resp_p', 'id.resp_p'],
    protocol: ['protocol', 'network.transport', 'proto', 'protocol', 'transport', 'ipprotocol', 'ip_protocol', 'protocolname'],
    action: ['action', 'event.action', 'act', 'action', 'deviceaction', 'fw_action', 'disposition', 'verdict'],
    outcome: ['status', 'event.outcome', 'outcome', 'status', 'result', 'eventoutcome'],
    src_user: ['srcuser', 'source.user.name', 'suser', 'srcuser', 'src_user', 'sourceuser', 'sourceusername', 'source_user', 'subjectusername', 'accountname', 'usrname', 'identhostname_user'],
    dst_user: ['dstuser', 'destination.user.name', 'duser', 'dstuser', 'dst_user', 'destinationuser', 'destinationusername', 'targetusername', 'target_user', 'user', 'username', 'user_name', 'login', 'account', 'cs-username'],
    event_id: ['id', 'event.code', 'eventid', 'event_id', 'logid', 'log_id', 'signatureid', 'signature_id', 'sid', 'ruleid', 'rule_id', 'msgid', 'messageid', 'externalid'],
    url: ['url', 'url.original', 'url', 'request', 'requesturl', 'request_url', 'uri', 'cs-uri', 'cs-uri-stem', 'fullurl'],
    hostname: ['system_name', 'host.name', 'dvchost', 'devname', 'device_name', 'devicename', 'hostname', 'host', 'computer', 'computername', 'workstationname', 'system'],
    event_name: ['event_name', 'event.reason', 'eventname', 'event_name', 'signature', 'signature_name', 'rulename_desc'],
    message: ['message', 'message', 'msg', 'message', 'description', 'desc', 'reason', 'logdesc'],
    severity: ['severity', 'event.severity', 'sev', 'severity', 'level', 'priority', 'pri', 'loglevel', 'log_level', 'risk', 'risklevel'],
    category: ['category', 'event.category', 'cat', 'category', 'type', 'eventtype', 'event_type', 'subtype', 'logtype'],
    src_host: ['srchost', 'source.domain', 'shost', 'srchost', 'src_host', 'sourcehostname', 'srcname', 'src_hostname', 'workstation'],
    dst_host: ['dsthost', 'destination.domain', 'dhost', 'dsthost', 'dst_host', 'destinationhostname', 'dstname', 'dst_hostname'],
    src_mac: ['srcmac', 'source.mac', 'smac', 'srcmac', 'src_mac', 'sourcemacaddress'],
    dst_mac: ['dstmac', 'destination.mac', 'dmac', 'dstmac', 'dst_mac', 'destinationmacaddress'],
    src_nat_ip: ['srcnatip', 'source.nat.ip', 'sourcetranslatedaddress', 'srcpostnat', 'transip', 'natsrcip', 'nat_src_ip', 'xlatesrc'],
    dst_nat_ip: ['dstnatip', 'destination.nat.ip', 'destinationtranslatedaddress', 'dstpostnat', 'natdstip', 'nat_dst_ip', 'xlatedst'],
    bytes_in: ['bytes_in', 'destination.bytes', 'in', 'rcvdbyte', 'bytesin', 'bytes_in', 'rcvd_bytes', 'dstbytes', 'sc-bytes'],
    bytes_out: ['bytes_out', 'source.bytes', 'out', 'sentbyte', 'bytesout', 'bytes_out', 'sent_bytes', 'srcbytes', 'cs-bytes'],
    file_name: ['file_name', 'file.name', 'fname', 'filename', 'file_name', 'file'],
    file_path: ['file_path', 'file.path', 'filepath', 'file_path', 'path', 'targetfilename', 'objectname'],
    file_hash: ['file_hash', 'file.hash.sha256', 'filehash', 'file_hash', 'sha256', 'hash', 'filehashsha256'],
    file_size: ['file_size', 'file.size', 'fsize', 'filesize', 'file_size'],
    process: ['process_name', 'process.name', 'sproc', 'dproc', 'processname', 'process_name', 'process', 'image', 'newprocessname'],
    process_id: ['process_id', 'process.pid', 'spid', 'dpid', 'processid', 'process_id', 'pid', 'newprocessid'],
    command_line: ['command_line', 'process.command_line', 'commandline', 'command_line', 'cmdline', 'cmd'],
    app: ['app', 'network.application', 'app', 'application', 'appname', 'app_name', 'service'],
    policy: ['policy', 'rule.name', 'policy', 'policyname', 'policy_name', 'policyid', 'rulename', 'rule_name', 'cs1'],
    http_method: ['http_method', 'http.request.method', 'requestmethod', 'method', 'http_method', 'cs-method'],
    http_version: ['http_version', 'http.version', 'http_version', 'httpversion', 'protocol_version', 'cs-version'],
    referrer: ['referrer', 'http.request.referrer', 'referrer', 'referer', 'http_referer', 'http_referrer', 'cs(referer)'],
    response_time: ['response_time', 'event.duration', 'response_time', 'request_time', 'time_taken', 'time-taken', 'duration_ms'],
    http_bytes: ['bytes', 'http.response.body.bytes', 'body_bytes_sent', 'bytes_sent_body', 'sc-bytes-body'],
    http_status: ['http_status', 'http.response.status_code', 'statuscode', 'status_code', 'http_status', 'sc-status', 'response_code'],
    user_agent: ['user_agent', 'user_agent.original', 'requestclientapplication', 'useragent', 'user_agent', 'cs(user-agent)', 'http_user_agent'],
    domain: ['domain', 'user.domain', 'sntdom', 'dntdom', 'domain', 'targetdomainname', 'subjectdomainname', 'realm'],
    direction: ['direction', 'network.direction', 'devicedirection', 'direction', 'dir'],
    event_time: ['event_time', 'event.created', 'rt', 'devtime', 'eventtime', 'event_time', 'receipttime', 'timestamp', 'time', '@timestamp', 'date'],
    start_time: ['start_time', 'event.start', 'start', 'starttime', 'start_time'],
    end_time: ['end_time', 'event.end', 'end', 'endtime', 'end_time'],
    vendor: ['vendor', 'observer.vendor', 'devicevendor', 'device_vendor', 'vendor'],
    product: ['product', 'observer.product', 'deviceproduct', 'device_product', 'product'],
    device_ip: ['device_ip', 'observer.ip', 'dvc', 'deviceaddress', 'device_ip', 'devip'],
    count: ['count', 'event.count', 'cnt', 'count', 'repeatcount'],
  };

  const ALIAS = new Map();
  for (const [concept, arr] of Object.entries(CONCEPTS)) {
    for (const a of arr.slice(2)) {
      if (!ALIAS.has(a.toLowerCase())) ALIAS.set(a.toLowerCase(), concept);
    }
  }

  // CEF / LEEF header positions → concept
  const HEADER_CONCEPTS = {
    'cef.version': null,
    'cef.vendor': 'vendor',
    'cef.product': 'product',
    'cef.device_version': null,
    'cef.signature_id': 'event_id',
    'cef.name': 'event_name',
    'cef.severity': 'severity',
    'leef.version': null,
    'leef.vendor': 'vendor',
    'leef.product': 'product',
    'leef.product_version': null,
    'leef.event_id': 'event_id',
  };

  function conceptOf(key) {
    if (!key) return null;
    if (Object.prototype.hasOwnProperty.call(HEADER_CONCEPTS, key)) return HEADER_CONCEPTS[key];
    const k = String(key).toLowerCase();
    if (ALIAS.has(k)) return ALIAS.get(k);
    // nested JSON keys: try the last path segment
    const last = k.split(/[.\/]/).pop();
    if (last !== k && ALIAS.has(last)) return ALIAS.get(last);
    return null;
  }

  function isStatic(name) {
    return STATIC_FIELDS.includes(name);
  }

  /** Scheme ids, with the names used by earlier versions as aliases. */
  function normalizeScheme(s) {
    if (s === 'ecs') return 'wcs';
    if (s === 'original') return 'custom';
    return s === 'wcs' || s === 'custom' ? s : 'wazuh';
  }

  /**
   * Suggest target names for a list of fields.
   *
   * Schemes:
   *   wazuh  : Native Wazuh (4.x) static fields where one exists
   *   wcs    : Wazuh Common Schema (Wazuh 5, ECS-based); fields outside the
   *            schema go under custom.* as WCS requires
   *   custom : the analyst's own mapping (remembered renames), else the
   *            vendor key
   *
   * @param {Array<{key:string,type?:string,label?:string}>} fields
   * @param {{scheme?:string, prefix?:string, customMap?:Object<string,string>}} opts
   * @returns {Map<string,string>} key → suggested name (unique)
   */
  function suggestNames(fields, opts) {
    const o = Object.assign({ scheme: 'wazuh', prefix: '', customMap: {} }, opts);
    o.scheme = normalizeScheme(o.scheme);
    const used = new Set();
    const out = new Map();
    const prefix = o.prefix ? W.util.sanitizeFieldName(o.prefix).replace(/\.?$/, '.') : o.scheme === 'wcs' ? 'custom.' : '';

    const fallback = (f) => {
      const base = f.label ? W.util.sanitizeFieldName(f.label) : W.util.sanitizeFieldName(f.key);
      return prefix + (base || 'field');
    };

    if (o.scheme === 'custom') {
      for (const f of fields) {
        let candidate = (o.customMap && o.customMap[f.key]) || fallback(f);
        let n = 2;
        const base = candidate;
        while (used.has(candidate)) candidate = `${base}_${n++}`;
        used.add(candidate);
        out.set(f.key, candidate);
      }
      return out;
    }

    // Static fields are single-slot: give them to the best candidate first
    // (fields present in every log, then in declaration order).
    const ordered = fields.map((f, i) => ({ f, i })).sort((a, b) => (b.f.presence || 0) - (a.f.presence || 0) || a.i - b.i);
    for (const { f } of ordered) {
      const concept = conceptOf(f.key);
      let name = null;
      if (concept && CONCEPTS[concept]) {
        const [wz, ecs] = CONCEPTS[concept];
        if (o.scheme === 'wazuh') {
          name = isStatic(wz) ? wz : prefix + wz;
          // static IP slots only make sense for IP-looking values
          if ((wz === 'srcip' || wz === 'dstip') && f.type && !['ipv4', 'ipv6', 'ip', 'empty'].includes(f.type)) name = null;
          if ((wz === 'srcport' || wz === 'dstport') && f.type && !['integer', 'empty'].includes(f.type)) name = null;
        } else {
          name = ecs;
        }
      }
      if (!name) name = fallback(f);
      let candidate = name;
      if (used.has(candidate)) {
        // concept slot already taken → keep the vendor's own key
        candidate = fallback(f);
        let n = 2;
        const base = candidate;
        while (used.has(candidate)) candidate = `${base}_${n++}`;
      }
      used.add(candidate);
      out.set(f.key, candidate);
    }
    return out;
  }

  /** Name catalogue for the UI's autocomplete. */
  function catalogue(scheme) {
    const wcs = normalizeScheme(scheme) === 'wcs';
    const names = new Set(wcs ? [] : STATIC_FIELDS.filter((s) => s !== 'user'));
    for (const arr of Object.values(CONCEPTS)) names.add(wcs ? arr[1] : arr[0]);
    return [...names].sort();
  }

  // ------------------------------------------------------------------
  // Field picker catalogue. WCS (Wazuh 5) follows ECS, so these are ECS
  // names; each carries the kinds of value it holds, used to rank the
  // suggestions against a field's inferred type.
  // ------------------------------------------------------------------
  const WCS_FIELDS = [
    ['source.ip', 'ip', 'Source address'], ['destination.ip', 'ip', 'Destination address'], ['client.ip', 'ip', 'Client address'], ['server.ip', 'ip', 'Server address'],
    ['host.ip', 'ip', 'Host address'], ['observer.ip', 'ip', 'Reporting device address'], ['source.nat.ip', 'ip', 'Source address after NAT'], ['destination.nat.ip', 'ip', 'Destination address after NAT'],
    ['network.forwarded_ip', 'ip', 'X-Forwarded-For client'], ['related.ip', 'ip', 'Any IP seen in the event'],
    ['source.port', 'port', 'Source port'], ['destination.port', 'port', 'Destination port'], ['client.port', 'port', 'Client port'], ['server.port', 'port', 'Server port'],
    ['source.nat.port', 'port', 'Source port after NAT'], ['destination.nat.port', 'port', 'Destination port after NAT'],
    ['source.mac', 'mac', 'Source MAC'], ['destination.mac', 'mac', 'Destination MAC'], ['host.mac', 'mac', 'Host MAC'], ['observer.mac', 'mac', 'Device MAC'],
    ['user.name', 'user', 'User name'], ['user.id', 'user id', 'User ID'], ['user.domain', 'user host', 'User domain'], ['user.email', 'email user', 'User e-mail'], ['user.full_name', 'user text', 'Full name'],
    ['source.user.name', 'user', 'User at the source'], ['destination.user.name', 'user', 'User at the destination'], ['user.target.name', 'user', 'Targeted user'], ['user.effective.name', 'user', 'Effective user'],
    ['related.user', 'user', 'Any user seen in the event'], ['group.name', 'user text', 'Group name'],
    ['host.name', 'host', 'Host name'], ['host.hostname', 'host', 'Host name (as reported)'], ['observer.hostname', 'host', 'Device host name'], ['observer.name', 'host text', 'Device name'],
    ['source.domain', 'host', 'Source domain'], ['destination.domain', 'host', 'Destination domain'], ['client.domain', 'host', 'Client domain'], ['server.domain', 'host', 'Server domain'],
    ['dns.question.name', 'host', 'DNS query name'], ['dns.question.type', 'text', 'DNS query type'], ['dns.response_code', 'text', 'DNS response code'],
    ['url.original', 'url path', 'URL as seen in the log'], ['url.full', 'url', 'Full URL'], ['url.path', 'path url', 'URL path'], ['url.query', 'text', 'URL query string'], ['url.domain', 'host', 'URL domain'], ['url.scheme', 'text', 'URL scheme'],
    ['http.request.method', 'text http', 'HTTP method'], ['http.response.status_code', 'number http', 'HTTP status code'], ['http.version', 'text http', 'HTTP version'],
    ['http.request.referrer', 'url', 'HTTP referrer'], ['http.request.body.bytes', 'bytes', 'Request body size'], ['http.response.body.bytes', 'bytes', 'Response body size'],
    ['user_agent.original', 'useragent text', 'User agent'],
    ['file.path', 'path', 'File path'], ['file.name', 'file', 'File name'], ['file.extension', 'text', 'File extension'], ['file.directory', 'path', 'File directory'], ['file.size', 'bytes number', 'File size'],
    ['file.hash.md5', 'hash', 'File MD5'], ['file.hash.sha1', 'hash', 'File SHA-1'], ['file.hash.sha256', 'hash', 'File SHA-256'],
    ['process.name', 'file text', 'Process name'], ['process.pid', 'number id', 'Process ID'], ['process.executable', 'path', 'Process executable'], ['process.command_line', 'text', 'Command line'],
    ['process.parent.name', 'file text', 'Parent process name'], ['process.parent.pid', 'number id', 'Parent process ID'], ['process.hash.sha256', 'hash', 'Process SHA-256'],
    ['@timestamp', 'time', 'Event time'], ['event.created', 'time', 'Time the event was created'], ['event.start', 'time', 'Start time'], ['event.end', 'time', 'End time'], ['event.duration', 'number', 'Duration'],
    ['event.action', 'text', 'Action'], ['event.outcome', 'text', 'Outcome (success, failure)'], ['event.category', 'text', 'Category'], ['event.type', 'text', 'Type'], ['event.kind', 'text', 'Kind'],
    ['event.code', 'id number text', 'Event code / ID'], ['event.id', 'id', 'Unique event ID'], ['event.severity', 'number text', 'Severity'], ['event.reason', 'text', 'Reason'], ['event.provider', 'text', 'Provider'],
    ['event.dataset', 'text', 'Dataset'], ['event.module', 'text', 'Module'], ['message', 'text', 'Message'], ['error.message', 'text', 'Error message'], ['log.level', 'text', 'Log level'],
    ['network.protocol', 'text', 'Application protocol'], ['network.transport', 'text', 'Transport (tcp, udp)'], ['network.direction', 'text', 'Direction'], ['network.application', 'text', 'Application'],
    ['network.bytes', 'bytes number', 'Total bytes'], ['network.packets', 'number', 'Total packets'], ['source.bytes', 'bytes number', 'Bytes from source'], ['destination.bytes', 'bytes number', 'Bytes from destination'],
    ['source.packets', 'number', 'Packets from source'], ['destination.packets', 'number', 'Packets from destination'],
    ['rule.name', 'text', 'Rule / policy name'], ['rule.id', 'id number text', 'Rule / policy ID'], ['rule.category', 'text', 'Rule category'],
    ['observer.vendor', 'text', 'Device vendor'], ['observer.product', 'text', 'Device product'], ['observer.version', 'text', 'Device version'], ['observer.serial_number', 'text id', 'Device serial number'],
    ['observer.ingress.interface.name', 'text', 'Inbound interface'], ['observer.egress.interface.name', 'text', 'Outbound interface'],
    ['email.from.address', 'email', 'Sender'], ['email.to.address', 'email', 'Recipient'], ['email.subject', 'text', 'Subject'],
    ['service.name', 'text', 'Service name'], ['tls.version', 'text', 'TLS version'], ['tls.cipher', 'text', 'TLS cipher'],
    ['source.geo.country_iso_code', 'text', 'Source country'], ['destination.geo.country_iso_code', 'text', 'Destination country'],
  ].map(([name, kinds, desc]) => ({ name, kinds: kinds.split(' '), desc }));

  const NATIVE_FIELDS = [
    ['srcip', 'ip', 'Source IP (static)'], ['dstip', 'ip', 'Destination IP (static)'], ['srcport', 'port', 'Source port (static)'], ['dstport', 'port', 'Destination port (static)'],
    ['srcuser', 'user', 'Source user (static)'], ['dstuser', 'user', 'Destination user (static)'], ['protocol', 'text', 'Protocol (static)'], ['action', 'text', 'Action (static)'],
    ['id', 'id number text', 'Event ID (static)'], ['url', 'url path', 'URL (static)'], ['status', 'text', 'Status (static)'], ['system_name', 'host', 'System name (static)'],
    ['data', 'text', 'Data (static)'], ['extra_data', 'text', 'Extra data (static)'],
  ]
    .map(([name, kinds, desc]) => ({ name, kinds: kinds.split(' '), desc }))
    .concat(
      Object.values(CONCEPTS)
        .map((c) => c[0])
        .filter((n) => !STATIC_FIELDS.includes(n))
        .map((n) => ({ name: n, kinds: kindsOfName(n), desc: 'common dynamic field' }))
    );

  function kindsOfName(n) {
    if (/ip$/.test(n)) return ['ip'];
    if (/port$/.test(n)) return ['port'];
    if (/user|account/.test(n)) return ['user'];
    if (/mac$/.test(n)) return ['mac'];
    if (/host|domain|system/.test(n)) return ['host'];
    if (/hash/.test(n)) return ['hash'];
    if (/bytes|size/.test(n)) return ['bytes', 'number'];
    if (/time|date/.test(n)) return ['time'];
    if (/url|path/.test(n)) return ['url', 'path'];
    if (/file/.test(n)) return ['file', 'path'];
    return ['text'];
  }

  /** Kinds of value a field of the given inferred type can hold. */
  const TYPE_KINDS = {
    ipv4: ['ip'], ipv6: ['ip'], ip: ['ip'], ipport: ['ip', 'port'], mac: ['mac'],
    integer: ['port', 'number', 'bytes', 'id'], number: ['number', 'bytes'], epoch: ['time'], hex: ['id'],
    md5: ['hash'], sha1: ['hash'], sha256: ['hash'], hash: ['hash'], uuid: ['id'],
    url: ['url'], unixpath: ['path', 'url'], winpath: ['path'], filename: ['file'], fqdn: ['host'], email: ['email', 'user'], domainuser: ['user'],
    iso8601: ['time'], syslogtime: ['time'], httpdate: ['time'], date: ['time'], time: ['time'], timestamp: ['time'],
    useragent: ['useragent'], httprequest: ['http', 'text'], bool: ['text'],
    word: ['user', 'text', 'host', 'id', 'http'], token: ['text', 'user', 'id', 'host', 'path'], text: ['text'], empty: ['text'],
  };

  function catalogueFor(scheme) {
    const s = normalizeScheme(scheme);
    if (s === 'wazuh') return NATIVE_FIELDS;
    if (s === 'wcs') return WCS_FIELDS;
    return WCS_FIELDS.concat(NATIVE_FIELDS);
  }

  /**
   * Picker suggestions for one field.
   * @returns {{suggested: Array, others: Array, known: boolean}}
   *   suggested: fields matching the value type (and the source key concept),
   *   others: every other field (narrowed by the query), known: query is in the catalogue.
   */
  function pickerOptions(scheme, { type, key, query }) {
    const cat = catalogueFor(scheme);
    const q = String(query || '').trim().toLowerCase();
    const kinds = TYPE_KINDS[type] || ['text'];
    const concept = conceptOf(key);
    const conceptNames = concept && CONCEPTS[concept] ? [CONCEPTS[concept][0], CONCEPTS[concept][1]] : [];
    const score = (f) => {
      let s = 0;
      if (conceptNames.includes(f.name)) s += 100;
      const k = f.kinds.findIndex((x) => kinds.includes(x));
      if (k >= 0) s += 40 - k * 5 + (kinds.length - kinds.indexOf(f.kinds[k])) * 2;
      return s;
    };
    const matchQ = (f) => {
      if (!q) return 1;
      const n = f.name.toLowerCase();
      if (n === q) return 4;
      if (n.startsWith(q)) return 3;
      if (n.split(/[._]/).some((p) => p.startsWith(q))) return 2;
      if (n.includes(q) || f.desc.toLowerCase().includes(q)) return 1;
      return 0;
    };
    const ranked = cat
      .map((f) => ({ f, s: score(f), m: matchQ(f) }))
      .filter((x) => x.m > 0)
      .sort((a, b) => b.m - a.m || b.s - a.s || a.f.name.localeCompare(b.f.name));
    const suggested = ranked.filter((x) => x.s > 0).map((x) => x.f);
    const others = ranked.filter((x) => x.s <= 0).map((x) => x.f);
    const known = cat.some((f) => f.name === q);
    return { suggested, others, known };
  }

  function isKnownName(scheme, name) {
    return catalogueFor(scheme).some((f) => f.name === name);
  }

  W.fieldmap = { STATIC_FIELDS, CONCEPTS, WCS_FIELDS, conceptOf, isStatic, suggestNames, catalogue, normalizeScheme, pickerOptions, isKnownName };
});
