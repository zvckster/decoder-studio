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

  W.fieldmap = { STATIC_FIELDS, CONCEPTS, conceptOf, isStatic, suggestNames, catalogue, normalizeScheme };
});
