/*
 * Sample library: one realistic, fictional data set per supported shape.
 * Used by the UI ("Load a sample") and by the test-suite.
 */
WDG_MODULE(function (W) {
  'use strict';

  W.samples = [
    {
      id: 'cef-trendmicro',
      label: 'CEF · Trend Micro Apex Central',
      source: 'trendmicro-apex',
      text: [
        'Aug 23 11:30:15 ap-syslog-1 CEF:0|Trend Micro|Apex Central|2019|700106|Data Loss Prevention|3|devicePayloadId=4860BD457222-BB2611EF-FBE7-2501-8BCF externalId=11504 suser=testuser1 msg=Policy violation detected on confidential data transfer. fname=report.xlsx src=192.168.4.155 smac=2C-F0-5D-51-A9-52 shost=RCHCORPD054 dvchost=Apex One as a Service',
        'Aug 23 11:32:04 central-server CEF:0|Trend Micro|Apex Central|2019|202101|Behavior Monitoring|5|devicePayloadId=9082AC123456-CC12345-FBE7-2501-ABCD externalId=11509 suser=admin_user msg=Suspicious process behavior detected. fname=svchost.exe act=Terminate src=10.10.20.50 smac=00-1B-63-84-45-E6 shost=FINANCE-PC01 dvchost=Apex One as a Service',
        'CEF:0|Trend Micro|Apex Central|2019|700106|Data Loss Prevention|3|devicePayloadId=5555BD457222-BB2611EF-FBE7-2501-8BCF externalId=12011 suser=testuser2 msg=Unauthorized USB device detected. fname=autorun.inf act=Block src=192.168.4.201 smac=5C-F9-DD-72-B1-04 shost=MARKETING-LT05 dvchost=Apex One as a Service',
        'CEF:0|Trend Micro|Apex Central|2019|400110|Virus/Malware|8|devicePayloadId=6666BD457222-BB2611EF-FBE7-2501-8BCF externalId=12015 suser=guest msg=Malware detected and cleaned. fname=trojan.js.xmr cn1Label=ThreatID cn1=10101 src=172.16.30.12 dvchost=Apex One as a Service',
      ].join('\n'),
    },
    {
      id: 'leef-qradar',
      label: 'LEEF · IBM QRadar (1.0 & 2.0)',
      source: 'qradar',
      text: [
        'Aug 23 17:55:10 qradar-primary LEEF:2.0|IBM|Security QRadar|7.3|LoginEvent|\tdevTime=Aug 23 2025 12:25:10 GMT\tusrName=jdoe\tsrc=192.168.1.101\tmsg=User login successful from host console.',
        'Aug 23 17:56:02 qradar-secondary LEEF:2.0|IBM|Security QRadar|7.3|LoginEvent|\tdevTime=Aug 23 2025 12:26:02 GMT\tusrName=admin\tsrc=10.0.0.5\tsev=8\tmsg=User login failed: invalid password.',
        'LEEF:2.0|IBM|Security QRadar|7.3|AuditEvent|\tdevTime=Aug 23 2025 12:27:15 GMT\tusrName=auditor\tsrc=127.0.0.1\tmsg=User activity report generated.',
        'LEEF:2.0|IBM|Security QRadar|7.3|SystemEvent|\tdevTime=Aug 23 2025 12:28:00 GMT\tsev=4\tmsg=System health check completed successfully.',
      ].join('\n'),
    },
    {
      id: 'leef-caret',
      label: 'LEEF 2.0 · custom "^" delimiter',
      source: 'acme-waf',
      text: [
        'LEEF:2.0|Acme|WAF|3.2|SQLi|^|devTime=1724412310000^src=203.0.113.7^dst=10.1.1.20^dstPort=443^usrName=^url=/login.php?id=1 OR 1=1^action=blocked^sev=9',
        'LEEF:2.0|Acme|WAF|3.2|XSS|^|devTime=1724412355000^src=198.51.100.23^dst=10.1.1.20^dstPort=443^usrName=bob^url=/search?q=<script>^action=blocked^sev=7',
        'LEEF:2.0|Acme|WAF|3.2|Allowed|^|devTime=1724412399000^src=192.0.2.44^dst=10.1.1.21^dstPort=80^usrName=alice^url=/index.html^action=allowed^sev=1',
      ].join('\n'),
    },
    {
      id: 'kv-fortigate',
      label: 'Key=Value · Fortinet FortiGate',
      source: 'fortigate-custom',
      text: [
        'date=2025-08-23 time=11:30:15 devname="FGT-HQ-01" devid="FG100FTK19000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.1.1.15 srcport=51544 srcintf="port2" dstip=93.184.216.34 dstport=443 dstintf="wan1" policyid=12 service="HTTPS" proto=6 action="accept" sentbyte=1520 rcvdbyte=48822 user="jdoe"',
        'date=2025-08-23 time=11:30:21 devname="FGT-HQ-01" devid="FG100FTK19000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.1.1.22 srcport=60122 srcintf="port2" dstip=151.101.1.69 dstport=443 dstintf="wan1" policyid=12 service="HTTPS" proto=6 action="deny" sentbyte=0 rcvdbyte=0',
        'date=2025-08-23 time=11:31:02 devname="FGT-HQ-01" devid="FG100FTK19000001" logid="0100032001" type="event" subtype="system" level="information" vd="root" user="admin" ui="https(10.1.1.5)" action="login" status="success" msg="Administrator admin logged in successfully from https(10.1.1.5)"',
      ].join('\n'),
    },
    {
      id: 'kv-syslog-app',
      label: 'Key=Value · app behind syslog program name',
      source: 'payment-api',
      text: [
        'Aug 23 11:40:01 app01 payment-api[2211]: level=INFO event=charge.created user=alice amount=19.99 currency=EUR client_ip=203.0.113.10 latency_ms=84',
        'Aug 23 11:40:07 app01 payment-api[2211]: level=WARN event=charge.retry user=bob amount=250.00 currency=USD client_ip=198.51.100.4 latency_ms=1203 reason="gateway timeout"',
        'Aug 23 11:41:30 app02 payment-api[3012]: level=ERROR event=charge.failed user=carol amount=5.00 currency=EUR client_ip=192.0.2.77 latency_ms=40 reason="card declined"',
      ].join('\n'),
    },
    {
      id: 'json-plain',
      label: 'JSON · plain NDJSON (built-in decoder)',
      source: 'edr-json',
      text: [
        '{"vendor":"Contoso","product":"EDR","event":{"type":"process_start","severity":"medium"},"host":{"name":"WS-042","ip":"10.2.3.4"},"process":{"name":"powershell.exe","cmdline":"powershell -enc SQBFAFgA","pid":4412},"user":"CORP\\\\jdoe"}',
        '{"vendor":"Contoso","product":"EDR","event":{"type":"network_connect","severity":"low"},"host":{"name":"WS-017","ip":"10.2.3.9"},"process":{"name":"chrome.exe","pid":1200},"dst_ip":"142.250.74.110","dst_port":443,"user":"CORP\\\\asmith"}',
        '{"vendor":"Contoso","product":"EDR","event":{"type":"malware_detected","severity":"critical"},"host":{"name":"SRV-DB-01","ip":"10.9.0.12"},"file":{"path":"C:\\\\Temp\\\\invoice.exe","sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},"user":"SYSTEM"}',
      ].join('\n'),
    },
    {
      id: 'json-syslog',
      label: 'JSON · behind a syslog program name',
      source: 'k8s-audit',
      text: [
        'Aug 23 12:00:01 node-3 kube-audit: {"kind":"Event","level":"Metadata","verb":"create","user":{"username":"system:serviceaccount:ci:deployer"},"sourceIPs":["10.244.1.9"],"objectRef":{"resource":"pods","namespace":"prod"},"responseStatus":{"code":201}}',
        'Aug 23 12:00:09 node-1 kube-audit: {"kind":"Event","level":"Metadata","verb":"delete","user":{"username":"admin@corp.example"},"sourceIPs":["10.0.4.20"],"objectRef":{"resource":"secrets","namespace":"prod"},"responseStatus":{"code":403}}',
      ].join('\n'),
    },
    {
      id: 'json-prefix',
      label: 'JSON · after a text prefix',
      source: 'gateway-audit',
      text: [
        '2025-08-23T12:10:01Z gw-eu-1 AUDIT: {"action":"policy_update","actor":"ops-bot","rule_id":1182,"src_ip":"172.16.4.2","result":"success"}',
        '2025-08-23T12:11:45Z gw-eu-2 AUDIT: {"action":"login","actor":"jane","src_ip":"198.51.100.61","result":"failure","reason":"mfa_timeout"}',
      ].join('\n'),
    },
    {
      id: 'csv-panos',
      label: 'CSV · Palo Alto-style traffic log',
      source: 'pan-traffic',
      text: [
        '1,2025/08/23 11:30:15,012801001234,TRAFFIC,end,2561,2025/08/23 11:30:15,10.0.0.10,8.8.8.8,0.0.0.0,0.0.0.0,allow-dns,,,dns,vsys1,trust,untrust,ethernet1/2,ethernet1/1,log-fwd,2025/08/23 11:30:15,31337,1,53421,53,0,0,0x19,udp,allow,184,84,100,2',
        '1,2025/08/23 11:30:18,012801001234,TRAFFIC,end,2561,2025/08/23 11:30:18,10.0.0.23,104.16.132.229,203.0.113.5,104.16.132.229,allow-web,corp\\jdoe,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,log-fwd,2025/08/23 11:30:18,31338,1,61022,443,40022,443,0x400053,tcp,allow,9344,1233,8111,24',
        '1,2025/08/23 11:30:22,012801001234,TRAFFIC,deny,2561,2025/08/23 11:30:22,10.0.0.45,185.220.101.1,0.0.0.0,0.0.0.0,block-tor,,,tor,vsys1,trust,untrust,ethernet1/2,ethernet1/1,log-fwd,2025/08/23 11:30:22,31339,1,50112,9001,0,0,0x0,tcp,deny,74,74,0,1',
      ].join('\n'),
    },
    {
      id: 'csv-header',
      label: 'CSV · with header row',
      source: 'vpn-export',
      text: ['timestamp,user,src_ip,country,result,"reason"', '2025-08-23T08:00:01Z,jdoe,203.0.113.4,FR,success,', '2025-08-23T08:03:12Z,asmith,198.51.100.9,US,failure,"bad password, locked"', '2025-08-23T08:05:40Z,mjones,192.0.2.33,DE,success,'].join('\n'),
    },
    {
      id: 'xml-windows',
      label: 'XML · Windows event over syslog',
      source: 'win-xml',
      text: [
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><Computer>DC01.corp.example</Computer></System><EventData><Data Name='TargetUserName'>administrator</Data><Data Name='IpAddress'>203.0.113.50</Data><Data Name='LogonType'>3</Data></EventData></Event>",
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><Computer>DC02.corp.example</Computer></System><EventData><Data Name='TargetUserName'>jdoe</Data><Data Name='IpAddress'>10.0.0.8</Data><Data Name='LogonType'>10</Data></EventData></Event>",
      ].join('\n'),
    },
    {
      id: 'rfc5424',
      label: 'RFC 5424 syslog · structured data + KV',
      source: 'idp-sso',
      text: [
        '<134>1 2025-08-23T11:30:15.003Z idp01 sso-service 812 AUTH [meta@32473 tenant="corp" region="eu-west"] user=jdoe src=203.0.113.9 result=success method=webauthn',
        '<132>1 2025-08-23T11:31:02.114Z idp02 sso-service 813 AUTH [meta@32473 tenant="corp" region="us-east"] user=asmith src=198.51.100.23 result=failure method=password reason="invalid credentials"',
      ].join('\n'),
    },
    {
      id: 'freeform-ssh',
      label: 'Free-form · custom SSH gateway',
      source: 'sshgw',
      text: [
        'Aug 23 11:30:15 bastion01 sshgw[4411]: Accepted publickey for alice from 203.0.113.10 port 51122 ssh2',
        'Aug 23 11:31:22 bastion01 sshgw[4411]: Accepted publickey for bob from 198.51.100.7 port 40022 ssh2',
        'Aug 23 11:32:40 bastion01 sshgw[4419]: Failed password for invalid user admin from 192.0.2.200 port 60311 ssh2',
        'Aug 23 11:32:44 bastion01 sshgw[4419]: Failed password for invalid user oracle from 192.0.2.200 port 60318 ssh2',
        'Aug 23 11:40:01 bastion01 sshgw[4502]: Session closed for user alice duration 00:09:46',
      ].join('\n'),
    },
    {
      id: 'freeform-access',
      label: 'Free-form · Nginx access log',
      source: 'nginx-custom',
      text: [
        '203.0.113.10 - alice [23/Aug/2025:11:30:15 +0000] "GET /api/orders?id=42 HTTP/1.1" 200 1532 "-" "Mozilla/5.0 (X11; Linux x86_64)"',
        '198.51.100.7 - - [23/Aug/2025:11:30:16 +0000] "POST /login HTTP/1.1" 401 88 "https://shop.example/" "curl/8.4.0"',
        '192.0.2.44 - bob [23/Aug/2025:11:30:19 +0000] "GET /static/app.js HTTP/2.0" 304 0 "https://shop.example/cart" "Mozilla/5.0 (Macintosh)"',
      ].join('\n'),
    },
  ];
});
