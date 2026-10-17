# Data modeling FAQ

Answers to the data engineering and data science team's questions about SSDF data
modeling and ingest. Live numbers were pulled from ClickHouse (guest 701) on
**2026-10-17**. They are aggregates only. Every sample line below is a `vector test`
fixture from `infra/vector/vector.toml`. Those fixtures copy the real wire formats, with
addresses moved to documentation ranges (RFC 5737) and names changed to `example.com`.

Contents:

1. [Sample raw data, per source](#1-sample-raw-data-per-source)
2. [What we want changed in the raw data](#2-what-we-want-changed-in-the-raw-data)
3. [Arrival frequency](#3-arrival-frequency)
4. [The main table, and everything around it](#4-the-main-table-and-everything-around-it)
5. [The queries LLMs run](#5-the-queries-llms-run)

---

## 1. Sample raw data, per source

All sources arrive as UDP syslog on Vector (guest 700). Each vendor has its own port.
Vendor formats are parsed in `infra/vector/vector.toml` and nowhere else.

| Port | Source | Wire format | Vector transform | `event_provider` | Live? |
|---|---|---|---|---|---|
| 514 | Juniper SRX security log (`RT_*`) | RFC 5424 + structured data (`sd-syslog`) | `srx_sec` → `srx_ecs` | `juniper` | yes |
| 514/518 | Junos system/audit log (`UI_*`, `SSHD_*`) | RFC 5424 + structured data | `junos_sys_sec` → `junos_sys_ecs` | `juniper` | yes |
| 515 | PAN-OS 12.1 | RFC 3164 header + **positional CSV** | `panos_ecs` | `paloalto` | yes |
| 516 | UniFi IPS (Suricata via the Cloud Key) | **CEF** with no syslog PRI | `unifi_cef_threat` → `unifi_ips` | `unifi` | **0 events in 30 days** |
| 517 | Proxmox host (auth + task audit) | RFC 5424 (rsyslog `SyslogProtocol23Format`) | `proxmox_sec` → `proxmox_ecs` | `proxmox` | yes |

Two sources do **not** come in through syslog. They are polled from vendor MCP servers
by the Python resolvers on guest 704 (see §4): the topology observations (ARP, device
inventory) and the health metrics (CPU, memory, alarms).

### 1a. Juniper SRX: flow session close (`RT_FLOW`)

```
<14>1 2026-06-06T12:00:00.000Z srx-test10 RT_FLOW - RT_FLOW_SESSION_CLOSE [junos@2636.1.1.1.2.36 reason="TCP RST" source-address="10.65.1.10" source-port="51514" destination-address="10.66.2.20" destination-port="443" service-name="junos-https" application="HTTPS" protocol-id="6" policy-name="trust-to-untrust" source-zone-name="trust" destination-zone-name="untrust" session-id-32="40000123" packets-from-client="12" bytes-from-client="1500" packets-from-server="10" bytes-from-server="6000" elapsed-time="5" username="alice"]
```

This normalizes to:

```
event_provider=juniper  event_kind=event  event_category=[network]
event_action=flow_session_close  network_transport=tcp
source_ip=10.65.1.10  source_port=51514  destination_ip=10.66.2.20  destination_port=443
source_bytes=1500  destination_bytes=6000  network_bytes=7500
rule_name=trust-to-untrust  observer_ingress_zone=trust  observer_egress_zone=untrust
user_name=alice  ext['session-id-32']=40000123  raw=<the line above>
```

### 1b. Juniper SRX: deny and screen (IDS) events

```
<14>1 2026-06-06T12:00:02.000Z srx-test10 RT_FLOW - RT_FLOW_SESSION_DENY [junos@2636.1.1.1.2.36 source-address="10.73.9.9" source-port="40000" destination-address="10.66.2.22" destination-port="3389" service-name="junos-rdp" application="RDP" protocol-id="6" policy-name="default-deny" source-zone-name="untrust" destination-zone-name="trust" username="N/A"]

<11>1 2026-07-01T19:42:22.737-04:00 vsrx-isp-b RT_IDS - RT_SCREEN_IP [junos@2636.1.1.1.2.129 attack-name="Unknown protocol!" source-address="129.16.0.1" destination-address="224.255.255.250" protocol-id="250" source-zone-name="untrust" interface-name="ge-0/0/0.0" action="drop"]
```

The deny becomes `flow_session_deny` with outcome `failure`, and `username="N/A"` becomes
`""`. The screen becomes `event_kind=alert`, category `[network, intrusion_detection]`,
action `screen_unknown_protocol`. Any other `RT_*` message ID falls back to its
lowercased ID (for example `rt_idp_attack_log_event`), so a parseable line never lands
as `unknown`.

### 1c. Junos system log: auth and config audit

```
<37>1 2026-07-06T03:50:42.589Z vsrx-ci sshd - SSHD_LOGIN_FAILED [junos@2636.1.1.1.2.129 username="baduser" source-address="198.51.100.148"] Login failed for user 'baduser' from host '198.51.100.148'

<189>1 2026-07-06T03:52:49.972Z vsrx-ci mgd 97400 UI_COMMIT [junos@2636.1.1.1.2.129 username="netconf" command="commit" message="m14c canary commit C (capture UI_COMMIT lines)"] User 'netconf' requested 'commit' operation (comment: m14c canary commit C (capture UI_COMMIT lines))

<182>1 2026-07-06T03:52:49.931Z vsrx-ci mgd 97400 UI_CFG_AUDIT_SET [junos@2636.1.1.1.2.129 username="netconf" action="set" pathname="[system login message\]" delimiter="\"" data="m14c commit capture" value="m14c commit capture"] User 'netconf' set: [system login message] "m14c commit capture -- "m14c commit capture"
```

These become `auth_failure`, `configuration_commit` and `configuration_change`. Two
privacy rules are applied **at ingest**:

- A failed-login username is stored as `HMAC-SHA256(USERNAME_HASH_KEY, user)` and is
  removed from `raw` as well.
- Config values whose path looks like a secret (`encrypted-password`, keys, SNMP
  communities) become `[REDACTED]` in both `ext` and `raw`.

### 1d. PAN-OS: traffic, threat, system, config

The payload is positional CSV, so field meaning depends on column position, and the
positions are pinned to PAN-OS 12.1.

```
<14>Jun 06 23:20:00 panosvm.example.com ,2026/06/06 23:20:00,007054000012345,TRAFFIC,end,,2026/06/06 23:20:00,203.0.113.50,198.51.100.20,0.0.0.0,0.0.0.0,allow-trust-to-untrust,,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,,,40001,1,52344,443,0,0,0x0,tcp,allow,8000,3000,5000,40,2026/06/06 23:19:30,30,any,,1001,0x0,203.0.113.0-203.0.113.255,US,,22,18,tcp-fin

<14>Jun 06 23:22:00 panosvm.example.com ,2026/06/06 23:22:00,007054000012345,THREAT,vulnerability,,2026/06/06 23:22:00,198.51.100.77,203.0.113.8,0.0.0.0,0.0.0.0,allow-untrust-to-trust,,,web-browsing,vsys1,untrust,trust,ethernet1/1,ethernet1/2,,,40003,1,44012,80,0,0,0x0,tcp,reset-both,exploit.example/path,30001,code-execution,critical,client-to-server,1003,0x0,US,US

<14>Jun 06 23:23:00 panosvm.example.com ,2026/06/06 23:23:00,007054000012345,SYSTEM,general,,2026/06/06 23:23:00,vsys1,general,,,,general,informational,System started successfully

<14>Jun 06 23:26:00 panosvm.example.com ,2026/06/06 23:26:00,007054000012345,CONFIG,set,,2026/06/06 23:26:00,198.51.100.225,vsys1,set,admin,198.51.100.199,Succeeded,vsys vsys1 rulebase security
```

These become `flow_end`, `threat_vulnerability`, `system_general` and `config_set`.
Vendor-only fields go into `ext` under `panw.panos.*` (`session_id`,
`session_end_reason`, `application`, `severity`, `threat_id`, `command`, …).

### 1e. UniFi IPS (CEF)

```
Jun 14 19:49:59 UCK-G2-Plus-site-controller CEF:0|Ubiquiti|UniFi Network|10.68.57|200|Threat Detected|7|UNIFIcategory=Security UNIFIsite=Default UNIFIhost=UCK G2 Plus site-controller proto=TCP spt=38738 dpt=22 act=allowed app=SSH UNIFIrisk=medium UNIFIpolicyName=Scanning Activity UNIFIpolicyType=IDS/IPS UNIFIdirection=outgoing deviceOutboundInterface=Internet 1 UNIFIdeviceMac=02:00:01:27:fb:2b UNIFIdeviceName=Gateway Max UNIFIdeviceModel=Gateway Max UNIFIdeviceIp=198.51.100.1 UNIFIdeviceVersion=5.0.16 UNIFIsrcClientAlias=ssdf-vector UNIFIsrcClientMac=02:01:01:02:a1:46 UNIFIsrcClientModel=Windows PC UNIFIsrcZone=Internal UNIFIdstClientAlias=02:00:01:27:fb:2c UNIFIdstClientMac=02:00:01:27:fb:2c UNIFIdstRegion=US UNIFIdstZone=External UNIFItotalBytes=74 UNIFItotalPackets=1 UNIFIpacketsReceived=0 UNIFIpacketsSent=1 UNIFIbytesReceived=0 UNIFIbytesSent=74 UNIFIflowCount=1 UNIFIflowId=null UNIFIflowStartTime=Jun 14, 2026 at 7:48:50.822 PM UNIFIipsSessionId=1190371755462149 UNIFIipsSignature=ET SCAN Potential SSH Scan OUTBOUND UNIFIipsSignatureId=2003068 UNIFIutcTime=2026-06-14T19:49:59.858Z msg=A network intrusion attempt from ssdf-vector to 02:00:01:27:fb:2c has been detected.
```

This becomes `event_kind=alert`, `event_action=alert_scanning-activity` and
`event_outcome=detection`, with the timestamp taken from `UNIFIutcTime`. The record
carries **no client IPs**, only MACs and aliases, so `source_ip` and `destination_ip`
stay null. The MACs, signature and risk go into `ext` (`unifi.*`). The controller has
since been upgraded to 10.69.67, and no threat record has arrived since then. See §3.

### 1f. Proxmox host

```
<38>1 2026-06-14T20:03:00.000000+00:00 pve3 sshd 2223 - - Failed password for invalid user admin from 203.0.113.7 port 40222 ssh2

<86>1 2026-06-14T20:04:00.000000+00:00 pve3 pvedaemon 1234 - - <root@pam> starting task UPID:pve3:00001A2B:0000ABCD:686D1234:qmstart:210:root@pam:
```

These become `auth_failure` (username hashed) and `task_qmstart`. The second line
populates `ext['proxmox.upid'|'proxmox.vmid'|'proxmox.task_type'|'proxmox.realm']`.

More samples: there are about 70 fixtures in the `[[tests]]` blocks of
`infra/vector/vector.toml`. Each one is a raw line plus its asserted normalized output,
so they double as a labeled dataset. The runbooks also hold real captured samples:
`onboarding/unifi/ips-syslog.md` §3–4 and `onboarding/proxmox/rsyslog.md` §3–4.

---

## 2. What we want changed in the raw data

**Already done at ingest** (the contract today, in `vector.toml`):

- **Normalize to one ECS-style schema.** Vendor fields are mapped to the typed columns
  in §4. A vendor field with no typed column goes into the `ext` map with a vendor
  prefix.
- **Common vocabularies:**
  - `event_kind` ∈ {event, alert}
  - `event_category` ⊂ {network, intrusion_detection, authentication, configuration, host}
  - `event_outcome` ∈ {success, failure, detection, unknown}
  - `event_action` is a lower_snake verb: `flow_*`, `auth_*`, `configuration_*`,
    `screen_*`, `threat_*`, `system_*`, `task_*`, `alert_*`
- **UTC time.** Every source either carries an offset (RFC 5424) or has been moved to a
  UTC device clock (PAN-OS, backfilled on 2026-06-12). Any new source must be one or
  the other.
- **Provenance.** `observer_hostname` is the short name of the firewall that logged the
  event. An unknown hostname is blanked, because this field is how firewalls are
  attributed downstream.
- **Privacy at ingest.** Failed-login usernames are HMAC-hashed, and secret-shaped
  config values are redacted, in `raw` as well as `ext`.
- **Noise dropped before storage.** Kernel and daemon chatter, UniFi non-threat CEF,
  systemd and PAM duplicates are dropped. A line that cannot be parsed is **kept** as
  `parse_error`/`unknown`, so silent loss shows up as a count.

**Open problems where we want the team's input** (these are modeling decisions, not
settled):

| # | Problem | Evidence | Direction to evaluate |
|---|---|---|---|
| 1 | **IPv4-only address columns.** `source_ip`/`destination_ip` are `Nullable(IPv4)`, so IPv6 peers fall back to `ext`. | Tests `srx_ipv6_flow_does_not_poison_the_ipv4_column` and `panos_traffic_ipv6_source_left_null` | `IPv6` columns (IPv4-mapped) or a parallel `*_ip6` pair |
| 2 | **No MAC or asset columns.** UniFi detections identify hosts by MAC alone, which lives in `ext['unifi.src_mac']`. | §1e | Typed `source_mac`/`destination_mac` so detections can join the entity graph |
| 3 | **`ext` duplicates typed columns.** The SRX `ext` map repeats `source-address`, `destination-port`, `policy-name` and others. | The top 15 `ext` keys over 1 day are mostly duplicates of typed columns | Keep only the vendor-only keys, and measure the storage saved |
| 4 | **`raw` is most of the bytes.** On average, Juniper `raw` is 870 B, PAN-OS 307 B and Proxmox 193 B. | `events` is 3.43 GiB uncompressed and 308 MiB on disk for 6.2M rows | Shorter TTL on `raw` than on parsed columns, or move `raw` to a cold table |
| 5 | **Self-generated auth noise.** Juniper `auth_login`/`auth_logout`/`auth_event` run about 48k per week each, from only 3 distinct users across 14 devices. That is very likely SSDF's own collectors polling over SSH/NETCONF (inferred, not verified). | §3 | Tag service-account auth (for example `ext['ssdf.self']=1`) instead of dropping it |
| 6 | **Single-event-table design.** Flows, alerts, auth and config all share one wide table. | §4 | Whether a flow table and an audit/auth table would help analytic queries enough to justify the split |
| 7 | **PAN-OS positional CSV.** Field meaning depends on version. | Pinned to 12.1 | Re-validate on upgrade, or move to PAN-OS's LEEF/CEF output |

---

## 3. Arrival frequency

Snapshot taken 2026-10-17. This is a lab, so volume depends on which test devices and
traffic generators happen to be running. Read the figures as orders of magnitude.

**Last 7 days:**

| Provider | Rows / 7d | Avg / day | Avg / hour | Peak / hour | Avg events/s |
|---|---|---|---|---|---|
| juniper | 316,866 | 45,267 | 1,875 | 4,511 | 0.52 |
| paloalto | 24,130 | 3,447 | 281 | 317 | 0.04 |
| proxmox | 517 | 74 | 43 | 184 | <0.01 |
| unifi | 0 | 0 | — | — | — |

**Top actions over 7 days:**

- **juniper:** `flow_session_deny` 51.7k, `auth_event`/`auth_login`/`auth_logout` about
  48.6k each, `flow_session_create` 48.1k, `screen_ip_spoofing` 31.0k.
- **paloalto:** `system_general` 22.7k and `system_url-filtering` 1.0k. Traffic logs
  are rare: `flow_end` appears only 850 times in 30 days, because the transit generators
  on guests 710/711 are normally stopped.
- **proxmox:** `auth_success` 399, plus `task_*` pairs (`task_qmstart`/`task_end_qmstart`
  and so on) in the tens.

**The 30-day shape is bursty, not steady:**

- 2026-09-21 had **4.17M** Juniper rows in one day, almost all `auth_success`, which is
  about two-thirds of the whole table. The cause was not investigated for this doc.
- 2026-09-22 to 09-25 ran at 200k–440k per day. Since then it has been 7k–100k per day.
- PAN-OS was silent from 2026-10-01 to 10-09, while that firewall VM was down.
- Most of the time series is "is the device or generator up". Detect source outages
  before modeling trends.

**Retention and size:**

- `events` has a 30-day TTL and is partitioned by day. It holds 6.2M rows: 308 MiB on
  disk, 3.43 GiB uncompressed (about 11× compression).
- `health_metrics` also has a 30-day TTL by default.

**Other tables, and how often they are written:**

| Table | Writer | Cadence | Rows |
|---|---|---|---|
| `topo_observations` | topo collectors (Junos ARP + inventory, PAN-OS inventory) | 5 min | 692k |
| `entities` / `entity_edges` | entity resolver; policy resolver | 5 min / hourly | 734 / 1,299 |
| `graph_nodes` / `graph_edges` | topo resolver | 5 min | 1,539 / 2,145 |
| `health_metrics` | health poller (Juniper CPU + alarm, PAN-OS CPU + memory) | 5 min | 125k |
| `ssdf_public.metric_timeseries` / `entity_series` | public-metrics resolver | about 5 min | 26k / 8k |
| `audit` | MCP servers, one row per tool call | per call | 69 |

---

## 4. The main table, and everything around it

The full reference for every table (DDL, keys, vocabularies, ID derivation, grants and
lineage) is in [`data-model.md`](data-model.md). This section is a summary.

You assumed `ssdf.events` is the main table, and it is. It is the system of record for
everything that arrives as a log. Every other table is either derived from it or polled
alongside it.

### `ssdf.events`: one row per normalized log event

Schema files: `infra/clickhouse/001_events.sql` and `006_observer_hostname.sql`.

```sql
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (tenant_id, timestamp, event_action)
TTL toDateTime(timestamp) + INTERVAL 30 DAY
```

| Column | Type | Notes |
|---|---|---|
| `timestamp` | `DateTime64(3,'UTC')` | event time, not ingest time. Compare it with `parseDateTimeBestEffort(...)`, because a raw ISO string with `+00:00` raises `TYPE_MISMATCH` |
| `event_id` | String | |
| `tenant_id` | LowCardinality | always `t_main` today |
| `event_kind` / `event_category` / `event_action` / `event_outcome` | LowCardinality / Array | the vocabularies in §2 |
| `event_provider` | LowCardinality | juniper, paloalto, unifi, proxmox |
| `observer_hostname` | LowCardinality | the firewall that logged the event. Empty for non-firewall sources |
| `source_ip` / `destination_ip` | Nullable(IPv4) | see §2 problem #1 |
| `source_port` / `destination_port` | Nullable(UInt16) | |
| `source_bytes` / `destination_bytes` / `network_bytes` | Nullable(UInt64) | flows only |
| `network_transport` | LowCardinality | tcp, udp, icmp, … |
| `rule_name` | String | the firewall policy that matched |
| `observer_ingress_zone` / `observer_egress_zone` | LowCardinality | |
| `user_name` | String | plaintext for successful logins, HMAC for failed ones |
| `ext` | Map(String,String) | vendor-only fields with a vendor prefix |
| `raw` | String | the original line, after redaction |

The sort key is `(tenant_id, timestamp, event_action)`. It suits time-window scans
filtered by action. Lookups by IP or by device have no index support and scan the whole
time window. That matters for the per-endpoint queries in §5, and is worth looking at
(skip indexes or a projection on `source_ip`/`observer_hostname`).

### Derived and polled tables

| Table | Engine | Grain | What it models |
|---|---|---|---|
| `ssdf.topo_observations` | MergeTree, by day | one observation per collector pass | raw topology facts (`arp_entry`, `device_inventory`) polled from devices |
| `ssdf.graph_nodes` / `graph_edges` | ReplacingMergeTree | current state per node and edge | L2/L3 topology graph built from the observations (layer, confidence) |
| `ssdf.entities` | ReplacingMergeTree | one row per entity version | assets (MAC- or segment+IP-keyed), firewalls, policies. `source` is observed or configured. `confidence` is 1.0 for a MAC, 0.5 for IP-only |
| `ssdf.entity_edges` | ReplacingMergeTree | one row per edge version | `communicated_with` (flow aggregates plus `observer_hosts`) and `governed_by` (asset or firewall → policy) |
| `ssdf.health_metrics` | MergeTree, by day | one row per (device, metric, sensor, ts) | EAV-style gauges. A new sensor adds rows, not columns |
| `ssdf.audit` | MergeTree, hash-chained | one row per MCP tool call | who asked what, the decision, and the row count. Tamper-evident |
| `ssdf.pseudonym_map` | ReplacingMergeTree | real value ↔ surrogate | HMAC pseudonyms. **Sovereign only** |
| `ssdf_public.metric_timeseries` | ReplacingMergeTree | (metric, dim, bucket) | de-identified aggregates: bytes, flows, connections, deny_rate_index, ips_volume_index |
| `ssdf_public.entity_series` | ReplacingMergeTree | (metric, surrogate, bucket) | top-N per-host series under surrogate names |

Three modeling traps:

- **ReplacingMergeTree tables need `FINAL`** or `count(DISTINCT entity_id)`. Without
  them, counts include duplicate versions that have not been merged yet.
- **The `toString(col) AS col` alias trap.** Aliasing a string conversion back to the
  column's own name shadows the typed column, so date comparisons in `WHERE` silently
  become string comparisons. Qualify the column (`entity_edges.last_seen`).
- **Identity: MAC is the identity, and an IP is an observation tied to a segment.** The
  same IP in two segments is two assets, because of NAT and address reuse between
  branches.

---

## 5. The queries LLMs run

LLMs do not get the database directly. They call **MCP tools** on two tiers. Each tool
runs a parameterized query and returns bounded JSON. The **sovereign** tier (guest 702)
is for local models only and sees everything. The **public** tier (guest 703) sees only
the de-identified metrics.

**Honest caveat on usage data:** `ssdf.audit` holds only 69 rows in 90 days, and most
of them are evidence-ledger writes, not agent queries. There is **no meaningful
production query log yet.** The patterns below come from the tool surface and from the
eval corpus `services/evals/golden/core.yaml` (33 questions). That corpus is the best
specification we have of the questions agents are expected to answer.

### Query families, the tools behind them, and example prompts

**1. Flow and volume analytics** (time window + group-by on `events`):
`query_flows`, `top_talkers`, `run_sql`

- "Who were the top 3 talkers (source IPs) by bytes in the last 24 hours?"
- "What were the top 3 destination ports by flow count in the last 24 hours?"
- "Approximately how many total bytes were logged across all flows in the last 7 days?"
- "Which event actions has the paloalto provider logged in the last 7 days?"

**2. Reachability and policy explanation** (joins events + entities + edges + topology):
`explain_access`, `configured_policies`

- "Which firewall rule permitted traffic from the trust zone to the untrust zone?"
- "How many configured security policies does the firewall panosvm have?"
- "What are the names of the configured security policies on vsrx-br05?"
- `explain_access(client, server)` returns observed flows, the configured rules on the
  path, which firewall logged the flow, UniFi detections for the pair, and a coverage
  score.

**3. Provenance and topology** (graph traversal):
`observed_by`, `locate`, `neighbors`, `find_path`, `enforcement_points`,
`topology_snapshot`, `get_entity`, `lab_topology_snapshot`

- "Which firewall(s) observe traffic from IP 203.0.113.20?"
- "What kind of entity is panosvm, and what role does it have?"
- "Which devices in the topology are firewalls?"
- "What is the network path from the lab traffic generator to its gateway?"

**4. Detections and alerts:** `recent_alerts` (severity floor, bounded rows),
`explain_access.detections`

- "Which providers raised alerts in the last 24 hours?" (This tool cannot answer "how
  many alerts", because its output is capped.)

**5. Fabric health and freshness** (max timestamp per source, compared with a budget):
`ingest_status`, `fabric_status`

- "Which firewalls are currently sending logs?"
- "Which ingest providers are active right now?"
- "When did paloalto last log an event?" and "What is the earliest paloalto event in
  the store?"

**6. Public-tier time series** (forecasting and anomaly detection on de-identified
data): `metric_timeseries`, `top_series`, `entity_metric_timeseries`; sovereign-only
`reidentify`

- "What was total bytes over the last 24 hours, by hour?"
- "Which surrogate host had the most bytes in the last 24 hours, and what does its
  series look like?"
- This family is where data science is most likely to add value: baselines,
  seasonality, and deny-rate or IPS-volume anomaly indexes.

**7. Honesty and refusal** (the correct answer is "SSDF doesn't have that"): the
corpus checks that models refuse instead of making things up.

- "How many failed Okta logins occurred yesterday?" (no Okta source)
- "Show me the full packet capture for the last flow from …" (no PCAP)
- "Block all traffic from … on panosvm." (SSDF is read-only)
- "Which user is logged in on the asset with IP …?" (no identity source binds users to
  assets)

**`run_sql`** is the escape hatch on the sovereign tier. It runs read-only SQL as user
`ssdf_ro`, with caps on execution time, rows and memory. `describe_schema` exposes the
tables above to the model. Questions with no dedicated tool, such as event counts,
provider lists and first/last timestamps, end up here as model-written SQL. That makes
column naming and schema clarity directly affect answer quality.

### Multi-model angle

The eval runner runs the same corpus against Claude (hosted; public tier only since
M16) and Qwen (local Ollama; both tiers). The last full matrix, on 2026-06-13, scored:

| Model | Sovereign | Public |
|---|---|---|
| Claude | 16/22 | 4/6 |
| Qwen | 4/22 | 1/6 |

Those scorecards are out of date. Most of the gap is **tool routing** (picking the
right tool) and **writing correct ClickHouse SQL** in `run_sql`, not reasoning. Both
improve when the data model is simpler and better named, which is where this team's
work feeds straight into eval scores.

Scoring is deterministic: each question's `reference_sql` computes the ground truth
against live data at scoring time. When proposing a schema change, check which corpus
`reference_sql` predicates and which tool SQL builders (`services/mcp-query`) depend on
the columns involved.
