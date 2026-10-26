# Proxmox host audit → SSDF (M11 onboarding)

SSDF ingests the pve3 hypervisor host's auth + admin-action syslog
(`pvedaemon`/`pveproxy`/`sshd`/`sshd-session` + the CLI admin tools `pct`/`qm`/`pvesh`)
via remote rsyslog. SSDF never configures the source in its own data path; the operator
applies the rsyslog drop-in on pve3.

## 0. Verify the host clock is accurate (do this FIRST)
SSDF stores event time from the syslog timestamp. Run on pve3:
  timedatectl
A **UTC** zone is ideal, but **not required**: the rsyslog template below forwards
RFC5424 (ISO-8601 *with the UTC offset*), so SSDF stores correct UTC even from a
local-zone host. Live-proven on pve3 running `America/New_York (EDT, -0400)` — the
`-04:00` offset on the wire is applied at parse time, so an EDT 19:05 event stores as
23:05 UTC. What matters is that the clock is **not skewed** (NTP-synced). This is the
robust escape from the PAN-OS/SRX naive-local-time trap.

## 1. rsyslog drop-in (forward to Vector)
rsyslog is not installed on a stock PVE host — install it first if needed:
  apt-get install -y rsyslog   # adds the package to the hypervisor; reversible
Create `/etc/rsyslog.d/49-ssdf.conf` on pve3:

  if (prifilt("auth,authpriv,daemon.*") or prifilt("*.warning")
      or ($programname == "systemd" and re_match($msg, "Failed with result|entered failed state"))
      or ($programname == "systemd-coredump" and $msg contains "dumped core")) then {
      action(type="omfwd" target="198.51.100.150" port="517" protocol="udp"
             template="RSYSLOG_SyslogProtocol23Format")
  }

(`protocol="udp"` = plain UDP; `RSYSLOG_SyslogProtocol23Format` = RFC5424 with offset
timestamp.) It is ONE rule so a line matching several conditions is sent once.
The security path is unchanged: the facility filter is the coarse gate and Vector's
`proxmox_sec` filter still applies its app + known-pattern allow-list, so non-security
daemon noise never reaches `ssdf.events`. The extra conditions (warnings and worse,
unit failures, coredumps) feed the same stream into `ssdf.host_logs` as
`source = 'proxmox'`, where Vector keeps only errors.

Apply this on **every PVE node** in the cluster, each forwarding to the same address
(the ingest host must allow each node on UDP 517).

## 2. Restart + verify on the wire
On pve3:  systemctl restart rsyslog
On guest 700 (was ct102): tcpdump -n -A -i any udp port 517 -c 20
Trip an event (e.g. from another host: `ssh baduser@pve3` with a wrong password) and
confirm the line arrives.

Two live-found realities the VRL handles:
  - On OpenSSH 9.8+ / Debian 13, per-connection auth logs under appname
    **`sshd-session`** (not `sshd`) — the filter/transform match the whole `sshd*` family.
  - CLI/API-driven admin tasks log their `starting|end task UPID:` lines under
    **`pct`/`qm`/`pvesh`** (not `pvedaemon`). On this SSH/CLI/MCP-driven host those are
    the bulk of the admin-action audit, so the filter app gate includes them. Web-UI
    tasks still arrive under `pvedaemon`/`pveproxy`.

## 3. Deployment-specific values (used by the nft allow-list + ext.proxmox.node)
  - PVE3_LAN_IP    = **198.51.100.201**  (src from `ip -4 route get 198.51.100.150` on pve3;
                     nft allow-list source on guest 700 (was ct102); see infra/firewall/ct102-ingest.nft)
  - NODE_HOSTNAME  = pve3   (rides ext.proxmox.node)

## 4. Captured samples (real lines from live-proof 2026-06-14 — the VRL test fixtures)
parse_syslog yields appname + message; the proxmox_ecs transform maps them as:
  - pvedaemon "successful auth for user 'root@pam'"         -> authentication / auth_success
  - pvedaemon "authentication failure; rhost=<ip> user=<u>" -> authentication / auth_failure (source_ip)
  - sshd-session "Accepted <m> for <u> from <ip> port <p>"  -> authentication / auth_success (source_ip+port)
  - sshd-session "Failed password for [invalid user] <u> from <ip> port <p>" -> authentication / auth_failure
  - pvesh/pct/qm/pvedaemon "starting task UPID:..:<dtype>:<vmid>:<u>:" -> configuration / task_<dtype>
  - "end task UPID:.. OK"                                    -> configuration / task_end_<dtype> (success)

Real captured wire lines (RFC5424, note the `-04:00` offset → stored UTC):
  <38>1 2026-06-14T19:04:58.902180-04:00 pve3 sshd-session 1355836 - -  Accepted publickey for root from 198.51.100.100 port 50152 ssh2: ED25519 SHA256:...
  <38>1 2026-06-14T19:00:31.000000-04:00 pve3 sshd-session 1353695 - -  Failed password for invalid user baduser_ssdf from 198.51.100.100 port 37744 ssh2
  <30>1 2026-06-14T19:04:59.859251-04:00 pve3 pvesh 1355846 - -  <root@pam> starting task UPID:pve3:0014B078:01177A0E:6A2F339B:vzsnapshot:701:root@pam:
  <30>1 2026-06-14T19:05:00.054009-04:00 pve3 pvesh 1355846 - -  <root@pam> end task UPID:pve3:0014B078:01177A0E:6A2F339B:vzsnapshot:701:root@pam: OK

Dropped as redundant: the sshd pam_unix line that accompanies every failed login
("pam_unix(sshd:auth): authentication failure; logname=... rhost=<ip>") — the
"Failed password for" line above already carries that auth_failure.
