# Generic rsyslog sender → SSDF host logs

For hosts that run rsyslog but not Vector (Debian LXCs, NAS boxes). The sender
forwards warning-and-worse syslog, systemd unit failures, coredump notices and
an rsyslog heartbeat to the SSDF ingest host on **TCP 519**, RFC5424 with
RFC6587 octet-counted framing. Records land in `ssdf.host_logs` with
`source = 'syslog'`.

Put this in `/etc/rsyslog.d/49-ssdf.conf`, using your ingest address in place
of the example one:

    module(load="impstats" interval="300" severity="7")

    if (prifilt("*.warning")
        or ($programname == "systemd" and re_match($msg, "Failed with result|entered failed state"))
        or ($programname == "systemd-coredump" and $msg contains "dumped core")
        or $programname == "rsyslogd-pstats") then {
        action(type="omfwd" target="198.51.100.150" port="519" protocol="tcp"
               template="RSYSLOG_SyslogProtocol23Format" TCP_Framing="octet-counted"
               queue.type="LinkedList" queue.size="10000"
               action.resumeRetryCount="-1")
    }

- It is ONE rule on purpose: separate rules for each condition would forward a
  line matching several of them more than once.
- `impstats` emits a stats line every 300 s. It is the liveness heartbeat: the
  ingest host counts every received line per minute but stores only warnings
  and worse, unit failures and coredumps.
- `action.resumeRetryCount="-1"` with the LinkedList queue retries forever and
  buffers in memory while the ingest host is down.

Validate before restarting, so a bad drop-in never stops a working daemon:

    rsyslogd -N1 && systemctl restart rsyslog

Then check with `logger -p user.err ssdf-canary`. Rollback: remove the drop-in
and `systemctl restart rsyslog`.

## UDP fallback

Appliances that cannot do TCP can send plain RFC5424 or RFC3164 syslog to
**UDP 519** instead. The same Vector listener parses both. UDP has no
delivery guarantee, so prefer TCP wherever the sender supports it.

The ingest host must allow the sender on TCP/UDP 519 (see
`infra/firewall/ct102-ingest.nft`).
