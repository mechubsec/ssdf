# Linux host logs → SSDF

`vector-agent.toml` is a Vector agent config that ships a host's journald
errors to the SSDF ingest host (TCP 6000, Vector-to-Vector). It sends:

- every journal entry at priority warning (4) or worse,
- systemd unit failures (`Failed with result`, `entered failed state`),
- coredump notices (`dumped core`),
- a heartbeat line every 5 minutes, so a quiet host still shows as alive.

Everything else stays on the host. Records land in `ssdf.host_logs`; liveness
in `ssdf.host_log_senders`.

## Install

1. Install Vector: Arch `pacman -S vector`; Debian/Ubuntu via the upstream
   Vector apt repository.
2. Copy `vector-agent.toml` to `/etc/vector/vector.toml` and set the `ssdf`
   sink `address` to your ingest host (`<ingest-ip>:6000`).
3. Point the service at it in `/etc/default/vector` (the packaged unit runs
   `vector` without `--config`, and its default config is
   `/etc/vector/vector.yaml`):

       VECTOR_CONFIG=/etc/vector/vector.toml

4. Make sure the `vector` service user can read the journal and has a
   writable `data_dir` (the disk buffer lives there):

       usermod -aG systemd-journal vector
       install -d -o vector -g vector /var/lib/vector

5. `systemctl enable --now vector`

## Verify

    logger -p user.err ssdf-canary

The line should appear in `ssdf.host_logs` within a few seconds
(`source = 'journald'`).

The ingest host must allow this sender on TCP 6000 (see
`infra/firewall/ct102-ingest.nft`).
