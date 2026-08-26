# WSL Network and Docker Proxy Diagnostics

These tools consolidate the safe, read-only parts of the legacy WSL proxy scripts. They do not
configure a proxy, restart Docker, change user groups, pull images, or copy files between checkouts.

## 1. Inspect Windows listeners

Run in Windows PowerShell 5.1 or newer:

```powershell
powershell -NoProfile -File scripts\diagnose_windows_proxy.ps1
powershell -NoProfile -File scripts\diagnose_windows_proxy.ps1 -Ports 7890,7897,1080
```

The report distinguishes:

- `loopback`: Windows-only listener such as `127.0.0.1`; a NAT-mode WSL guest usually cannot use
  the Windows gateway address to reach it.
- `wildcard`: listener bound to all interfaces; confirm the proxy application's LAN-access and
  authentication settings before using it from WSL.
- `lan-specific`: listener bound to one non-loopback address.

The script prints process names but never process arguments. Windows proxy userinfo is redacted.

## 2. Inspect WSL and Docker

Run from the WSL checkout:

```bash
./scripts/diagnose_wsl_proxy.sh
./scripts/diagnose_wsl_proxy.sh --host 172.25.96.1 --port 7890
```

Use the host and port actually reported by the Windows listener check. Do not copy the example
address: the WSL gateway changes after restart, and a transparent tunnel may expose no HTTP proxy
listener at all.

Without endpoint arguments the script checks only local route/Docker state. With an endpoint it
performs one TCP probe and one HTTP CONNECT probe to the Docker registry. Requested endpoint
failure returns a non-zero status.

## Why configuration is not automatic

The legacy scripts assumed port `7890`, treated the same port as both HTTP and SOCKS, overwrote a
Docker systemd drop-in, restarted Docker, and placed Docker registries in `NO_PROXY`. On a machine
using a transparent Windows tunnel with no listener, that creates a stale daemon proxy and breaks
image pulls.

Configure Docker only after the two diagnostics prove a reachable HTTP proxy. Keep machine-local
configuration outside Git, use a dedicated systemd drop-in, and record how to disable it. Docker
group membership is root-equivalent; grant it deliberately through normal host administration,
not as a side effect of a verification script.

## Legacy merge decisions

| Legacy file | Decision |
|---|---|
| `diagnose-proxy.sh`, `check-proxy-v2.ps1`, `check-listeners.ps1` | Safe read-only behavior consolidated here; fixed-port scans and process arguments removed. |
| `docker-daemon-proxy.sh`, `verify-proxy-and-pull*.sh` | Rejected: mutate systemd/restart Docker; proxy assumptions were not valid on the current host. |
| `fix-docker-perm.sh` | Rejected: hard-coded user and unnecessary on the current WSL installation. |
| `restart-and-verify.sh`, service wait scripts | Rejected: hard-coded old paths/container names; use `scripts/compose_smoke.py`. |
| `mutation_cases.py`, `run_large_scale_test.py` | Already merged as corrected supersets; source versions must not overwrite them. |
| `run-large-scale.sh`, `run-all-tests*.sh`, `get-report.sh` | Rejected: embedded credential and old cross-repository paths. Rotate/revoke that credential. |

## Validation

```bash
bash -n scripts/diagnose_wsl_proxy.sh
uv run pytest -q tests/test_network_diagnostics.py
uv run ruff check .
```
