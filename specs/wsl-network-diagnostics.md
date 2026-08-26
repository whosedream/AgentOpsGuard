# WSL Network Diagnostics Contract

## Merge scope

The useful read-only portions of `diagnose-proxy.sh`, `check-listeners.ps1`, and
`check-proxy-v2.ps1` are consolidated into two platform-specific diagnostic entry points:

- `scripts/diagnose_wsl_proxy.sh`
- `scripts/diagnose_windows_proxy.ps1`

The benchmark sources already merged into the repository are retained as-is. One-off scripts that
write Docker systemd configuration, restart services, change group membership, pull images, copy
source files across repositories, or contain credentials are explicitly excluded.

## WSL contract

`diagnose_wsl_proxy.sh` is read-only. With no endpoint arguments it reports the WSL default route,
Docker socket ownership/mode, Docker access, daemon status, and whether a daemon proxy is set,
without printing proxy values. `--host HOST --port PORT` additionally performs one TCP reachability
probe and one HTTP CONNECT probe through that endpoint. A requested but unreachable endpoint
returns non-zero.

The script does not scan a list of ports, infer that a transparent Windows tunnel is an HTTP proxy,
print the public egress IP, dump `/etc/resolv.conf`, modify environment variables, or invoke `sudo`.

## Windows contract

`diagnose_windows_proxy.ps1` is read-only and accepts an overridable, comma-separated `-Ports`
list from Windows PowerShell 5.1 or PowerShell 7. It reports only matching listener address, port,
process ID/name, and whether the bind is loopback, wildcard, or LAN-specific. It also reports
Windows proxy-enabled state, a credential-redacted proxy endpoint, and WSL virtual-adapter
addresses.

The script never prints process command lines and never changes registry, firewall, listeners, or
environment variables. It uses `$ProcessId`, not PowerShell's read-only `$PID` automatic variable.

## Safety invariants

- No API keys, usernames, workspace paths, WSL IPs, or mandatory proxy ports are embedded.
- No `sudo`, `usermod`, Docker socket permission change, `/etc` write, daemon restart, image pull,
  or cross-repository copy occurs.
- Proxy userinfo is never accepted or printed by the WSL script and is redacted in Windows proxy
  settings output.
- Failures are visible through a non-zero exit; neither script claims configuration success.

## Validation

- `bash -n scripts/diagnose_wsl_proxy.sh`
- Windows PowerShell 5.1 parser validation
- `uv run pytest -q tests/test_network_diagnostics.py`
- `uv run ruff check .`
