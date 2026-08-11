import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WSL_DIAGNOSTICS = ROOT / "scripts/diagnose_wsl_proxy.sh"
WINDOWS_DIAGNOSTICS = ROOT / "scripts/diagnose_windows_proxy.ps1"


def test_wsl_diagnostics_has_valid_shell_syntax_and_help():
    subprocess.run(["bash", "-n", WSL_DIAGNOSTICS], check=True)
    result = subprocess.run(
        [WSL_DIAGNOSTICS, "--help"],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "--host HOST --port PORT" in result.stdout
    assert "read-only" in result.stdout


def test_wsl_diagnostics_rejects_invalid_port_without_network_access():
    result = subprocess.run(
        [WSL_DIAGNOSTICS, "--host", "127.0.0.1", "--port", "not-a-port"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "port must be an integer from 1 to 65535" in result.stderr


def test_diagnostics_do_not_contain_machine_specific_or_mutating_commands():
    linux_text = WSL_DIAGNOSTICS.read_text(encoding="utf-8")
    windows_text = WINDOWS_DIAGNOSTICS.read_text(encoding="utf-8")

    for forbidden in (
        "/mnt/d/CodeField",
        "usermod",
        "chmod 666",
        "systemctl restart",
        "docker pull",
        "sudo",
        "sk-",
    ):
        assert forbidden not in linux_text
    assert "CommandLine" not in windows_text
    assert "Set-ItemProperty" not in windows_text
    assert "New-NetFirewallRule" not in windows_text
    assert "$pid =" not in windows_text.lower()


def test_windows_diagnostics_is_parameterized_and_read_only():
    text = WINDOWS_DIAGNOSTICS.read_text(encoding="utf-8")

    assert "[string[]]$Ports" in text
    assert "$portArgument -split ','" in text
    assert "Get-NetTCPConnection" in text
    assert "ProxyServer" in text
    assert "Get-NetIPAddress" in text
