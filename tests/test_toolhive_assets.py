from pathlib import Path
from runpy import run_path

import pytest


def test_toolhive_no_access_profile_is_fail_closed():
    path = Path("deploy/toolhive/permission-profiles/no-access.json")
    validate_profile = run_path("scripts/run_toolhive_verified.py")["validate_profile"]

    assert validate_profile(path) == "none"


def test_toolhive_launcher_enables_provenance_and_runtime_guards():
    module = run_path("scripts/run_toolhive_verified.py")
    profile = Path("deploy/toolhive/permission-profiles/no-access.json")
    command = module["build_command"](
        executable="thv",
        server="catalogued-server",
        workload_name="guarded-server",
        proxy_port=4484,
        profile_path=profile,
    )

    assert command[:3] == ["thv", "run", "catalogued-server"]
    assert command[command.index("--image-verification") + 1] == "enabled"
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--permission-profile") + 1] == str(profile)
    assert command[command.index("--host") + 1] == "127.0.0.1"
    assert "--isolate-network" in command
    assert "--strict-protocol-validation" in command
    assert "--enable-audit" in command


def test_toolhive_launcher_rejects_an_unrestricted_profile(tmp_path: Path):
    profile = tmp_path / "unsafe.json"
    profile.write_text(
        '{"privileged":false,"network":{"mode":"bridge",'
        '"outbound":{"insecure_allow_all":true}}}',
        encoding="utf-8",
    )
    validate_profile = run_path("scripts/run_toolhive_verified.py")["validate_profile"]

    with pytest.raises(ValueError, match="unrestricted outbound"):
        validate_profile(profile)


def test_toolhive_runtime_verifier_compares_declaration_with_container_state():
    verify_runtime = run_path("scripts/verify_toolhive_no_access_runtime.py")[
        "verify_runtime"
    ]
    result = verify_runtime(
        {
            "name": "guarded-server",
            "image": "registry.example/server@sha256:" + "1" * 64,
            "permission_profile": {
                "read": [],
                "write": [],
                "network": {"mode": "none"},
                "privileged": False,
            },
        },
        {
            "HostConfig": {
                "NetworkMode": "none",
                "Binds": None,
                "Privileged": False,
                "CapDrop": ["ALL"],
                "PidMode": "",
                "IpcMode": "private",
                "Devices": None,
            }
        },
    )

    assert result["image_digest_pinned"] is True
    assert result["host_mounts"] == 0
    assert result["actual_network_mode"] == "none"


def test_toolhive_runtime_verifier_rejects_runtime_drift():
    verify_runtime = run_path("scripts/verify_toolhive_no_access_runtime.py")[
        "verify_runtime"
    ]

    with pytest.raises(RuntimeError, match="actual_no_network"):
        verify_runtime(
            {
                "permission_profile": {
                    "read": [],
                    "write": [],
                    "network": {"mode": "none"},
                }
            },
            {
                "HostConfig": {
                    "NetworkMode": "bridge",
                    "Binds": None,
                    "Privileged": False,
                    "CapDrop": ["ALL"],
                    "PidMode": "",
                    "IpcMode": "private",
                    "Devices": None,
                }
            },
        )
