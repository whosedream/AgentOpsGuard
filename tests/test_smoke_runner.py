from pathlib import Path


def test_SPEC_P1_003_compose_smoke_script_exists():
    script = Path("scripts/compose_smoke.py")
    assert script.exists(), "compose smoke runner must exist"
