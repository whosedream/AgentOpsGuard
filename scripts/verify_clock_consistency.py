#!/usr/bin/env python3
"""Cross-check WSL clocks against Windows Stopwatch without changing host time."""
from __future__ import annotations

import argparse
import asyncio
from datetime import UTC, datetime
import json
import math
from pathlib import Path
import time

POWERSHELL = Path('/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe')
TOLERANCE = 0.02


def read_clocks():
    return {"wall": time.time(), "monotonic": time.monotonic(),
            "raw": time.clock_gettime(time.CLOCK_MONOTONIC_RAW)}


def evaluate_window(before, after, reference_seconds, tolerance=TOLERANCE):
    elapsed = {key: after[key] - before[key] for key in before}
    valid_reference = math.isfinite(reference_seconds) and reference_seconds > 0
    errors = {key: abs(value / reference_seconds - 1) if valid_reference and math.isfinite(value)
              else None for key, value in elapsed.items()}
    return {"reference_seconds": reference_seconds, "linux_seconds": elapsed,
            "relative_errors": errors,
            "passed": all(value is not None and value <= tolerance for value in errors.values())}


async def measure_clock(samples=2, seconds=5):
    result = {"started_at": datetime.now(UTC).isoformat(), "reference": "Windows Stopwatch",
              "tolerance": TOLERANCE, "samples": [], "passed": False,
              "scope": "same physical host; not an independent load generator"}
    if not POWERSHELL.is_file():
        return {**result, "error": "independent_reference_unavailable"}
    # Only bounded numeric inputs enter this fixed command. No profile, credentials,
    # clock adjustment, NTP changes, or host administrator privileges are involved.
    if not 1 <= samples <= 400 or not 1 <= seconds <= 30:
        raise ValueError("clock sampling outside bounded limits")
    script = ("$s=[Diagnostics.Stopwatch]::StartNew(); "
              "[Console]::WriteLine(0); [Console]::Out.Flush(); "
              f"for($i=0;$i -lt {int(samples)};$i++) {{ "
              f"[Threading.Thread]::Sleep({int(seconds * 1000)}); "
              "[Console]::WriteLine($s.Elapsed.TotalSeconds.ToString("
              "[Globalization.CultureInfo]::InvariantCulture)); [Console]::Out.Flush() }")
    process = await asyncio.create_subprocess_exec(str(POWERSHELL), '-NoProfile', '-NonInteractive',
        '-Command', script, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL)
    try:
        previous_reference = float(await asyncio.wait_for(process.stdout.readline(), 20))
        before = read_clocks()
        for _ in range(samples):
            reference = float(await asyncio.wait_for(process.stdout.readline(), seconds * 3 + 10))
            after = read_clocks()
            result['samples'].append(evaluate_window(before, after, reference - previous_reference))
            before, previous_reference = after, reference
        result['passed'] = await asyncio.wait_for(process.wait(), 5) == 0 and all(
            sample['passed'] for sample in result['samples'])
    except (TimeoutError, ValueError, OSError) as error:
        result['error'] = type(error).__name__  # Never expose subprocess output.
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
    result['finished_at'] = datetime.now(UTC).isoformat()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=3)
    parser.add_argument('--seconds', type=int, default=10)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError('preserve the previous clock report')
    result = asyncio.run(measure_clock(args.samples, args.seconds))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as handle:
        json.dump(result, handle, indent=2)
        handle.write('\n')
    print(json.dumps(result))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
