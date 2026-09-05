#!/usr/bin/env python3
"""Create the local Kubernetes API fault proxy before starting Patroni."""

from __future__ import annotations

import json
import os
import time
from urllib.error import URLError
from urllib.request import Request, urlopen


API = "http://127.0.0.1:8474"


def main() -> None:
    deadline = time.monotonic() + 30
    while True:
        try:
            with urlopen(f"{API}/version", timeout=1) as response:
                if response.status == 200:
                    break
        except URLError:
            if time.monotonic() >= deadline:
                raise RuntimeError("Toxiproxy did not become ready") from None
            time.sleep(0.1)
    body = json.dumps(
        [
            {
                "name": "kubernetes-api",
                "listen": "127.0.0.1:16443",
                "upstream": "kubernetes.default.svc:443",
                "enabled": True,
            }
        ]
    ).encode("ascii")
    request = Request(
        f"{API}/populate",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=5) as response:
        if response.status not in (200, 201):
            raise RuntimeError("Toxiproxy rejected the Kubernetes API proxy")
    os.execvp("patroni", ("patroni", "/etc/patroni/patroni.yml"))


if __name__ == "__main__":
    main()
