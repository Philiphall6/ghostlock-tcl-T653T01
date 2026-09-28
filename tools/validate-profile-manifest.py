#!/usr/bin/env python3
"""Fail-closed validation for Android TV kernel profile manifests."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VALID_STATES = {"draft", "analysis_only", "qemu_validated", "hardware_validated"}


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()

    data = json.loads(args.manifest.read_text(encoding="utf-8"))
    failures: list[str] = []

    require(data.get("schema_version") == 1, "schema_version must be 1", failures)
    require(data.get("status") in VALID_STATES, "invalid status", failures)

    kernel = data.get("kernel", {})
    btf_hash = kernel.get("btf_sha256", "")
    image_hashes = kernel.get("accepted_image_sha256", [])
    require(bool(SHA256_RE.fullmatch(btf_hash)), "invalid BTF SHA-256", failures)
    require(bool(image_hashes), "accepted_image_sha256 is empty", failures)
    require(all(SHA256_RE.fullmatch(item or "") for item in image_hashes),
            "invalid accepted kernel SHA-256", failures)
    require(len(image_hashes) == len(set(image_hashes)),
            "duplicate accepted kernel SHA-256", failures)

    firmwares = data.get("firmwares", [])
    require(bool(firmwares), "firmware list is empty", failures)
    versions: set[str] = set()
    firmware_kernel_hashes: set[str] = set()
    for entry in firmwares:
        version = entry.get("version", "")
        require(bool(version), "firmware version is empty", failures)
        require(version not in versions, f"duplicate firmware version: {version}", failures)
        versions.add(version)
        for field in ("ota_sha256", "boot_sha256", "kernel_sha256"):
            require(bool(SHA256_RE.fullmatch(entry.get(field, ""))),
                    f"{version}: invalid {field}", failures)
        firmware_kernel_hashes.add(entry.get("kernel_sha256", ""))

    require(set(image_hashes) == firmware_kernel_hashes,
            "accepted kernel hashes must exactly match firmware entries", failures)

    safety = data.get("safety", {})
    execution_allowed = safety.get("execution_allowed")
    blockers = safety.get("blockers", [])
    require(isinstance(execution_allowed, bool),
            "safety.execution_allowed must be boolean", failures)
    require(isinstance(blockers, list), "safety.blockers must be a list", failures)
    if execution_allowed:
        require(data.get("status") == "hardware_validated",
                "execution requires hardware_validated status", failures)
        require(not blockers, "executable profile cannot retain blockers", failures)
    else:
        require(bool(blockers), "non-executable profile must state blockers", failures)

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1

    print(f"PASS: {data['id']}")
    print(f"status={data['status']}")
    print(f"firmwares={len(firmwares)}")
    print(f"execution_allowed={str(execution_allowed).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
