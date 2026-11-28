#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate and reconcile the Xenora campaign tracker.

`--check` is deterministic and offline. `--sync` uses the installed `gh` CLI to
refresh PR and issue states from upstream. Independent verification and its
evidence stay under manual review.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TRACKER = ROOT / "docs" / "coordination" / "ascension-tracker.json"
RUNTIME_INVENTORY = ROOT / "docs" / "runtime" / "inventory.json"
REPO = "ranveersoni98/Xenora"

STATES = {
    "UNCLAIMED",
    "CLAIMED",
    "RESEARCHING",
    "IMPLEMENTING",
    "TESTING",
    "PR_OPEN",
    "REVIEW_REQUIRED",
    "MERGED",
    "VERIFIED",
    "BLOCKED",
    "SUPERSEDED",
}
COMPLETED_STATES = {"MERGED", "VERIFIED"}
FINISHED_IMPLEMENTATION_STATES = COMPLETED_STATES | {"SUPERSEDED"}
EVIDENCE = {"A", "B", "C", "D", "E"}
RUNTIME_MILESTONES = {f"R{number}" for number in range(1, 10)}
MILESTONE_STATES = {"PARTIAL", "BLOCKED", "VERIFIED"}
OWNERSHIP_STATES = {
    "DeepSeek-owned",
    "Catminou-owned",
    "CPU contributor-owned",
    "Graphics contributor-owned",
    "Awaiting external dependency",
    "Ready for integration",
    "Verified",
}
PRIORITIES = {"P0", "P1", "P2", "P3"}
REQUIRED = {
    "id",
    "subsystem",
    "description",
    "priority",
    "dependencies",
    "owner",
    "status",
    "evidence_class",
    "ownership_state",
    "assignment_side",
    "counts_toward_personal_workload",
    "issue",
    "pr",
    "test_status",
    "limitations",
}


def load() -> dict:
    return json.loads(TRACKER.read_text(encoding="utf-8"), object_pairs_hook=unique_object)


def save(data: dict) -> None:
    TRACKER.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def service_key(row: dict) -> tuple[str, str, str]:
    return row["library"], row["kind"], row["symbol"]


def nonempty_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def runtime_evidence(data: dict) -> dict:
    inventory = json.loads(
        RUNTIME_INVENTORY.read_text(encoding="utf-8"), object_pairs_hook=unique_object
    )
    services = inventory["services"]
    canonical = {service_key(row) for row in services}
    if len(canonical) != len(services):
        raise ValueError("runtime inventory contains duplicate canonical service keys")

    supplements: dict[tuple[str, str, str], dict] = {}
    for row in data["runtime_service_evidence"]:
        key = service_key(row)
        if key in supplements or key not in canonical:
            raise ValueError(f"duplicate or unknown runtime evidence key {key}")
        if row["evidence_class"] not in EVIDENCE or not nonempty_text(row["evidence"]):
            raise ValueError(f"missing or invalid runtime evidence for {key}")
        if row["evidence_class"] in {"A", "B"} and not all(
            nonempty_text(row.get(field)) for field in ("source", "witness")
        ):
            raise ValueError(f"documented or reproduced behavior requires a source and witness for {key}")
        supplements[key] = {
            "evidence_class": row["evidence_class"],
            "evidence": row["evidence"],
            **({"evidence_source": row["source"]} if row.get("source") else {}),
            **({"evidence_witness": row["witness"]} if row.get("witness") else {}),
        }

    unknown = {"evidence_class": "E", "evidence": "No service-level evidence reviewed in this tracker."}
    aliases = inventory["aliases"]
    statuses = Counter(row["status"] for row in services)
    registration_sources = Counter(row["source"] for row in services)
    row_counts = {
        "canonical_services": len(services),
        "data_import_services": sum(row["data_import"] for row in services),
        "implicit_status_services": sum(not row["status_explicit"] for row in services),
        "manual_services": registration_sources["manual"],
        "typed_services": registration_sources["typed"],
        "aliases": len(aliases),
        "api_set_aliases": sum(row["api_set"] for row in aliases),
        "ordinal_aliases": sum(row["kind"] == "ordinal" for row in aliases),
        **{status: statuses[status] for status in ("implemented", "partial", "stub")},
    }
    summary_mismatches = {
        key: {"declared": inventory["summary"][key], "rows": count}
        for key, count in row_counts.items()
        if inventory["summary"][key] != count
    }
    return {
        "schema_version": 1,
        "evidence_classes": data["evidence_classes"],
        "services": [{**service, **supplements.get(service_key(service), unknown)} for service in services],
        "aliases": aliases,
        "inventory_summary_mismatches": summary_mismatches,
    }


def validate(data: dict) -> None:
    if data.get("schema_version") != 1:
        raise ValueError("schema_version must be 1")
    packages = data.get("work_packages")
    if not isinstance(packages, list):
        raise ValueError("work_packages must be a list")
    seen: set[str] = set()
    ids: set[str] = set()
    for index, package in enumerate(packages):
        label = f"work_packages[{index}]"
        missing = REQUIRED - package.keys()
        if missing:
            raise ValueError(f"{label} missing {sorted(missing)}")
        identifier = package["id"]
        if identifier in seen:
            raise ValueError(f"duplicate work package id {identifier}")
        seen.add(identifier)
        ids.add(identifier)
        if package["status"] not in STATES:
            raise ValueError(f"{identifier}: unknown status {package['status']}")
        if package["evidence_class"] not in EVIDENCE:
            raise ValueError(f"{identifier}: unknown evidence class {package['evidence_class']}")
        if package["ownership_state"] not in OWNERSHIP_STATES:
            raise ValueError(f"{identifier}: unknown ownership state {package['ownership_state']}")
        if package["assignment_side"] not in {"personal", "external"}:
            raise ValueError(f"{identifier}: assignment_side must be personal or external")
        if not isinstance(package["counts_toward_personal_workload"], bool):
            raise ValueError(f"{identifier}: counts_toward_personal_workload must be boolean")
        if package["priority"] not in PRIORITIES:
            raise ValueError(f"{identifier}: unknown priority {package['priority']}")
        for key in ("issue", "pr"):
            value = package[key]
            if value is not None and (not isinstance(value, int) or value <= 0):
                raise ValueError(f"{identifier}: {key} must be null or a positive integer")
        if not isinstance(package["dependencies"], list):
            raise ValueError(f"{identifier}: dependencies must be a list")
        for key in ("subsystem", "description", "test_status", "limitations"):
            if not isinstance(package[key], str):
                raise ValueError(f"{identifier}: {key} must be a string")
        if package["owner"] is not None and not isinstance(package["owner"], str):
            raise ValueError(f"{identifier}: owner must be null or a string")
    for package in packages:
        for dependency in package["dependencies"]:
            if dependency not in ids:
                raise ValueError(f"{package['id']}: unknown dependency {dependency}")
    milestones = data["runtime_acceptance"]
    if len(milestones) != len(RUNTIME_MILESTONES) or {row["id"] for row in milestones} != RUNTIME_MILESTONES:
        raise ValueError("runtime acceptance must contain each of R1–R9 once")
    for milestone in milestones:
        if milestone["status"] not in MILESTONE_STATES:
            raise ValueError(f"{milestone['id']}: invalid runtime acceptance state")
        if not all(nonempty_text(milestone[key]) for key in ("goal", "evidence", "remaining")):
            raise ValueError(f"{milestone['id']}: incomplete runtime acceptance record")
        sources = milestone["sources"]
        if not isinstance(sources, list) or not sources or not all(nonempty_text(url) for url in sources):
            raise ValueError(f"{milestone['id']}: expected a list of evidence sources")
        if milestone["status"] == "VERIFIED":
            reviews = milestone.get("independent_reviews")
            if not isinstance(reviews, list) or not all(
                isinstance(review, dict) and all(nonempty_text(review.get(key)) for key in ("reviewer", "source"))
                for review in reviews
            ):
                raise ValueError(f"{milestone['id']}: independent review records required")
            reviewers = {review["reviewer"].strip().casefold() for review in reviews}
            if len(reviewers) < 2:
                raise ValueError(f"{milestone['id']}: two distinct reviewers required")


def api_objects(endpoint: str, jq: str) -> dict[int, dict]:
    command = ["gh", "api", "--paginate", endpoint, "--jq", jq]
    try:
        output = subprocess.check_output(command, cwd=ROOT, text=True)
    except FileNotFoundError as error:
        raise SystemExit("gh is required for --sync") from error
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"gh api failed for {endpoint}: {error}") from error
    result: dict[int, dict] = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        result[int(item["number"])] = item
    return result


def sync(data: dict) -> list[str]:
    pulls = api_objects(
        f"repos/{REPO}/pulls?state=all&per_page=100",
        '.[] | {number, state, merged_at}',
    )
    issues = api_objects(
        f"repos/{REPO}/issues?state=all&per_page=100",
        '.[] | {number, state}',
    )
    changes: list[str] = []
    for package in data["work_packages"]:
        current = package["status"]
        if current == "VERIFIED":
            continue
        pull = pulls.get(package["pr"]) if package["pr"] is not None else None
        issue = issues.get(package["issue"]) if package["issue"] is not None else None
        if pull is not None:
            if pull.get("merged_at"):
                desired = "MERGED"
            elif pull["state"] == "open":
                desired = "PR_OPEN"
            else:
                desired = "SUPERSEDED"
        elif issue is not None:
            if issue["state"] == "closed" and current not in FINISHED_IMPLEMENTATION_STATES:
                desired = "SUPERSEDED"
            elif current in STATES:
                desired = current
            else:
                desired = "UNCLAIMED"
        else:
            desired = current
        if desired != current:
            package["status"] = desired
            changes.append(f"{package['id']}: {current} -> {desired}")
    if changes:
        data["updated_at"] = datetime.now(timezone.utc).date().isoformat()
        save(data)
    return changes


def dashboard(data: dict) -> None:
    packages = data["work_packages"]
    print(f"work packages: {len(packages)}")
    for state in sorted(STATES):
        count = sum(package["status"] == state for package in packages)
        if count:
            print(f"  {state}: {count}")
    for side in ("personal", "external"):
        group = [package for package in packages if package["assignment_side"] == side]
        completed = sum(package["status"] in COMPLETED_STATES for package in group)
        remaining = sum(
            package["counts_toward_personal_workload"]
            and package["status"] not in FINISHED_IMPLEMENTATION_STATES
            for package in group
        )
        print(f"{side} assignments: total={len(group)} completed={completed} remaining_implementation={remaining}")
    for ownership in sorted(OWNERSHIP_STATES):
        count = sum(package["ownership_state"] == ownership for package in packages)
        if count:
            print(f"  ownership {ownership}: {count}")
    for subsystem in sorted({package["subsystem"] for package in packages}):
        count = sum(package["subsystem"] == subsystem for package in packages)
        print(f"  subsystem {subsystem}: {count}")
    print("runtime acceptance:")
    for milestone in data["runtime_acceptance"]:
        print(f"  {milestone['id']} {milestone['status']} {milestone['goal']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate the tracker only")
    parser.add_argument("--sync", action="store_true", help="reconcile states with upstream via gh")
    parser.add_argument("--dashboard", action="store_true", help="print status counts")
    parser.add_argument("--runtime-evidence", action="store_true", help="print service evidence as JSON")
    args = parser.parse_args()
    if args.runtime_evidence and (args.check or args.sync or args.dashboard):
        parser.error("--runtime-evidence must run on its own")
    data = load()
    validate(data)
    evidence = runtime_evidence(data)
    if args.runtime_evidence:
        print(json.dumps(evidence, indent=2, ensure_ascii=False))
        return 0
    if args.sync:
        changes = sync(data)
        for change in changes:
            print(change)
        validate(data)
    if args.check or not (args.sync or args.dashboard):
        print(f"tracker valid: {TRACKER.relative_to(ROOT)}")
    if args.dashboard or not (args.sync or args.check):
        dashboard(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
