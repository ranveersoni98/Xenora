#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

import importlib.util
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("campaign_tracker", ROOT / "scripts/audit/campaign_tracker.py")
tracker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tracker)


class WorkPackageTests(unittest.TestCase):
    def test_sync_leaves_verified_packages_and_timestamp_unchanged(self):
        pulls = {
            1: {"state": "closed", "merged_at": "2026-11-28T00:00:00Z"},
            2: {"state": "open", "merged_at": None},
            3: {"state": "closed", "merged_at": None},
        }
        issues = {4: {"state": "closed"}, 5: {"state": "open"}}
        data = {
            "updated_at": "2026-11-27",
            "work_packages": [
                {"id": f"pr-{number}", "status": "VERIFIED", "pr": number, "issue": None}
                for number in pulls
            ] + [
                {"id": f"issue-{number}", "status": "VERIFIED", "pr": None, "issue": number}
                for number in issues
            ],
        }
        with (
            patch.object(tracker, "api_objects", side_effect=[pulls, issues]),
            patch.object(tracker, "save") as save,
        ):
            self.assertEqual(tracker.sync(data), [])
        save.assert_not_called()
        self.assertEqual(data["updated_at"], "2026-11-27")
        self.assertTrue(all(row["status"] == "VERIFIED" for row in data["work_packages"]))

    def test_sync_still_updates_active_packages_from_pull_and_issue_state(self):
        data = {"work_packages": [
            {"id": "merged-pull", "status": "PR_OPEN", "pr": 1, "issue": None},
            {"id": "open-pull", "status": "TESTING", "pr": 2, "issue": None},
            {"id": "closed-issue", "status": "CLAIMED", "pr": None, "issue": 3},
        ]}
        pulls = {
            1: {"state": "closed", "merged_at": "2026-11-28T00:00:00Z"},
            2: {"state": "open", "merged_at": None},
        }
        issues = {3: {"state": "closed"}}
        with (
            patch.object(tracker, "api_objects", side_effect=[pulls, issues]),
            patch.object(tracker, "save") as save,
        ):
            changes = tracker.sync(data)
        self.assertEqual(changes, [
            "merged-pull: PR_OPEN -> MERGED",
            "open-pull: TESTING -> PR_OPEN",
            "closed-issue: CLAIMED -> SUPERSEDED",
        ])
        self.assertEqual(
            [row["status"] for row in data["work_packages"]],
            ["MERGED", "PR_OPEN", "SUPERSEDED"],
        )
        save.assert_called_once_with(data)

    def test_dashboard_counts_only_enabled_unfinished_assignments(self):
        statuses = [
            ("MERGED", True), ("VERIFIED", True), ("SUPERSEDED", True),
            ("IMPLEMENTING", True), ("TESTING", False),
        ]
        data = {"work_packages": [
            {
                "status": status,
                "counts_toward_personal_workload": enabled,
                "assignment_side": "personal",
                "ownership_state": "Catminou-owned",
                "subsystem": "runtime",
            }
            for status, enabled in statuses
        ], "runtime_acceptance": []}
        output = StringIO()
        with redirect_stdout(output):
            tracker.dashboard(data)
        self.assertIn(
            "personal assignments: total=5 completed=2 remaining_implementation=1",
            output.getvalue().splitlines(),
        )


class RuntimeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.data = tracker.load()

    def test_evidence_preserves_all_inventory_binding_fields(self):
        self.data["runtime_service_evidence"][0]["status"] = "stub"
        projection = tracker.runtime_evidence(self.data)
        inventory = json.loads(tracker.RUNTIME_INVENTORY.read_text(encoding="utf-8"))
        self.assertEqual(len(projection["services"]), len(inventory["services"]))
        self.assertEqual(projection["aliases"], inventory["aliases"])
        for binding, projected in zip(inventory["services"], projection["services"]):
            self.assertEqual(binding, {key: projected[key] for key in binding})
            self.assertIn(projected["evidence_class"], tracker.EVIDENCE)

    def test_duplicate_inventory_summary_keys_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key 'canonical_services'"):
            json.loads('{"summary":{"canonical_services":3,"canonical_services":2}}',
                       object_pairs_hook=tracker.unique_object)

    def test_stale_inventory_summary_is_reported_without_losing_rows(self):
        inventory = json.loads(tracker.RUNTIME_INVENTORY.read_text(encoding="utf-8"))
        count = len(inventory["services"])
        inventory["summary"]["canonical_services"] = count - 1
        with patch.object(Path, "read_text", return_value=json.dumps(inventory)):
            projection = tracker.runtime_evidence(self.data)
        self.assertEqual(len(projection["services"]), count)
        self.assertEqual(projection["inventory_summary_mismatches"]["canonical_services"],
                         {"declared": count - 1, "rows": count})

    def test_verified_milestone_requires_two_distinct_reviewers(self):
        milestone = self.data["runtime_acceptance"][0]
        milestone["status"] = "VERIFIED"
        milestone["independent_reviews"] = True
        with self.assertRaisesRegex(ValueError, "independent review records required"):
            tracker.validate(self.data)
        milestone["independent_reviews"] = [
            {"reviewer": "account", "source": "https://example.com/1"},
            {"reviewer": "Account", "source": "https://example.com/2"},
        ]
        with self.assertRaisesRegex(ValueError, "two distinct reviewers required"):
            tracker.validate(self.data)
        milestone["independent_reviews"][1]["reviewer"] = "other-account"
        tracker.validate(self.data)
