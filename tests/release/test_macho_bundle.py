# SPDX-License-Identifier: GPL-3.0-or-later
import plistlib
import tempfile
import unittest
from pathlib import Path

from release.bundle import check_app_bundle, diagnose_codesign_output
from release.macho import check_archs, check_otool_linkage, consistent_deployment_targets


class MachOBundle(unittest.TestCase):
    def test_arch_and_linkage(self):
        ok = check_archs("/tmp/x", "arm64")
        self.assertTrue(ok.ok)
        bad = check_archs("/tmp/x", "x86_64 arm64")
        self.assertFalse(bad.ok)
        link = check_otool_linkage("/tmp/x", "/tmp/x:\n\t/usr/lib/libSystem.B.dylib")
        self.assertTrue(link.ok)
        vuln = check_otool_linkage("/tmp/x", "/tmp/x:\n\t@rpath/libvulkan.dylib")
        self.assertFalse(vuln.ok)

    def test_deployment_targets(self):
        a = "version.min osx,10.15\n"
        b = "version.min osx,10.15\n"
        c = "version.min osx,11.0\n"
        self.assertTrue(consistent_deployment_targets([a, b])[0])
        self.assertFalse(consistent_deployment_targets([a, c])[0])

    def make_bundle(self, directory):
        root = Path(directory) / "Xenora.app"
        executable_directory = root / "Contents/MacOS"
        executable_directory.mkdir(parents=True)
        (root / "Contents/Info.plist").write_bytes(plistlib.dumps({
            "CFBundleExecutable": "Xenora",
            "CFBundlePackageType": "APPL",
        }))
        for name in ("Xenora", "xenora-cli", "xenora-pe-session"):
            binary = executable_directory / name
            binary.write_bytes(b"fixture")
            binary.chmod(0o755)
        return root

    def assert_bundle_refused(self, root, diagnostic):
        check = check_app_bundle(root)
        self.assertFalse(check.ok, check)
        self.assertIn(diagnostic, " ".join(check.problems))

    def test_bundle_and_codesign(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.make_bundle(tmp)
            self.assertTrue(check_app_bundle(root).ok)
            missing = check_app_bundle(Path(tmp) / "Missing.app")
            self.assertFalse(missing.ok)
        unsigned = diagnose_codesign_output("/tmp/x", "code object is not signed at all")
        self.assertFalse(unsigned.ok)
        self.assertIn("unsigned", unsigned.problems)

    def test_bundle_refuses_invalid_metadata(self):
        for overrides, diagnostic in [
            (None, "Contents/Info.plist"),
            ({"CFBundleExecutable": "xenora-cli"}, "CFBundleExecutable"),
            ({"CFBundlePackageType": "BNDL"}, "CFBundlePackageType"),
        ]:
            with self.subTest(diagnostic=diagnostic), tempfile.TemporaryDirectory() as tmp:
                root = self.make_bundle(tmp)
                plist = root / "Contents/Info.plist"
                if overrides is None:
                    plist.write_bytes(b"not a plist")
                else:
                    settings = plistlib.loads(plist.read_bytes())
                    settings.update(overrides)
                    plist.write_bytes(plistlib.dumps(settings))
                self.assert_bundle_refused(root, diagnostic)

    def test_bundle_requires_all_three_binaries(self):
        for name in ("Xenora", "xenora-cli", "xenora-pe-session"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = self.make_bundle(tmp)
                relative = f"Contents/MacOS/{name}"
                (root / relative).unlink()
                self.assert_bundle_refused(root, relative)

    def test_bundle_refuses_nonexecutable_helper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.make_bundle(tmp)
            relative = "Contents/MacOS/xenora-pe-session"
            helper = root / relative
            helper.chmod(0o644)
            self.assert_bundle_refused(root, relative)

    def test_bundle_refuses_symlink_helper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.make_bundle(tmp)
            relative = "Contents/MacOS/xenora-pe-session"
            helper = root / relative
            real_helper = Path(tmp) / "actual-helper"
            helper.rename(real_helper)
            helper.symlink_to(real_helper)
            self.assert_bundle_refused(root, relative)

    def test_bundle_refuses_wrong_directory_and_plist_kinds(self):
        for relative in ("Contents/Info.plist", "Contents/MacOS"):
            with self.subTest(entry=relative), tempfile.TemporaryDirectory() as tmp:
                root = self.make_bundle(tmp)
                entry = root / relative
                original = Path(tmp) / "original-entry"
                entry.rename(original)
                if original.is_dir():
                    entry.symlink_to(original, target_is_directory=True)
                else:
                    entry.mkdir()
                self.assert_bundle_refused(root, relative)

    def test_custom_entries_keep_the_explicit_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Custom.app"
            root.mkdir()
            (root / "marker").touch()
            check = check_app_bundle(root, entries=["marker"])
            self.assertTrue(check.ok, check)
            self.assertEqual(check.present, ("marker",))
            self.assertFalse(check_app_bundle(root, entries=["missing"]).ok)
            self.assertTrue(check_app_bundle(root, entries=[]).ok)


if __name__ == "__main__":
    unittest.main()
