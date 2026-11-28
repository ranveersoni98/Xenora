# SPDX-License-Identifier: GPL-3.0-or-later
"""Create, unpack and inspect the native contributor preview bundle."""
from __future__ import annotations

import plistlib
import re
import stat
import unicodedata
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from release.bundle import APP_EXECUTABLE
from release.bundle import BUNDLE_EXECUTABLES as EXECUTABLES
from release.bundle import BUNDLE_HELPERS as HELPERS
from release.macho import check_archs, check_otool_linkage

APP_NAME = f"{APP_EXECUTABLE}.app"
CONTENTS = f"{APP_NAME}/Contents"
DIRECTORIES = {
    APP_NAME,
    CONTENTS,
    f"{CONTENTS}/MacOS",
    f"{CONTENTS}/_CodeSignature",
}
REQUIRED_FILES = {
    f"{CONTENTS}/Info.plist",
    *(f"{CONTENTS}/MacOS/{name}" for name in EXECUTABLES),
}
FILES = REQUIRED_FILES | {
    f"{CONTENTS}/_CodeSignature/CodeResources",
    # stapler may add a ticket at this path.
    f"{CONTENTS}/CodeResources",
}
PLIST_KEYS = (
    "CFBundleIdentifier",
    "CFBundleExecutable",
    "CFBundlePackageType",
    "CFBundleShortVersionString",
    "CFBundleVersion",
    "LSMinimumSystemVersion",
    "XenoraSourceRevision",
)
MAX_MEMBER_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
APPLEDOUBLE_MAGIC = bytes.fromhex("00051607")
DEPENDENCY = re.compile(r"\s*(.+) \(compatibility version [^\r\n]+\)\s*")


def _check_bundle_tree(app: Path) -> None:
    if app.name != APP_NAME or app.is_symlink() or not app.is_dir():
        raise ValueError(f"expected a regular {APP_NAME} bundle")
    found = set()
    for path in app.rglob("*"):
        member = f"{APP_NAME}/{path.relative_to(app).as_posix()}"
        kind = stat.S_IFMT(path.lstat().st_mode)
        if member in FILES and kind == stat.S_IFREG:
            found.add(member)
        elif member not in DIRECTORIES or kind != stat.S_IFDIR:
            raise ValueError(f"unexpected bundle member {member!r}")
    if missing := REQUIRED_FILES - found:
        raise ValueError(f"missing bundle members: {', '.join(sorted(missing))}")


def archive_app(app: Path, archive: Path, *, run) -> None:
    """Archive the bundle with Apple metadata needed by signed previews."""
    _check_bundle_tree(app)
    if archive.exists() or archive.is_symlink():
        raise ValueError("preview archive destination already exists")
    run(["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", app, archive])


def _appledouble_target(parts: list[str], is_dir: bool) -> str | None:
    if is_dir:
        # The metadata directory hierarchy mirrors the app hierarchy.
        if len(parts) == 1 or "/".join(parts[1:]) in DIRECTORIES:
            return None
    elif len(parts) >= 2 and parts[-1].startswith("._"):
        target = "/".join([*parts[1:-1], parts[-1][2:]])
        if target in FILES or target in DIRECTORIES:
            return target
    raise ValueError("unexpected AppleDouble member")


def _validate_archive(archive: Path) -> None:
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("preview ZIP exceeds its on-disk size limit")
    with ZipFile(archive) as source:
        seen = set()
        app_members = set()
        metadata_targets = set()
        total_bytes = 0
        for entry in source.infolist():
            original = entry.orig_filename
            is_dir = entry.is_dir()
            name = original.removesuffix("/") if is_dir else original
            parts = name.split("/")
            if original != entry.filename or any(part in ("", ".", "..") for part in parts):
                raise ValueError(f"invalid archive member {original!r}")
            key = unicodedata.normalize("NFC", name).casefold()
            if key in seen:
                raise ValueError(f"duplicate archive member {original!r}")
            seen.add(key)

            kind = stat.S_IFMT(entry.external_attr >> 16)
            expected_kind = stat.S_IFDIR if is_dir else stat.S_IFREG
            if kind not in (0, expected_kind) or (is_dir and entry.file_size):
                raise ValueError(f"invalid archive member type for {original!r}")
            total_bytes += entry.file_size
            if entry.file_size > MAX_MEMBER_BYTES or total_bytes > MAX_ARCHIVE_BYTES:
                raise ValueError("preview archive exceeds its uncompressed size limit")

            if parts[0] == "__MACOSX":
                target = _appledouble_target(parts, is_dir)
            else:
                allowed = DIRECTORIES if is_dir else FILES
                if name not in allowed:
                    raise ValueError(f"unexpected archive member {original!r}")
                app_members.add(name)
                target = None

            # Opening also validates the local header against the central listing.
            with source.open(entry) as member:
                if target is not None:
                    if member.read(len(APPLEDOUBLE_MAGIC)) != APPLEDOUBLE_MAGIC:
                        raise ValueError(f"invalid AppleDouble member {original!r}")
                    metadata_targets.add(target)

        if missing := REQUIRED_FILES - app_members:
            raise ValueError(f"missing archive members: {', '.join(sorted(missing))}")
        implicit_directories = {
            directory for directory in DIRECTORIES
            if any(name.startswith(f"{directory}/") for name in app_members)
        }
        if not metadata_targets <= (app_members | implicit_directories):
            raise ValueError("AppleDouble metadata has no matching app member")


def extract_app(archive: Path, destination: Path, *, run) -> Path:
    """Validate the preview archive before invoking ditto in an empty directory."""
    if destination.is_symlink() or not destination.is_dir() or any(destination.iterdir()):
        raise ValueError("preview extraction destination must be an empty directory")
    try:
        _validate_archive(archive)
    except (BadZipFile, NotImplementedError, RuntimeError) as error:
        raise ValueError("invalid preview ZIP") from error
    run(["ditto", "-x", "-k", archive, destination])
    app = destination / APP_NAME
    if set(destination.iterdir()) != {app}:
        raise ValueError("preview archive did not extract exactly one app")
    _check_bundle_tree(app)
    return app


def _dependencies(description: str, name: str) -> list[str]:
    lines = description.strip().splitlines()
    if not lines or not lines[0].endswith(":"):
        raise ValueError(f"missing otool header for {name}")
    dependencies = []
    for line in lines[1:]:
        row = DEPENDENCY.fullmatch(line)
        if row is None:
            raise ValueError(f"unrecognized dependency row for {name}")
        path = row.group(1)
        if (
            not path.startswith(("/System/Library/", "/usr/lib/"))
            or any(part in ("", ".", "..") for part in path[1:].split("/"))
        ):
            raise ValueError(f"{name} links a non-system library: {path}")
        dependencies.append(path)
    check = check_otool_linkage(name, "\n".join(dependencies))
    if not check.ok:
        raise ValueError(f"{name}: {'; '.join(check.problems)}")
    return dependencies


def inspect_app(app: Path, *, run) -> dict:
    """Inspect the app and its helpers without launching them."""
    _check_bundle_tree(app)
    with (app / "Contents/Info.plist").open("rb") as source:
        plist = plistlib.load(source)
    if (
        not isinstance(plist, dict)
        or plist.get("CFBundleExecutable") != APP_EXECUTABLE
        or plist.get("CFBundlePackageType") != "APPL"
    ):
        raise ValueError("expected Xenora executable and APPL package type in Info.plist")
    info = {key: plist[key] for key in PLIST_KEYS if key in plist}
    if any(not isinstance(value, str) for value in info.values()):
        raise ValueError("preview Info.plist metadata must be strings")

    executables = {}
    for name in EXECUTABLES:
        binary = app / "Contents/MacOS" / name
        file_type = run(["file", "-b", binary], capture=True).strip()
        if not file_type.startswith("Mach-O") or "executable" not in file_type:
            raise ValueError(f"{name} is not a Mach-O executable")
        arch = check_archs(name, run(["lipo", "-archs", binary], capture=True))
        if not arch.ok:
            raise ValueError(f"{name}: {'; '.join(arch.problems)}")
        dependencies = _dependencies(run(["otool", "-L", binary], capture=True), name)
        run(["codesign", "--verify", "--strict", binary], capture=True)
        executables[name] = {
            "file": file_type,
            "architectures": list(arch.archs),
            "dependencies": dependencies,
            "signature_verified": True,
        }

    run(["codesign", "--verify", "--strict", app], capture=True)
    return {
        "info_plist": info,
        "executables": executables,
        "signature_verified": True,
    }
