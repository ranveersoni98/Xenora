# SPDX-License-Identifier: GPL-3.0-or-later
"""Application bundle structure and codesign diagnostic helpers."""
from __future__ import annotations

import plistlib
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from xml.parsers.expat import ExpatError


APP_EXECUTABLE = "Xenora"
BUNDLE_HELPERS = ("xenora-cli", "xenora-pe-session")
BUNDLE_EXECUTABLES = (APP_EXECUTABLE, *BUNDLE_HELPERS)


@dataclass(frozen=True)
class BundleCheck:
    root: str
    ok: bool
    problems: tuple[str, ...]
    present: tuple[str, ...]


@dataclass(frozen=True)
class CodesignDiagnosis:
    path: str
    ok: bool
    problems: tuple[str, ...]
    notes: tuple[str, ...]


def _entry_mode(root: Path, relative: str, present: list[str], problems: list[str]) -> int | None:
    try:
        mode = (root / relative).lstat().st_mode
    except FileNotFoundError:
        problems.append(f"missing {relative}")
        return None
    except OSError as error:
        problems.append(f"cannot inspect {relative}: {error.strerror}")
        return None
    present.append(relative)
    return mode


def _check_info_plist(path: Path, problems: list[str]) -> None:
    try:
        with path.open("rb") as source:
            info = plistlib.load(source)
    except (OSError, ValueError, ExpatError, AttributeError, TypeError, OverflowError):
        problems.append("Contents/Info.plist is not a readable property list")
        return
    if not isinstance(info, dict):
        problems.append("Contents/Info.plist must contain a dictionary")
        return
    if info.get("CFBundleExecutable") != APP_EXECUTABLE:
        problems.append(f"Contents/Info.plist CFBundleExecutable must be {APP_EXECUTABLE}")
    if info.get("CFBundlePackageType") != "APPL":
        problems.append("Contents/Info.plist CFBundlePackageType must be APPL")


def _check_default_layout(root: Path, present: list[str], problems: list[str]) -> None:
    contents = _entry_mode(root, "Contents", present, problems)
    if contents is None:
        return
    if not stat.S_ISDIR(contents):
        problems.append("Contents must be a directory")
        return

    info = "Contents/Info.plist"
    info_mode = _entry_mode(root, info, present, problems)
    if info_mode is not None:
        if stat.S_ISREG(info_mode):
            _check_info_plist(root / info, problems)
        else:
            problems.append(f"{info} must be a regular file")

    macos = "Contents/MacOS"
    macos_mode = _entry_mode(root, macos, present, problems)
    if macos_mode is None:
        return
    if not stat.S_ISDIR(macos_mode):
        problems.append(f"{macos} must be a directory")
        return

    for name in BUNDLE_EXECUTABLES:
        relative = f"{macos}/{name}"
        mode = _entry_mode(root, relative, present, problems)
        if mode is None:
            continue
        if not stat.S_ISREG(mode):
            problems.append(f"{relative} must be a regular file")
        elif not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            problems.append(f"{relative} is not executable")


def check_app_bundle(root: Path, entries: Iterable[str] | None = None) -> BundleCheck:
    """Check the Xenora layout, or check existence only for explicit entries."""
    present: list[str] = []
    problems: list[str] = []
    if not root.exists():
        return BundleCheck(root=str(root), ok=False, problems=(f"missing bundle root: {root}",), present=())
    if not root.is_dir():
        return BundleCheck(root=str(root), ok=False, problems=(f"bundle root is not a directory: {root}",), present=())
    if entries is None:
        _check_default_layout(root, present, problems)
    else:
        for rel in entries:
            if (root / rel).exists():
                present.append(rel)
            else:
                problems.append(f"missing {rel}")
    return BundleCheck(root=str(root), ok=not problems, problems=tuple(problems), present=tuple(present))


def diagnose_codesign_output(path: str, codesign_stderr_or_stdout: str) -> CodesignDiagnosis:
    text = codesign_stderr_or_stdout.strip()
    notes = tuple(line.strip() for line in text.splitlines() if line.strip())
    problems: list[str] = []
    lower = text.casefold()
    if "code object is not signed at all" in lower:
        problems.append("unsigned")
    if "cssmerr_tp_cert_expired" in lower or "expired" in lower:
        problems.append("certificate expired or reported expired")
    if "errsec" in lower or "failed" in lower:
        if not problems:
            problems.append("codesign reported failure")
    ok = not problems
    if not text:
        problems.append("empty codesign output")
        ok = False
    return CodesignDiagnosis(path=path, ok=ok, problems=tuple(problems), notes=notes)
