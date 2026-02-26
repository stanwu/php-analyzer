from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

ROOT_VENDOR_DIRS = {
    "google_config",
    "vendor",
    "fb_config",
    "mailer/vendor",
    "test/PHPExcel",
    "classes/mailer",
}


def _vendor_prefixes() -> list[tuple[str, ...]]:
    prefixes: list[tuple[str, ...]] = []
    for raw in ROOT_VENDOR_DIRS:
        parts = tuple(p for p in Path(raw).as_posix().split("/") if p)
        if parts:
            prefixes.append(parts)
    prefixes.sort(key=len, reverse=True)
    return prefixes


_VENDOR_PREFIXES = _vendor_prefixes()


def _rel_parts(path: Path, root: Path) -> tuple[str, ...]:
    try:
        rel = path.resolve().relative_to(root.resolve())
    except Exception:
        rel = path
    rel_posix = rel.as_posix().lstrip("./")
    if not rel_posix:
        return tuple()
    return tuple(p for p in rel_posix.split("/") if p)


def is_custom_file(path: Path, root: Path) -> bool:
    """Return True only if the file is NOT inside a vendor directory."""
    parts = _rel_parts(path, root)
    for prefix in _VENDOR_PREFIXES:
        if len(parts) >= len(prefix) and parts[: len(prefix)] == prefix:
            return False
    return True


def iter_custom_php(root: Path) -> Iterator[Path]:
    """Yield all custom PHP file Paths under root."""
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        base = Path(dirpath)

        # Prune vendor dirs early.
        kept: list[str] = []
        for d in dirnames:
            candidate = base / d
            parts = _rel_parts(candidate, root)
            if any(len(parts) >= len(p) and parts[: len(p)] == p for p in _VENDOR_PREFIXES):
                continue
            kept.append(d)
        dirnames[:] = kept

        for name in filenames:
            if not name.lower().endswith(".php"):
                continue
            file_path = base / name
            if is_custom_file(file_path, root):
                yield file_path


def iter_non_vendor_files(root: Path) -> Iterator[Path]:
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        base = Path(dirpath)

        kept: list[str] = []
        for d in dirnames:
            candidate = base / d
            parts = _rel_parts(candidate, root)
            if any(len(parts) >= len(p) and parts[: len(p)] == p for p in _VENDOR_PREFIXES):
                continue
            kept.append(d)
        dirnames[:] = kept

        for name in filenames:
            yield base / name


def count_php_files(root: Path) -> tuple[int, int]:
    """Return (custom_php_count, vendor_php_count). Walks the whole tree."""
    root = root.resolve()
    custom = 0
    vendor = 0
    for dirpath, _, filenames in os.walk(root):
        base = Path(dirpath)
        for name in filenames:
            if not name.lower().endswith(".php"):
                continue
            p = base / name
            if is_custom_file(p, root):
                custom += 1
            else:
                vendor += 1
    return custom, vendor


def relpath(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return path.as_posix()
