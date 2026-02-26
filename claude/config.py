from pathlib import Path

ROOT_VENDOR_DIRS: set[str] = {
    "google_config",
    "vendor",
    "fb_config",
    "mailer/vendor",
    "test/PHPExcel",
    "classes/mailer",
}


def is_custom_file(path: Path, root: Path) -> bool:
    """Return True only if the file is NOT inside a vendor directory."""
    try:
        rel = path.relative_to(root)
    except ValueError:
        return False

    parts = rel.parts
    rel_str = str(rel)

    for vendor in ROOT_VENDOR_DIRS:
        vendor_parts = Path(vendor).parts
        # Check if the file path starts with vendor dir parts
        if len(parts) >= len(vendor_parts) and parts[: len(vendor_parts)] == vendor_parts:
            return False
        # Also check forward-slash joined string prefix for multi-part vendors
        if rel_str == vendor or rel_str.startswith(vendor + "/"):
            return False

    return True


def iter_custom_php(root: Path):
    """Yield all custom PHP file Paths under root, skipping vendor directories."""
    root = root.resolve()

    # Compute absolute paths of vendor dirs to skip
    skip_dirs: set[Path] = set()
    for vendor in ROOT_VENDOR_DIRS:
        skip_dirs.add((root / vendor).resolve())

    def _walk(directory: Path):
        try:
            entries = list(directory.iterdir())
        except PermissionError:
            return

        for entry in entries:
            resolved = entry.resolve()
            if entry.is_dir():
                if resolved in skip_dirs:
                    continue
                yield from _walk(entry)
            elif entry.is_file() and entry.suffix.lower() == ".php":
                yield entry

    yield from _walk(root)
