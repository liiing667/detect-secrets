import os
from typing import Optional


def get_relative_path(root: str, path: str) -> Optional[str]:
    """Returns the path relative to ``root`` after resolving symlinks.

    Both ``root`` and ``path`` are canonicalized (symlinks resolved, ``..``
    collapsed) before computing the relative path, so the same on-disk file
    always maps to the same identity regardless of how it was referenced.

    Returns ``None`` when ``path`` cannot be shown to live inside ``root``
    (e.g. a symlink pointing outside the workspace), rather than producing a
    path that escapes the scan boundary.
    """
    canonical_root = os.path.realpath(root)
    canonical_path = os.path.realpath(path)
    if not _is_path_within(canonical_root, canonical_path):
        return None

    return os.path.relpath(canonical_path, canonical_root)


def get_relative_path_if_in_cwd(path: str) -> Optional[str]:
    """Returns the path of ``path`` relative to the current working directory.

    Returns ``None`` when ``path`` does not resolve to a file inside the
    current working directory.
    """
    relative_path = get_relative_path(os.getcwd(), path)
    if relative_path is None or not os.path.isfile(path):
        return None

    return relative_path


def _is_path_within(root: str, path: str) -> bool:
    """Whether canonical ``path`` is identical to, or nested under, canonical ``root``."""
    if path == root:
        return True

    try:
        return os.path.commonpath((root, path)) == root
    except ValueError:
        # e.g. different drives on Windows
        return False


def convert_local_os_path(path: str) -> str:
    # Linux filesystem, replace \\ with /
    if os.sep == '/':
        path = path.replace('\\', '/')
        return path
    else:
        path = path.replace('/', '\\')
        return path
