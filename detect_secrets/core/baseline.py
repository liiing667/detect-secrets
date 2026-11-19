import json
import os
import re
import time
from collections import OrderedDict
from copy import deepcopy
from pathlib import Path
from typing import Any
from typing import Callable
from typing import cast
from typing import Dict
from typing import List
from typing import Optional
from typing import Union

from . import upgrades
from ..__version__ import VERSION
from ..exceptions import BaselineSizeExceededError
from ..exceptions import DuplicateKeyError
from ..exceptions import InvalidBaselineError
from ..exceptions import PathTraversalError
from ..exceptions import UnableToReadBaselineError
from ..settings import configure_settings_from_baseline
from ..settings import get_settings
from ..util.importlib import import_modules_from_package
from ..util.semver import Version
from .scan import get_files_to_scan
from .secrets_collection import SecretsCollection

# A baseline is a configuration file, not a data dump. Cap how much we are willing
# to read into memory so that a maliciously large baseline cannot exhaust resources
# before scanning even starts.
MAX_BASELINE_FILE_SIZE = 10 * 1024 * 1024

# Cache of validated baseline documents, keyed by the resolved path of the file they
# were loaded from. Entries are only ever populated *after* every boundary check has
# passed, so a failed import leaves any previously cached entry untouched.
# Each entry also stores the file's size and modification time at load time, so a
# baseline rewritten in place (e.g. by an audit session saving progress) is re-read
# rather than served stale.
_baseline_cache: Dict[str, Dict[str, Any]] = {}

# The structural fields every baseline document must carry.
_REQUIRED_FIELDS = ('version', 'results')

# Matches Windows-style absolute paths (e.g. ``C:\Users\...`` or ``\\host\share``),
# which ``pathlib`` on POSIX systems would otherwise treat as ordinary relative names.
_WINDOWS_ABSOLUTE_PATH = re.compile(r'^(?:[a-zA-Z]:[\\/]|\\\\)')


class _DuplicateKeyDetector(OrderedDict):
    """``object_pairs_hook`` that rejects JSON objects containing duplicate keys."""

    def __init__(self, pairs: Optional[List[Any]] = None) -> None:
        seen: Dict[str, None] = {}
        for key, value in pairs or []:
            if key in seen:
                raise DuplicateKeyError(
                    f'Duplicate key found in baseline: {key!r}.',
                )
            seen[key] = None
        super().__init__(pairs or [])


def clear_baseline_cache() -> None:
    _baseline_cache.clear()


def create(
    *paths: str,
    should_scan_all_files: bool = False,
    root: str = '',
    num_processors: Optional[int] = None,
) -> SecretsCollection:
    """Scans all the files recursively in path to initialize a baseline."""
    kwargs = {}
    if num_processors:
        kwargs['num_processors'] = num_processors

    secrets = SecretsCollection(root=root)
    secrets.scan_files(
        *get_files_to_scan(*paths, should_scan_all_files=should_scan_all_files, root=root),
        **kwargs,
    )

    return secrets


def load(baseline: Dict[str, Any], filename: str = '') -> SecretsCollection:
    """
    With a given baseline file, load all settings and discovered secrets from it.

    :raises: InvalidBaselineError
    """
    # Reject malformed documents before any global state is touched, so that a failed
    # import leaves previously loaded baselines (and their cached results) intact.
    validate_baseline_structure(baseline)
    _validate_result_paths(baseline['results'])

    # This is required for backwards compatibility, and supporting upgrades from older versions.
    baseline = upgrade(baseline)
    configure_settings_from_baseline(baseline, filename=filename)
    return SecretsCollection.load_from_baseline(baseline)


def load_from_file(filename: str) -> Dict[str, Any]:
    """
    Loads a baseline from disk, enforcing size, structural and path boundaries.

    Successfully validated baselines are cached by their resolved path; subsequent
    calls return a copy of the cached document as long as the underlying file has not
    changed. If any boundary check fails, the cache (and therefore the previously
    imported results) is left untouched.

    :raises: UnableToReadBaselineError
    :raises: InvalidBaselineError
    """
    cache_key = os.path.realpath(filename)

    try:
        stat_result = os.stat(filename)
        file_size = stat_result.st_size
    except (FileNotFoundError, IOError, OSError) as e:
        raise UnableToReadBaselineError from e

    cached = _baseline_cache.get(cache_key)
    if (
        cached is not None
        and cached['file_size'] == file_size
        and cached['mtime'] == stat_result.st_mtime
    ):
        return deepcopy(cached['data'])

    try:
        if file_size > MAX_BASELINE_FILE_SIZE:
            raise BaselineSizeExceededError(
                f'Baseline file {filename!r} is {file_size} bytes, which exceeds the '
                f'maximum allowed size of {MAX_BASELINE_FILE_SIZE} bytes.',
            )

        with open(filename) as f:
            contents = f.read()
    except BaselineSizeExceededError:
        raise
    except IOError as e:
        raise UnableToReadBaselineError from e

    # Re-check after reading: a file may have grown between the stat and the read.
    if len(contents.encode('utf-8', errors='ignore')) > MAX_BASELINE_FILE_SIZE:
        raise BaselineSizeExceededError(
            f'Baseline file {filename!r} exceeds the maximum allowed size of '
            f'{MAX_BASELINE_FILE_SIZE} bytes.',
        )

    try:
        data = json.loads(contents, object_pairs_hook=_DuplicateKeyDetector)
    except json.decoder.JSONDecodeError as e:
        raise UnableToReadBaselineError from e

    # The structure and path checks are shared with ``load`` so that both entry points
    # enforce the same boundary, regardless of how the document was obtained.
    validate_baseline_structure(cast(Dict[str, Any], data))
    _validate_result_paths(cast(Dict[str, Any], data)['results'])

    # Only cache once every check has passed.
    validated_data = cast(Dict[str, Any], data)
    _baseline_cache[cache_key] = {
        'data': validated_data,
        'file_size': file_size,
        'mtime': stat_result.st_mtime,
    }
    return deepcopy(validated_data)


def validate_baseline_structure(baseline: Any) -> None:
    """
    Verifies that a parsed baseline has the expected structure and a parseable,
    supported ``version`` field.

    Older baselines are accepted as long as their version can be parsed: the upgrade
    machinery is responsible for migrating them. An empty ``results`` mapping is also
    valid, since a clean scan legitimately produces no secrets.

    :raises: InvalidBaselineError
    """
    if not isinstance(baseline, dict):
        raise InvalidBaselineError(
            f'Baseline must be a JSON object, got {type(baseline).__name__}.',
        )

    missing = [field for field in _REQUIRED_FIELDS if field not in baseline]
    if missing:
        raise InvalidBaselineError(
            f'Baseline is missing required field(s): {", ".join(missing)}.',
        )

    version = baseline['version']
    if not isinstance(version, str):
        raise InvalidBaselineError(
            f'Baseline version must be a string, got {type(version).__name__}.',
        )
    try:
        baseline_version = Version(version)
    except (ValueError, TypeError) as e:
        raise InvalidBaselineError(f'Invalid baseline version: {version!r}.') from e

    results = baseline['results']
    if not isinstance(results, dict):
        raise InvalidBaselineError(
            f'Baseline results must be a JSON object, got {type(results).__name__}.',
        )

    for path, entries in results.items():
        if not isinstance(path, str):
            raise InvalidBaselineError('Baseline result keys must be file path strings.')
        if not isinstance(entries, list):
            raise InvalidBaselineError(
                f'Baseline results for {path!r} must be a list of secrets.',
            )
        for entry in entries:
            if not isinstance(entry, dict):
                raise InvalidBaselineError(
                    f'Baseline results for {path!r} must contain JSON objects.',
                )

    # Baselines produced by a newer release than this one are only loadable if their
    # format is still understood; refuse rather than silently misinterpreting them.
    # Compare components directly, since ``Version`` only implements ``__lt__`` reliably.
    supported_version = Version(VERSION)
    if (
        baseline_version.major,
        baseline_version.minor,
        baseline_version.patch,
    ) > (
        supported_version.major,
        supported_version.minor,
        supported_version.patch,
    ):
        raise InvalidBaselineError(
            f'Baseline version {version} is newer than the supported version {VERSION}.',
        )


def _validate_result_paths(results: Dict[str, Any]) -> None:
    """
    Ensures every path referenced by the baseline stays within the working directory,
    blocking absolute paths and ``..`` traversal that would point outside the scanned
    repository (e.g. ``../../etc/passwd`` or an absolute ``/etc/shadow``).

    :raises: PathTraversalError
    """
    root = Path(os.getcwd()).resolve()
    for path in results:
        if _WINDOWS_ABSOLUTE_PATH.match(path):
            raise PathTraversalError(
                f'Baseline references an absolute path outside the working '
                f'directory: {path!r}.',
            )

        candidate = Path(path)
        if candidate.is_absolute() or candidate.anchor:
            raise PathTraversalError(
                f'Baseline references an absolute path outside the working '
                f'directory: {path!r}.',
            )

        resolved = (root / candidate).resolve()
        if not _is_within(resolved, root):
            raise PathTraversalError(
                f'Baseline references a path outside the working directory: {path!r}.',
            )


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def format_for_output(secrets: SecretsCollection, is_slim_mode: bool = False) -> Dict[str, Any]:
    output = {
        'version': VERSION,

        # This will populate settings of filters and plugins,
        **get_settings().json(),

        'results': secrets.json(),
    }

    if not is_slim_mode:
        output['generated_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    else:
        # NOTE: This has a nice little side effect of keeping it ordered by line number,
        # even though we don't output it.
        for filename, secret_list in cast(
            Dict[str, List[Dict[str, Any]]],
            output['results'],
        ).items():
            for secret_dict in secret_list:
                secret_dict.pop('line_number')

    return output


def save_to_file(
    secrets: Union[SecretsCollection, Dict[str, Any]],
    filename: str,
) -> None:    # pragma: no cover
    """
    :param secrets: if this is a SecretsCollection, it will output the baseline in its latest
        format. Otherwise, you should pass in a dictionary to this function, to manually
        specify the baseline format to save as.

        If you're trying to decide the difference, ask yourself whether there are any changes
        that does not directly impact the results of the scan.
    """
    # TODO: I wonder whether this should add the `detect_secrets.filters.common.is_baseline_file`
    # filter, since we know the filename already. However, one could argue that it would cause
    # this function to "do more than one thing".
    output = secrets
    if isinstance(secrets, SecretsCollection):
        output = format_for_output(secrets)

    with open(filename, 'w') as f:
        f.write(json.dumps(output, indent=2) + '\n')


def upgrade(baseline: Dict[str, Any]) -> Dict[str, Any]:
    """
    Baselines will eventually require format changes. This function is responsible for upgrading
    an older baseline to the latest version.
    """
    baseline_version = Version(baseline['version'])
    if baseline_version >= Version(VERSION):
        return baseline

    modules = import_modules_from_package(
        upgrades,
        filter=lambda x: not _is_relevant_upgrade_module(baseline_version)(x),
    )

    new_baseline = {**baseline}
    for module in modules:
        module.upgrade(new_baseline)

    new_baseline['version'] = VERSION
    return new_baseline


def _is_relevant_upgrade_module(current_version: Version) -> Callable:
    def wrapped(module_path: str) -> bool:
        # This converts `v1_0` to `1.0`
        affected_version_string = module_path.rsplit('.', 1)[-1].lstrip('v').replace('_', '.')

        # Patch version doesn't matter, because patches should not require baseline bumps.
        affected_version = Version(f'{affected_version_string}.0')

        return current_version < affected_version

    return wrapped
