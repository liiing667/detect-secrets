import copy
import json
import time
from typing import Any
from typing import Callable
from typing import cast
from typing import Dict
from typing import List
from typing import Optional
from typing import Union

from . import upgrades
from ..__version__ import VERSION
from ..exceptions import InvalidBaselineError
from ..exceptions import UnableToReadBaselineError
from ..settings import configure_settings_from_baseline
from ..settings import get_settings
from ..util.importlib import import_modules_from_package
from ..util.semver import Version
from .scan import get_files_to_scan
from .secrets_collection import SecretsCollection

# Fields that uniquely identify a recorded secret. If any of these are missing
# or malformed, the secret cannot be carried across format versions without
# risking drift, so the upgrade fails closed.
REQUIRED_SECRET_FIELDS = (
    'type',
    'hashed_secret',
)


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

    :raises: KeyError
    """
    # This is required for backwards compatibility, and supporting upgrades from older versions.
    baseline = upgrade(baseline)

    configure_settings_from_baseline(baseline, filename=filename)
    return SecretsCollection.load_from_baseline(baseline)


def load_from_file(filename: str) -> Dict[str, Any]:
    """
    :raises: UnableToReadBaselineError
    :raises: InvalidBaselineError
    """
    try:
        with open(filename) as f:
            return cast(Dict[str, Any], json.loads(f.read()))
    except (FileNotFoundError, IOError, json.decoder.JSONDecodeError) as e:
        raise UnableToReadBaselineError from e


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

    The upgrade fails closed (raising :class:`InvalidBaselineError`) when the baseline version
    is missing or unparseable, or when a recorded secret is missing its identifying fields or
    the upgrade modules would otherwise let a secret record drift.

    This guarantees that every secret's fingerprint, type, location and manual classification
    survive the migration: the input baseline is never mutated, and its ``results`` are copied
    verbatim into the upgraded baseline.
    """
    baseline_version = _parse_baseline_version(baseline)
    if baseline_version >= Version(VERSION):
        return baseline

    _validate_results(baseline.get('results', {}))

    # Deep copy so that the original (old-format) baseline stays intact and can be reviewed
    # alongside the upgraded one. A shallow copy would let the upgrade modules mutate nested
    # results in place.
    new_baseline = copy.deepcopy(baseline)

    modules = import_modules_from_package(
        upgrades,
        filter=lambda x: not _is_relevant_upgrade_module(baseline_version)(x),
    )

    for module in modules:
        module.upgrade(new_baseline)

    new_baseline['version'] = VERSION

    # The upgrade modules only touch configuration-level fields. Assert that no secret record
    # drifted (e.g. fingerprint, type, location or human classification), failing closed
    # otherwise.
    _assert_results_preserved(baseline, new_baseline)
    return new_baseline


def _parse_baseline_version(baseline: Dict[str, Any]) -> Version:
    """:raises: InvalidBaselineError"""
    if 'version' not in baseline:
        raise InvalidBaselineError(
            'Unable to upgrade baseline: no `version` field found. '
            'Try recreating your baseline to fix this issue.',
        )

    try:
        return Version(str(baseline['version']))
    except (TypeError, ValueError) as e:
        raise InvalidBaselineError(
            f'Unable to upgrade baseline: invalid version '
            f'{baseline["version"]!r}. Try recreating your baseline to fix this issue.',
        ) from e


def _validate_results(results: Any) -> None:
    """
    Ensures every recorded secret carries the fields required to identify it across format
    versions, and that its location (the filename key) is well-formed.

    :raises: InvalidBaselineError
    """
    if not isinstance(results, dict):
        # Some very old baselines serialized an empty result set as an empty list. Accept that
        # historical shape, but reject any non-empty list (which cannot carry secret records).
        if isinstance(results, list) and not results:
            return

        raise InvalidBaselineError(
            'Unable to upgrade baseline: `results` must be a mapping of filenames to secrets. '
            'Try recreating your baseline to fix this issue.',
        )

    for filename, secret_list in results.items():
        if not isinstance(filename, str) or not filename:
            raise InvalidBaselineError(
                'Unable to upgrade baseline: found a result with an invalid filename. '
                'Try recreating your baseline to fix this issue.',
            )

        if not isinstance(secret_list, list):
            raise InvalidBaselineError(
                f'Unable to upgrade baseline: results for {filename!r} must be a list of '
                'secrets. Try recreating your baseline to fix this issue.',
            )

        for index, secret in enumerate(secret_list):
            if not isinstance(secret, dict):
                raise InvalidBaselineError(
                    f'Unable to upgrade baseline: secret #{index} in {filename!r} is not a '
                    'valid secret record. Try recreating your baseline to fix this issue.',
                )

            missing_fields = [
                field
                for field in REQUIRED_SECRET_FIELDS
                if not isinstance(secret.get(field), str) or not secret.get(field)
            ]
            if missing_fields:
                raise InvalidBaselineError(
                    f'Unable to upgrade baseline: secret #{index} in {filename!r} is missing '
                    f'required field(s): {", ".join(missing_fields)}. '
                    'Try recreating your baseline to fix this issue.',
                )

            line_number = secret.get('line_number')
            if line_number is not None and not isinstance(line_number, int):
                raise InvalidBaselineError(
                    f'Unable to upgrade baseline: secret #{index} in {filename!r} has an '
                    'invalid `line_number`. Try recreating your baseline to fix this issue.',
                )


def _assert_results_preserved(
    old_baseline: Dict[str, Any],
    new_baseline: Dict[str, Any],
) -> None:
    """:raises: InvalidBaselineError"""
    if old_baseline.get('results', {}) != new_baseline.get('results', {}):
        raise InvalidBaselineError(
            'Unable to upgrade baseline: secret records changed during the upgrade. '
            'Try recreating your baseline to fix this issue.',
        )


def _is_relevant_upgrade_module(current_version: Version) -> Callable:
    def wrapped(module_path: str) -> bool:
        # This converts `v1_0` to `1.0`
        affected_version_string = module_path.rsplit('.', 1)[-1].lstrip('v').replace('_', '.')

        # Patch version doesn't matter, because patches should not require baseline bumps.
        affected_version = Version(f'{affected_version_string}.0')

        return current_version < affected_version

    return wrapped
