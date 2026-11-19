import os
import subprocess
from typing import Any
from typing import cast
from typing import Generator
from typing import Iterable
from typing import List
from typing import Set
from typing import Tuple
from typing import Union

from ..filters.allowlist import is_line_allowlisted
from ..settings import get_filters
from ..settings import get_plugins
from ..settings import get_settings
from ..transformers import get_transformed_file
from ..types import NamedIO
from ..types import SelfAwareCallable
from ..util import git
from ..util.code_snippet import CodeSnippet
from ..util.code_snippet import get_code_snippet
from ..util.inject import call_function_with_arguments
from ..util.path import get_relative_path
from .budget import get_budget
from .budget import get_tracker
from .log import log
from .plugins import Plugin
from .potential_secret import PotentialSecret


def get_files_to_scan(
    *paths: str,
    should_scan_all_files: bool = False,
    root: str = '',
) -> Generator[str, None, None]:
    """
    If we specify specific files, we should be able to scan them. This abides by the
    Principle of Least Surprise -- so users don't have to do:

        $ detect-secrets scan test_data/config.env --all-files

    to scan the specific file.

        >>> list(get_files_to_scan('test_data/config.env')) == ['test_data/config.env']

    In a similar way,

        >>> list(get_files_to_scan('test_data/config.env', '.secrets.baseline')) == \
        ...     ['test_data/config.env', '.secrets.baseline']

    If we specify directories, then we should use git tracked files when possible. To
    override this behavior, we can specify `should_scan_all_files=True`, which will force
    the scan for all files.

    See test cases for more details.

    :param root: if not specified, will assume current repository as root.
    """
    if root:
        root = os.path.realpath(root)

    # First, we determine the appropriate filtering mode to be used.
    # If this is True, then it will consider everything to be valid.
    # Otherwise, it will only list the files that are valid.
    valid_paths: Union[bool, Set[str]] = True
    for path in paths:
        # Since this is not a directory, we assume that it is a file proper, and automatically
        # consider it valid.
        if not os.path.isdir(path):
            continue

        if not should_scan_all_files:
            try:
                valid_paths = git.get_tracked_files(git.get_root_directory(root))
            except subprocess.CalledProcessError:
                log.warning('Did not detect git repository. Try scanning all files instead.')
                valid_paths = False

        # Since valid_paths attempts to get *all* tracked files in the repository, we just need
        # to initialize it once.
        break

    if not valid_paths:
        yield from []
        return

    budget = get_budget()
    files_emitted = 0
    for path in paths:
        iterator = (
            cast(List[Tuple], [(root or os.getcwd(), None, [path])])
            if os.path.isfile(path)
            else os.walk(path)
        )

        for path_root, _, filenames in iterator:
            for filename in filenames:
                relative_path = get_relative_path(
                    root=root or os.getcwd(),
                    path=os.path.join(path_root, filename),
                )
                if not relative_path:
                    # e.g. symbolic links may be pointing outside the root directory
                    continue

                if (
                    valid_paths is True
                    or relative_path in valid_paths
                ):
                    if budget.max_files is not None and files_emitted >= budget.max_files:
                        get_tracker().record(
                            'file_count_exceeded',
                            detail=(
                                f'Only the first {budget.max_files} files were scanned; '
                                f'"{relative_path}" and any remaining files were skipped.'
                            ),
                            once=True,
                        )
                        return

                    files_emitted += 1
                    yield relative_path


def scan_line(line: str) -> Generator[PotentialSecret, None, None]:
    """Used for adhoc string scanning."""
    # Disable this, since it doesn't make sense to run this for adhoc usage.
    get_settings().disable_filters(
        'detect_secrets.filters.common.is_invalid_file',
    )
    get_filters.cache_clear()
    context = get_code_snippet(lines=[line], line_number=1)

    yield from (
        secret
        for plugin in get_plugins()
        for secret in _scan_line(
            plugin=plugin,
            filename='adhoc-string-scan',
            line=line,
            line_number=0,
            enable_eager_search=True,
            context=context,
        )
        if not _is_filtered_out(
            required_filter_parameters=['context'],
            filename=secret.filename,
            secret=secret.secret_value,
            plugin=plugin,
            line=line,
            context=context,
        )
    )


def scan_file(filename: str) -> Generator[PotentialSecret, None, None]:
    try:
        if not get_plugins():   # pragma: no cover
            log.error('No plugins to scan with!')
            return
    except FileNotFoundError:
        log.error('Unable to load plugins!')
        return

    if _is_filtered_out(required_filter_parameters=['filename'], filename=filename):
        return

    if _exceeds_file_size_budget(filename):
        return

    try:
        has_secret = False
        for lines in _get_lines_from_file(filename):
            for secret in _process_line_based_plugins(
                lines=list(enumerate(lines, start=1)),
                filename=filename,
            ):
                has_secret = True
                yield secret

            if has_secret:
                break
    except IOError:
        log.warning(f'Unable to open file: {filename}')
        return


def _exceeds_file_size_budget(filename: str) -> bool:
    max_file_bytes = get_budget().max_file_bytes
    if max_file_bytes is None:
        return False

    try:
        file_size = os.path.getsize(filename)
    except OSError:
        return False

    if file_size <= max_file_bytes:
        return False

    get_tracker().record(
        'file_size_exceeded',
        filename=filename,
        detail=(
            f'File is {file_size} bytes, exceeding the budget of {max_file_bytes} '
            'bytes; file was skipped.'
        ),
    )
    return True


def scan_diff(diff: str) -> Generator[PotentialSecret, None, None]:
    """
    :raises: ImportError
    """
    if not get_plugins():   # pragma: no cover
        log.error('No plugins to scan with!')
        return

    for filename, lines in _get_lines_from_diff(diff):
        yield from _process_line_based_plugins(lines, filename=filename)


def scan_for_allowlisted_secrets_in_file(filename: str) -> Generator[PotentialSecret, None, None]:
    """
    Developers are able to add individual lines to the allowlist using
    `detect_secrets.filters.allowlist.is_line_allowlisted`. However, there are
    times when we want to verify that no *actual* secrets are added to the codebase
    via this feature.

    This scans specifically for these lines, and ignores everything else.
    """
    if not get_plugins():   # pragma: no cover
        log.error('No plugins to scan with!')
        return

    if _is_filtered_out(
        required_filter_parameters=['filename'],
        filename=filename,
    ):
        return

    # NOTE: Unlike `scan_file`, we don't ever have to use eager file transformers, since we already
    # know which lines we want to scan.
    try:
        for lines in _get_lines_from_file(filename):
            yield from _scan_for_allowlisted_secrets_in_lines(enumerate(lines, start=1), filename)
            break
    except IOError:
        log.warning(f'Unable to open file: {filename}')
        return


def scan_for_allowlisted_secrets_in_diff(diff: str) -> Generator[PotentialSecret, None, None]:
    if not get_plugins():   # pragma: no cover
        log.error('No plugins to scan with!')
        return

    for filename, lines in _get_lines_from_diff(diff):
        yield from _scan_for_allowlisted_secrets_in_lines(lines, filename)


def _scan_for_allowlisted_secrets_in_lines(
    lines: Iterable[Tuple[int, str]],
    filename: str,
) -> Generator[PotentialSecret, None, None]:
    # We control the setting here because it makes more sense than requiring the caller
    # to set this setting before calling this function.
    get_settings().disable_filters('detect_secrets.filters.allowlist.is_line_allowlisted')
    get_filters.cache_clear()

    line_numbers, lines = zip(*lines)
    line_content = [line.rstrip() for line in lines]
    for line_number, line in zip(line_numbers, line_content):
        context = get_code_snippet(line_content, line_number)
        if not is_line_allowlisted(
            filename=filename,
            line=line,
            context=context,
        ):
            continue

        if _is_filtered_out(required_filter_parameters=['line'], filename=filename, line=line):
            continue

        for plugin in get_plugins():
            yield from _scan_line(
                plugin=plugin,
                filename=filename,
                line=line,
                line_number=line_number,
                context=context,
            )


def _get_lines_from_file(filename: str) -> Generator[List[str], None, None]:
    """
    This attempts to get lines in a given file. If no more lines are needed, the caller
    is responsible for breaking out of this loop.

    :raises: IOError
    :raises: FileNotFoundError
    """
    with open(filename) as f:
        log.info(f'Checking file: {filename}')

        try:
            lines = get_transformed_file(cast(NamedIO, f))
            if not lines:
                lines = f.readlines()
        except UnicodeDecodeError:
            # We flat out ignore binary files
            return

        yield _enforce_line_budgets(lines, filename)

        # If the above lines don't prove to be useful to the caller, try using eager transformers.
        f.seek(0)
        lines = get_transformed_file(cast(NamedIO, f), use_eager_transformers=True)
        if not lines:
            return

        yield _enforce_line_budgets(lines, filename)


def _enforce_line_budgets(lines: List[str], filename: str) -> List[str]:
    """
    Truncates the lines of a file to the configured budgets, recording a budget
    event whenever content is dropped. This bounds the amount of work (and
    memory) that pathological files (e.g. minified files with huge lines) can
    cause, while making the truncation visible rather than silently returning
    incomplete results.
    """
    budget = get_budget()

    if budget.max_lines_per_file is not None and len(lines) > budget.max_lines_per_file:
        get_tracker().record(
            'line_count_exceeded',
            filename=filename,
            detail=(
                f'File has {len(lines)} lines, exceeding the budget of '
                f'{budget.max_lines_per_file}; remaining lines were not scanned.'
            ),
        )
        lines = lines[:budget.max_lines_per_file]

    if budget.max_line_length is not None:
        was_truncated = False
        trimmed_lines = []
        for line in lines:
            if len(line) > budget.max_line_length:
                was_truncated = True
                line = line[:budget.max_line_length]

            trimmed_lines.append(line)

        if was_truncated:
            get_tracker().record(
                'line_length_exceeded',
                filename=filename,
                detail=(
                    'One or more lines exceed the budget of '
                    f'{budget.max_line_length} characters; trailing content was '
                    'not scanned.'
                ),
            )
            lines = trimmed_lines

    return lines


def _get_lines_from_diff(diff: str) -> Generator[Tuple[str, List[Tuple[int, str]]], None, None]:
    """
    :raises: ImportError
    """
    # Local imports, so that we don't need to require unidiff for versions of
    # detect-secrets that don't use it.
    from unidiff import PatchSet

    patch_set = PatchSet.from_string(diff)
    for patch_file in patch_set:
        filename = patch_file.path
        if _is_filtered_out(required_filter_parameters=['filename'], filename=filename):
            continue

        yield (
            filename,
            [
                (line.target_line_no, line.value)
                for chunk in patch_file
                # target_lines refers to incoming (new) changes
                for line in chunk.target_lines()
                if line.is_added
            ],
        )


def _process_line_based_plugins(
    lines: List[Tuple[int, str]],
    filename: str,
) -> Generator[PotentialSecret, None, None]:
    line_content = [line[1] for line in lines]

    # NOTE: We iterate through lines *then* plugins, because we want to quit early if any of the
    # filters return True.
    for line_number, line in lines:
        log.debug(f'Processing {filename}:{line_number}')
        line = line.rstrip()
        code_snippet = get_code_snippet(
            lines=line_content,
            line_number=line_number,
        )

        # We apply line-specific filters, and see whether that allows us to quit early.
        if _is_filtered_out(
            required_filter_parameters=['line'],
            filename=filename,
            line=line,
            context=code_snippet,
        ):
            continue

        yield from (
            secret
            for plugin in get_plugins()
            for secret in _scan_line(
                plugin=plugin,
                filename=filename,
                line=line,
                line_number=line_number,
                context=code_snippet,
            )
            if not _is_filtered_out(
                required_filter_parameters=['context'],
                filename=secret.filename,
                secret=secret.secret_value,
                plugin=plugin,
                line=line,
                context=code_snippet,
            )
        )


def _scan_line(
    plugin: Plugin,
    filename: str,
    line: str,
    line_number: int,
    context: CodeSnippet,
    **kwargs: Any,
) -> Generator[PotentialSecret, None, None]:
    # NOTE: We don't apply filter functions here yet, because we don't have any filters
    # that operate on (filename, line, plugin) without `secret`
    secrets = call_function_with_arguments(
        plugin.analyze_line,
        filename=filename,
        line=line,
        line_number=line_number,
        context=context,
        **kwargs,
    )
    if not secrets:
        return

    yield from (
        secret
        for secret in secrets
        if not _is_filtered_out(
            required_filter_parameters=['secret'],
            filename=secret.filename,
            secret=secret.secret_value,
            plugin=plugin,
            line=line,
        )
    )


def _is_filtered_out(required_filter_parameters: Iterable[str], **kwargs: Any) -> bool:
    for filter_fn in get_filters_with_parameter(*required_filter_parameters):
        try:
            if call_function_with_arguments(filter_fn, **kwargs):
                if 'secret' in kwargs:
                    debug_msg = f'Skipping "{0}" due to `{1}`.'.format(
                        kwargs['secret'],
                        filter_fn.path,
                    )
                elif list(kwargs.keys()) == ['filename']:
                    # We want to make sure this is only run if we're skipping files (as compared
                    # to other filters that may include `filename` as a parameter).
                    debug_msg = 'Skipping "{0}" due to `{1}`'.format(
                        kwargs['filename'],
                        filter_fn.path,
                    )
                else:
                    debug_msg = 'Skipping secret due to `{0}`.'.format(filter_fn.path)

                log.info(debug_msg)
                return True
        except TypeError:
            # Skipping non-compatible filters
            pass

    return False


def get_filters_with_parameter(*parameters: str) -> List[SelfAwareCallable]:
    """
    The issue of our method of dependency injection is that functions will be called multiple
    times. For example, if we have two functions:

    >>> def foo(filename: str): ...
    >>> def bar(filename: str, secret: str): ...

    our invocation of `call_function_with_arguments(filename=filename, secret=secret)`
    will run both of these functions. While expected, this results in multiple invocations of
    the same function, which can be less than ideal (especially if we have a heavy duty filter).

    To address this, we filter our filters with this function. It will return the functions
    that accept a minimum set of parameters, to avoid duplicative work. For instance,

    >>> get_filters_with_parameter('secret')
    [bar]
    """
    minimum_parameters = set(parameters)

    return [
        filter
        for filter in get_filters()
        if minimum_parameters <= filter.injectable_variables
    ]
