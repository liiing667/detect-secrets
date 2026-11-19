import builtins
import json
import os
import tempfile
from contextlib import contextmanager
from typing import Generator

import pytest

from detect_secrets.core import baseline
from detect_secrets.exceptions import BaselineSizeExceededError
from detect_secrets.exceptions import DuplicateKeyError
from detect_secrets.exceptions import InvalidBaselineError
from detect_secrets.exceptions import PathTraversalError
from detect_secrets.exceptions import UnableToReadBaselineError
from testing.mocks import mock_named_temporary_file


FIXTURE_DIR = os.path.join('test_data', 'baselines')


@pytest.fixture(autouse=True)
def clear_baseline_cache():
    baseline.clear_baseline_cache()
    yield
    baseline.clear_baseline_cache()


def _fixture_path(name: str) -> str:
    return os.path.join(FIXTURE_DIR, name)


@contextmanager
def _in_repo_baseline(content: str) -> Generator[str, None, None]:
    # Keep the baseline inside the working directory so that its own path passes the
    # ownership boundary; only the *contents* of the document are malicious.
    handle = tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.json',
        dir='.',
        delete=False,
    )
    try:
        handle.write(content)
        handle.flush()
        yield handle.name
    finally:
        handle.close()
        os.unlink(handle.name)


class TestDuplicateKeys:
    @staticmethod
    def test_duplicate_top_level_key_rejected():
        with pytest.raises(DuplicateKeyError):
            baseline.load_from_file(_fixture_path('duplicate_keys_baseline.json'))

    @staticmethod
    def test_duplicate_nested_key_rejected():
        content = (
            '{'
            '"version": "1.5.0",'
            '"plugins_used": [],'
            '"results": {"file.py": ['
            '{"type": "AWS Access Key", "hashed_secret": "a", "type": "other"}'
            ']}'
            '}'
        )
        with _in_repo_baseline(content) as filename:
            with pytest.raises(DuplicateKeyError):
                baseline.load_from_file(filename)

    @staticmethod
    def test_duplicate_key_is_invalid_baseline():
        # The exception hierarchy must let callers handling InvalidBaselineError
        # also catch duplicate-key documents.
        with pytest.raises(InvalidBaselineError):
            baseline.load_from_file(_fixture_path('duplicate_keys_baseline.json'))


class TestFileSizeLimit:
    @staticmethod
    def test_oversized_baseline_rejected(monkeypatch):
        monkeypatch.setattr(baseline, 'MAX_BASELINE_FILE_SIZE', 128)
        with pytest.raises(BaselineSizeExceededError):
            baseline.load_from_file(_fixture_path('valid_baseline.json'))

    @staticmethod
    def test_size_limit_is_read_failure_not_invalid():
        # Size violations are treated as unreadable inputs, not structurally bad ones.
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(baseline, 'MAX_BASELINE_FILE_SIZE', 128)
            with pytest.raises(UnableToReadBaselineError):
                baseline.load_from_file(_fixture_path('valid_baseline.json'))

    @staticmethod
    def test_growing_file_between_stat_and_read_rejected(monkeypatch):
        filename = _fixture_path('valid_baseline.json')

        original_open = builtins.open

        def growing_open(path, *args, **kwargs):
            handle = original_open(path, *args, **kwargs)
            original_read = handle.read

            def inflated_read():
                return original_read() + ' ' * (baseline.MAX_BASELINE_FILE_SIZE + 1)

            handle.read = inflated_read
            return handle

        monkeypatch.setattr(builtins, 'open', growing_open)
        with pytest.raises(BaselineSizeExceededError):
            baseline.load_from_file(filename)


class TestPathTraversal:
    @staticmethod
    @pytest.mark.parametrize(
        'path',
        (
            '../../etc/passwd',
            '../' * 10 + 'etc/shadow',
            '/etc/passwd',
            '/tmp/outside.txt',
            r'C:\Windows\system32',
            r'\\fileserver\share\secret',
        ),
    )
    def test_escaping_paths_rejected(path):
        content = json.dumps({
            'version': '1.5.0',
            'plugins_used': [],
            'results': {
                path: [],
            },
        })
        with _in_repo_baseline(content) as filename:
            with pytest.raises(PathTraversalError):
                baseline.load_from_file(filename)

    @staticmethod
    def test_fixture_traversal_baseline_rejected():
        with pytest.raises(PathTraversalError):
            baseline.load_from_file(_fixture_path('path_traversal_baseline.json'))

    @staticmethod
    def test_in_repo_relative_paths_accepted():
        data = baseline.load_from_file(_fixture_path('valid_baseline.json'))
        assert data['version'] == '1.5.0'

    @staticmethod
    def test_load_dict_entry_point_also_enforces_boundary():
        malicious = {
            'version': '1.5.0',
            'plugins_used': [],
            'results': {
                '../../etc/passwd': [],
            },
        }
        with pytest.raises(PathTraversalError):
            baseline.load(malicious)


class TestStructureAndVersion:
    @staticmethod
    @pytest.mark.parametrize(
        'document',
        (
            [],
            'not-an-object',
            {'plugins_used': []},
            {'version': '1.5.0'},
            {'version': 1, 'results': {}},
            {'version': 'not-a-version', 'results': {}},
            {'version': '1.5.0', 'results': []},
            {'version': '1.5.0', 'results': {'file.py': 'not-a-list'}},
            {'version': '1.5.0', 'results': {'file.py': ['not-an-object']}},
        ),
    )
    def test_malformed_documents_rejected(document):
        with pytest.raises(InvalidBaselineError):
            baseline.validate_baseline_structure(document)

    @staticmethod
    def test_non_string_result_path_rejected():
        with pytest.raises(InvalidBaselineError):
            baseline.validate_baseline_structure({
                'version': '1.5.0',
                'results': {1: []},
            })

    @staticmethod
    def test_missing_file_is_unreadable():
        with pytest.raises(UnableToReadBaselineError):
            baseline.load_from_file('this-baseline-does-not-exist.json')

    @staticmethod
    def test_malformed_json_is_unreadable():
        with _in_repo_baseline('{not valid json') as filename:
            with pytest.raises(UnableToReadBaselineError):
                baseline.load_from_file(filename)

    @staticmethod
    def test_read_error_is_unreadable(monkeypatch):
        def failing_open(path, *args, **kwargs):
            raise IOError('disk on fire')

        monkeypatch.setattr('builtins.open', failing_open)
        with pytest.raises(UnableToReadBaselineError):
            baseline.load_from_file(_fixture_path('valid_baseline.json'))

    @staticmethod
    def test_newer_version_rejected():
        with pytest.raises(InvalidBaselineError):
            baseline.validate_baseline_structure({
                'version': '99.0.0',
                'results': {},
            })

    @staticmethod
    def test_legacy_version_still_readable():
        data = baseline.load_from_file(_fixture_path('legacy_baseline.json'))
        secrets = baseline.load(data)
        assert secrets.data == {}

    @staticmethod
    def test_empty_results_are_readable():
        data = baseline.load_from_file(_fixture_path('empty_results_baseline.json'))
        secrets = baseline.load(data)
        assert secrets.files == set()


class TestNormalImport:
    @staticmethod
    def test_valid_fixture_loads_and_collects_secrets():
        data = baseline.load_from_file(_fixture_path('valid_baseline.json'))
        secrets = baseline.load(data, filename=_fixture_path('valid_baseline.json'))

        assert len(secrets.files) == 1
        filename = os.path.join('test_data', 'files', 'file_with_secrets.py')
        assert len(secrets[filename]) == 1

    @staticmethod
    def test_cached_copy_is_returned_on_second_read():
        filename = _fixture_path('valid_baseline.json')
        first = baseline.load_from_file(filename)
        second = baseline.load_from_file(filename)

        assert first == second
        assert first is not second

        # Mutating a returned document must not corrupt the cached boundary.
        first['results'] = {}
        assert baseline.load_from_file(filename)['results'] != {}


class TestCacheRetentionOnFailure:
    @staticmethod
    def test_failed_import_keeps_previous_cache():
        filename = _fixture_path('valid_baseline.json')
        good_data = baseline.load_from_file(filename)
        cache_key = os.path.realpath(filename)
        assert cache_key in baseline._baseline_cache

        # Tamper with the on-disk document so a fresh read fails the structural
        # boundary; the previously validated cache entry must remain untouched.
        tampered = json.dumps({'plugins_used': []})
        with _in_repo_baseline(tampered) as other_filename:
            other_key = os.path.realpath(other_filename)
            with pytest.raises(InvalidBaselineError):
                baseline.load_from_file(other_filename)
            assert other_key not in baseline._baseline_cache

        assert baseline.load_from_file(filename) == good_data
        assert baseline._baseline_cache[cache_key]['data'] == good_data

    @staticmethod
    def test_oversized_failure_keeps_previous_cache(monkeypatch):
        filename = _fixture_path('valid_baseline.json')
        good_data = baseline.load_from_file(filename)
        cache_key = os.path.realpath(filename)

        # Point the cache key somewhere else so the oversized read cannot take the
        # fast path, then restore it: the failed size check must not have mutated the
        # original entry.
        entry = baseline._baseline_cache.pop(cache_key)
        baseline._baseline_cache[cache_key + '.shadow'] = entry
        try:
            monkeypatch.setattr(baseline, 'MAX_BASELINE_FILE_SIZE', 128)
            with pytest.raises(BaselineSizeExceededError):
                baseline.load_from_file(filename)
        finally:
            monkeypatch.undo()
            baseline._baseline_cache.pop(cache_key + '.shadow', None)
            baseline._baseline_cache[cache_key] = entry

        assert baseline.load_from_file(filename) == good_data

    @staticmethod
    def test_invalid_file_never_populates_cache():
        with pytest.raises(DuplicateKeyError):
            baseline.load_from_file(_fixture_path('duplicate_keys_baseline.json'))

        assert baseline._baseline_cache == {}

    @staticmethod
    def test_rewritten_baseline_is_re_read_not_served_stale():
        with mock_named_temporary_file() as f:
            f.write(json.dumps({
                'version': '1.5.0',
                'plugins_used': [],
                'results': {},
            }).encode())
            f.seek(0)
            filename = f.name

            assert baseline.load_from_file(filename)['results'] == {}

            # Simulate an audit session saving progress back to the same file.
            updated = {
                'version': '1.5.0',
                'plugins_used': [],
                'results': {
                    'test_data/files/file_with_secrets.py': [
                        {
                            'type': 'AWS Access Key',
                            'hashed_secret': 'a',
                            'is_verified': False,
                            'line_number': 1,
                        },
                    ],
                },
            }
            baseline.save_to_file(updated, filename)

            reloaded = baseline.load_from_file(filename)
            assert reloaded['results'] != {}
