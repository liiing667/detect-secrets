import os
import textwrap
from pathlib import Path

import pytest

from detect_secrets.core import scan
from detect_secrets.settings import transient_settings
from detect_secrets.util import git
from detect_secrets.util.path import get_relative_path_if_in_cwd
from testing.mocks import mock_named_temporary_file


class TestGetFilesToScan:
    @staticmethod
    def test_should_scan_specific_non_tracked_file(non_tracked_file):
        assert list(scan.get_files_to_scan(non_tracked_file.name, should_scan_all_files=False))

    @staticmethod
    def test_should_scan_tracked_files_in_directory(non_tracked_file):
        assert (
            get_relative_path_if_in_cwd(non_tracked_file.name) not in set(
                scan.get_files_to_scan(
                    os.path.dirname(non_tracked_file.name),
                    should_scan_all_files=False,
                ),
            )
        )

    @staticmethod
    def test_should_scan_all_files_in_directory_if_flag_is_provided(non_tracked_file):
        assert (
            get_relative_path_if_in_cwd(non_tracked_file.name) in set(
                scan.get_files_to_scan(
                    os.path.dirname(non_tracked_file.name),
                    should_scan_all_files=True,
                ),
            )
        )

    @staticmethod
    def test_handles_each_path_separately(non_tracked_file):
        results = list(
            scan.get_files_to_scan(
                non_tracked_file.name,
                'test_data/short_files',
            ),
        )

        # This implies that the test_data/short_files directory is scanned, because otherwise,
        # it would only be one file. However, at the same time, this test case isn't fragile to
        # additions to this directory.
        assert len(results) > 2

    @staticmethod
    def test_handles_multiple_directories():
        directories = [Path('test_data/short_files'), Path('test_data/files')]
        results = list(scan.get_files_to_scan(*directories))

        for prefix in directories:
            assert len(list(filter(lambda x: x.startswith(str(prefix)), results))) > 1

    @staticmethod
    @pytest.fixture(autouse=True, scope='class')
    def non_tracked_file():
        with mock_named_temporary_file(
            prefix=os.path.join(git.get_root_directory(), 'test_data/'),
        ) as f:
            f.write(b'content does not matter')
            f.seek(0)

            yield f


@pytest.mark.skipif(os.name == 'nt', reason='symlink semantics differ on Windows')
class TestGetFilesToScanSymlinksAndBoundaries:
    @staticmethod
    @pytest.fixture()
    def workspace(tmp_path, monkeypatch):
        """
        Fixed directory layout used to exercise file identity, relative root paths and read
        boundaries in a single place::

            workspace/
            ├── real_file.txt           # regular file (scanned)
            ├── link_to_real.txt         # symlink -> real_file.txt (duplicate identity)
            ├── link_outside.txt         # symlink -> ../outside.txt (outside the root)
            ├── broken_link.txt          # dangling symlink (cannot be resolved)
            ├── real_dir/
            │   └── nested.txt           # regular nested file (scanned)
            └── link_dir                 # symlink -> ../outside_dir (directory, not followed)

            outside_dir/outside_nested.txt
            outside.txt
        """
        workspace = tmp_path / 'workspace'
        workspace.mkdir()

        real_file = workspace / 'real_file.txt'
        real_file.write_text('nothing to see here')

        nested_dir = workspace / 'real_dir'
        nested_dir.mkdir()
        nested_file = nested_dir / 'nested.txt'
        nested_file.write_text('nothing to see here')

        inside_link = workspace / 'link_to_real.txt'
        inside_link.symlink_to(real_file)

        outside_file = tmp_path / 'outside.txt'
        outside_file.write_text('nothing to see here')
        outside_link = workspace / 'link_outside.txt'
        outside_link.symlink_to(outside_file)

        broken_link = workspace / 'broken_link.txt'
        broken_link.symlink_to(tmp_path / 'does_not_exist.txt')

        outside_dir = tmp_path / 'outside_dir'
        outside_dir.mkdir()
        (outside_dir / 'outside_nested.txt').write_text('nothing to see here')
        directory_link = workspace / 'link_dir'
        directory_link.symlink_to(outside_dir, target_is_directory=True)

        monkeypatch.chdir(tmp_path)
        return {
            'root': str(workspace),
            'expected': {
                'real_file.txt',
                os.path.join('real_dir', 'nested.txt'),
            },
            'inside_link': str(inside_link),
            'outside_link': str(outside_link),
            'broken_link': str(broken_link),
            'directory_link': str(directory_link),
            'outside_file': str(outside_file),
        }

    @staticmethod
    def test_directory_scan_lists_entered_and_skipped_entries(workspace, mock_log):
        results = set(
            scan.get_files_to_scan(
                workspace['root'],
                should_scan_all_files=True,
                root=workspace['root'],
            ),
        )

        assert results == workspace['expected']

        # Entered: regular files are scanned under their canonical relative path.
        assert 'real_file.txt' in results
        assert os.path.join('real_dir', 'nested.txt') in results

        # Skipped: the in-workspace symlink collapses onto a file already scanned.
        assert 'already scanned' in mock_log.info_messages
        # Skipped: symlinks resolving outside the workspace never produce results.
        assert 'resolves outside of the scan root' in mock_log.info_messages
        # Skipped: dangling symlinks cannot be resolved, so they don't produce results.
        assert 'target cannot be resolved or read' in mock_log.info_messages
        # Skipped: symlinked directories are not followed.
        assert 'symlinked directories are not followed' in mock_log.info_messages

    @staticmethod
    def test_symlink_does_not_create_duplicate_identity(workspace):
        results = list(
            scan.get_files_to_scan(
                workspace['root'],
                should_scan_all_files=True,
                root=workspace['root'],
            ),
        )

        assert len(results) == len(set(results))
        assert 'link_to_real.txt' not in results

    @staticmethod
    def test_non_normalized_paths_share_one_identity(workspace):
        results = list(
            scan.get_files_to_scan(
                os.path.join(workspace['root'], 'real_dir', '..', 'real_dir', 'nested.txt'),
                should_scan_all_files=True,
                root=workspace['root'],
            ),
        )

        assert results == [os.path.join('real_dir', 'nested.txt')]

    @staticmethod
    def test_explicit_file_inside_root_is_still_scanned(workspace):
        results = list(
            scan.get_files_to_scan(
                os.path.join(workspace['root'], 'real_file.txt'),
                should_scan_all_files=True,
                root=workspace['root'],
            ),
        )

        assert results == ['real_file.txt']

    @staticmethod
    def test_explicit_inside_symlink_resolves_to_canonical_identity(workspace):
        results = list(
            scan.get_files_to_scan(
                workspace['inside_link'],
                should_scan_all_files=True,
                root=workspace['root'],
            ),
        )

        assert results == ['real_file.txt']

    @staticmethod
    def test_explicit_file_outside_root_does_not_produce_results(workspace, mock_log):
        results = list(
            scan.get_files_to_scan(
                workspace['outside_file'],
                should_scan_all_files=True,
                root=workspace['root'],
            ),
        )

        assert results == []
        assert 'resolves outside of the scan root' in mock_log.info_messages

    @staticmethod
    def test_missing_explicit_file_does_not_produce_results(workspace, mock_log):
        results = list(
            scan.get_files_to_scan(
                os.path.join(workspace['root'], 'missing.txt'),
                should_scan_all_files=True,
                root=workspace['root'],
            ),
        )

        assert results == []
        assert 'not a readable file' in mock_log.info_messages

    @staticmethod
    def test_custom_root_normalizes_relative_paths(workspace, monkeypatch):
        monkeypatch.chdir(workspace['root'])
        results = set(
            scan.get_files_to_scan(
                '.',
                should_scan_all_files=True,
                root=os.path.join('.', '..', 'workspace'),
            ),
        )

        assert results == {'real_file.txt', os.path.join('real_dir', 'nested.txt')}


class TestScanFile:
    @staticmethod
    def test_handles_broken_yaml_gracefully():
        with mock_named_temporary_file(suffix='.yaml') as f:
            f.write(
                textwrap.dedent("""
                metadata:
                    name: {{ .values.name }}
                """)[1:].encode(),
            )
            f.seek(0)

            assert not list(scan.scan_file(f.name))

    @staticmethod
    def test_handles_binary_files_gracefully():
        # NOTE: This suffix needs to be something that isn't in the known file types, as determined
        # by `detect_secrets.util.filetype.determine_file_type`.
        with mock_named_temporary_file(suffix='.woff2') as f:
            f.write(b'\x86')
            f.seek(0)

            assert not list(scan.scan_file(f.name))


@pytest.fixture(autouse=True)
def configure_plugins():
    with transient_settings({
        'plugins_used': [
            {
                'name': 'BasicAuthDetector',
            },
        ],
    }):
        yield
