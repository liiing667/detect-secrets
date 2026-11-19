import os

import pytest

from detect_secrets.util.path import get_relative_path
from detect_secrets.util.path import get_relative_path_if_in_cwd


@pytest.mark.skipif(os.name == 'nt', reason='symlink semantics differ on Windows')
class TestGetRelativePath:
    @staticmethod
    def test_returns_normalized_relative_path(tmp_path):
        nested = tmp_path / 'dir' / 'file.txt'
        nested.parent.mkdir()
        nested.write_text('')

        assert (
            get_relative_path(
                str(tmp_path),
                os.path.join(str(tmp_path), 'dir', '..', 'dir', 'file.txt'),
            )
            == os.path.join('dir', 'file.txt')
        )

    @staticmethod
    def test_symlink_resolves_to_canonical_relative_path(tmp_path):
        real_file = tmp_path / 'real_file.txt'
        real_file.write_text('')
        link = tmp_path / 'link.txt'
        link.symlink_to(real_file)

        assert get_relative_path(str(tmp_path), str(link)) == 'real_file.txt'

    @staticmethod
    def test_returns_none_for_path_outside_root(tmp_path):
        outside = tmp_path.parent / 'outside.txt'
        outside.write_text('')
        try:
            assert get_relative_path(str(tmp_path), str(outside)) is None
        finally:
            outside.unlink()

    @staticmethod
    def test_does_not_mistake_sibling_directory_with_shared_prefix(tmp_path):
        root = tmp_path / 'root'
        sibling = tmp_path / 'root_sibling'
        root.mkdir()
        sibling.mkdir()
        target = sibling / 'file.txt'
        target.write_text('')

        assert get_relative_path(str(root), str(target)) is None

    @staticmethod
    def test_returns_none_for_symlink_pointing_outside_root(tmp_path):
        outside = tmp_path.parent / 'outside_target.txt'
        outside.write_text('')
        link = tmp_path / 'escape.txt'
        link.symlink_to(outside)
        try:
            assert get_relative_path(str(tmp_path), str(link)) is None
        finally:
            outside.unlink()

    @staticmethod
    def test_keeps_dangling_symlink_within_root_as_relative_path(tmp_path):
        # Existence is enforced by the scan layer; the path utility only guarantees
        # canonicalization and root containment.
        link = tmp_path / 'dangling.txt'
        link.symlink_to(tmp_path / 'does_not_exist.txt')

        assert get_relative_path(str(tmp_path), str(link)) == 'does_not_exist.txt'


@pytest.mark.skipif(os.name == 'nt', reason='symlink semantics differ on Windows')
class TestGetRelativePathIfInCwd:
    @staticmethod
    def test_returns_relative_path_for_file_inside_cwd(tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        nested = tmp_path / 'file.txt'
        nested.write_text('')

        assert get_relative_path_if_in_cwd(str(nested)) == 'file.txt'

    @staticmethod
    def test_returns_none_for_path_outside_cwd(tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        outside = tmp_path.parent / 'outside_cwd.txt'
        outside.write_text('')
        try:
            assert get_relative_path_if_in_cwd(str(outside)) is None
        finally:
            outside.unlink()

    @staticmethod
    def test_returns_none_for_directory(tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        directory = tmp_path / 'dir'
        directory.mkdir()

        assert get_relative_path_if_in_cwd(str(directory)) is None
