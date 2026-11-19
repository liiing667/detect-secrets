from pathlib import Path
from unittest import mock

import pytest

from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.exceptions import InvalidBaselineError
from detect_secrets.settings import get_settings
from detect_secrets.settings import transient_settings
from testing.factories import potential_secret_factory


@pytest.fixture(autouse=True)
def configure_plugins():
    config = {
        'plugins_used': [
            {'name': 'AWSKeyDetector'},
            {
                'name': 'Base64HighEntropyString',
                'limit': 4.5,
            },
        ],
    }
    with transient_settings(config):
        yield config


class TestScanFile:
    @staticmethod
    def test_filename_filters_are_invoked_first(mock_log):
        # This is a directory, which should be ignored via
        # detect_secrets.filters.common.is_invalid_file
        SecretsCollection().scan_file('test_data')

        assert (
            'Skipping "test_data" due to `detect_secrets.filters.common.is_invalid_file`'
            in mock_log.info_messages
        )

    @staticmethod
    def test_error_reading_file(mock_log_warning):
        with mock.patch(
            'detect_secrets.core.scan.open',
            side_effect=IOError,
        ):
            SecretsCollection().scan_file('test_data/config.env')

        file_warning = str(Path('test_data/config.env'))
        assert 'Unable to open file: %s' % file_warning in mock_log_warning.warning_messages

    @staticmethod
    def test_line_based_success():
        # Explicitly configure filters, so that additions to filters won't affect this test.
        get_settings().configure_filters([
            # This will remove the `id` string
            {'path': 'detect_secrets.filters.heuristic.is_likely_id_string'},

            # This gets rid of the aws keys with `EXAMPLE` in them.
            {
                'path': 'detect_secrets.filters.regex.should_exclude_line',
                'pattern': [
                    'EXAMPLE',
                ],
            },
        ])

        secrets = SecretsCollection()
        secrets.scan_file('test_data/each_secret.py')

        secret = next(iter(secrets[str(Path('test_data/each_secret.py'))]))
        assert secret.secret_value.startswith('c2VjcmV0IG1lc')
        assert len(secrets[str(Path('test_data/each_secret.py'))]) == 1

    @staticmethod
    def test_file_based_success_config():
        get_settings().configure_plugins([
            {
                'name': 'Base64HighEntropyString',
                'limit': 3.0,
            },
        ])
        secrets = SecretsCollection()
        secrets.scan_file('test_data/config.ini')

        assert [str(secret).splitlines()[1] for _, secret in secrets] == [
            'Location:    %s:2' % str(Path('test_data/config.ini')),
            'Location:    %s:10' % str(Path('test_data/config.ini')),
            'Location:    %s:21' % str(Path('test_data/config.ini')),
            'Location:    %s:22' % str(Path('test_data/config.ini')),
            'Location:    %s:32' % str(Path('test_data/config.ini')),
        ]

    @staticmethod
    def test_file_based_success_yaml():
        get_settings().configure_plugins([
            {
                'name': 'HexHighEntropyString',
                'limit': 3.0,
            },
        ])
        secrets = SecretsCollection()
        secrets.scan_file('test_data/config.yaml')

        assert [str(secret).splitlines()[1] for _, secret in secrets] == [
            'Location:    %s:3' % str(Path('test_data/config.yaml')),
            'Location:    %s:5' % str(Path('test_data/config.yaml')),
            'Location:    %s:13' % str(Path('test_data/config.yaml')),
        ]

    @staticmethod
    def test_file_based_yaml_only_comments():
        secrets = SecretsCollection()
        secrets.scan_file('test_data/only_comments.yaml')

        assert not secrets

    @staticmethod
    @pytest.mark.parametrize(
        'filename',
        (
            'test_data/config.env',

            # Markdown files with colons and unicode characters preceding the colon on the line
            # would have caused the scanner to fail and exit on python2.7.
            # This test case ensures scanning can complete and still find high entropy strings.
            'test_data/config.md',
        ),
    )
    def test_file_based_success_unexpected_config_file(filename):
        secrets = SecretsCollection()
        secrets.scan_file(filename)

        assert bool(secrets)


class TestScanDiff:
    @staticmethod
    def test_filename_filters_are_invoked_first():
        get_settings().configure_filters([
            {
                'path': 'detect_secrets.filters.regex.should_exclude_file',
                'pattern': [
                    'test|baseline',
                ],
            },
        ])

        secrets = SecretsCollection()
        with open('test_data/sample.diff') as f:
            secrets.scan_diff(f.read())

        assert len(secrets.files) == 0

    @staticmethod
    def test_success():
        with transient_settings({
            'plugins_used': [
                {
                    'name': 'HexHighEntropyString',
                    'limit': 3,
                },
            ],
            'filters_used': [],
        }):
            secrets = SecretsCollection()
            with open('test_data/sample.diff') as f:
                secrets.scan_diff(f.read())

        assert secrets.files == {
            'detect_secrets/core/baseline.py',
            'tests/core/secrets_collection_test.py',
            '.secrets.baseline',
        }


def test_merge():
    old_secrets = SecretsCollection()
    old_secrets.scan_file('test_data/each_secret.py')
    assert len(list(old_secrets)) >= 4      # otherwise, this test won't work.

    index = 0
    for _, secret in old_secrets:
        if index == 0:
            secret.is_secret = False
        elif index == 1:
            secret.is_secret = True
        elif index == 2:
            secret.is_verified = True

        index += 1

    new_secrets = SecretsCollection()
    new_secrets.scan_file('test_data/each_secret.py')
    list(new_secrets)[-2][1].is_secret = True

    new_secrets.merge(old_secrets)

    index = 0
    for _, secret in new_secrets:
        if index == 0:
            assert secret.is_secret is False
            assert secret.is_verified is False
        elif index == 1:
            assert secret.is_secret is True
            assert secret.is_verified is False
        elif index == 2:
            assert secret.is_secret is True
            assert secret.is_verified is True
        elif index == 3:
            assert secret.is_secret is None
            assert secret.is_verified is False

        index += 1


class TestClassificationIdentity:
    """Classification state belongs to a record's stable identity
    (filename, hashed secret and type), not to the load order of occurrences.
    """

    @staticmethod
    def test_load_rejects_conflicting_is_secret():
        secret = potential_secret_factory()
        conflicting = potential_secret_factory(line_number=2, is_secret=True)
        secret.is_secret = False

        with pytest.raises(InvalidBaselineError) as exc_info:
            SecretsCollection.load_from_baseline(
                {'results': {secret.filename: [secret.json(), conflicting.json()]}},
            )

        assert 'Conflicting `is_secret`' in str(exc_info.value)

    @staticmethod
    def test_load_keeps_verification_when_duplicate_disagrees():
        # Verification is monotonic: an unverified duplicate can't downgrade a record
        # that has already been verified.
        verified = potential_secret_factory(is_verified=True)
        unverified = potential_secret_factory(line_number=2, is_verified=False)

        secrets = SecretsCollection.load_from_baseline(
            {'results': {
                verified.filename: [verified.json(), unverified.json()],
            }},
        )

        merged = next(iter(secrets[verified.filename]))
        assert merged.is_verified is True

    @staticmethod
    def test_load_merges_duplicate_records_with_compatible_labels():
        # The first record carries a legitimate false-positive label at an older line,
        # while the second record shows the same secret moved to another line and has
        # been verified. Both labels survive the merge.
        false_positive = potential_secret_factory(line_number=1, is_secret=False)
        verified = potential_secret_factory(line_number=3, is_verified=True)

        secrets = SecretsCollection.load_from_baseline(
            {'results': {
                false_positive.filename: [false_positive.json(), verified.json()],
            }},
        )

        assert len(secrets[false_positive.filename]) == 1
        merged = next(iter(secrets[false_positive.filename]))
        assert merged.is_secret is False
        assert merged.is_verified is True

    @staticmethod
    def test_load_merges_unlabelled_duplicate_records():
        first = potential_secret_factory(line_number=1)
        second = potential_secret_factory(line_number=2)

        secrets = SecretsCollection.load_from_baseline(
            {'results': {first.filename: [first.json(), second.json()]}},
        )

        assert len(secrets[first.filename]) == 1
        merged = next(iter(secrets[first.filename]))
        assert merged.is_secret is None
        assert merged.is_verified is False

    @staticmethod
    def test_merge_rejects_conflicting_is_secret():
        old_secrets = SecretsCollection()
        old_secret = potential_secret_factory(is_secret=False)
        old_secrets[old_secret.filename].add(old_secret)

        new_secrets = SecretsCollection()
        new_secret = potential_secret_factory(is_secret=True)
        new_secrets[new_secret.filename].add(new_secret)

        with pytest.raises(InvalidBaselineError):
            new_secrets.merge(old_secrets)

    @staticmethod
    def test_merge_preserves_labels_across_line_movement():
        # Same identity (filename, hash and type) but the secret moved lines.
        old_secrets = SecretsCollection()
        old_secret = potential_secret_factory(
            line_number=1,
            is_secret=False,
            is_verified=True,
        )
        old_secrets[old_secret.filename].add(old_secret)

        new_secrets = SecretsCollection()
        new_secret = potential_secret_factory(line_number=4)
        new_secrets[new_secret.filename].add(new_secret)

        new_secrets.merge(old_secrets)

        merged = next(iter(new_secrets[new_secret.filename]))
        assert merged.line_number == 4
        assert merged.is_secret is False
        assert merged.is_verified is True

    @staticmethod
    def test_merge_does_not_downgrade_verification():
        old_secrets = SecretsCollection()
        old_secret = potential_secret_factory(is_verified=False)
        old_secrets[old_secret.filename].add(old_secret)

        new_secrets = SecretsCollection()
        new_secret = potential_secret_factory(is_verified=True)
        new_secrets[new_secret.filename].add(new_secret)

        new_secrets.merge(old_secrets)

        merged = next(iter(new_secrets[new_secret.filename]))
        assert merged.is_verified is True


class TestTrim:
    @staticmethod
    def test_deleted_secret():
        secrets = SecretsCollection()
        secrets.scan_file('test_data/each_secret.py')

        results = SecretsCollection.load_from_baseline({'results': secrets.json()})
        results.data[str(Path('test_data/each_secret.py'))].pop()

        original_size = len(secrets[str(Path('test_data/each_secret.py'))])
        secrets.trim(results)

        assert len(secrets[str(Path('test_data/each_secret.py'))]) < original_size

    @staticmethod
    def test_deleted_secret_file():
        secrets = SecretsCollection()
        secrets.scan_file('test_data/each_secret.py')

        secrets.trim(SecretsCollection())
        assert secrets

        secrets.trim(SecretsCollection(), filelist=[str(Path('test_data/each_secret.py'))])
        assert not secrets

    @staticmethod
    def test_same_secret_new_location():
        old_secret = potential_secret_factory()
        new_secret = potential_secret_factory(line_number=2)

        secrets = SecretsCollection.load_from_baseline({'results': {'blah': [old_secret.json()]}})
        results = SecretsCollection.load_from_baseline({'results': {'blah': [new_secret.json()]}})

        secrets.trim(results)

        count = 0
        for filename, secret in secrets:
            assert secret.line_number == 2
            count += 1

        assert count == 1

    @staticmethod
    @pytest.mark.parametrize(
        'base_state, scanned_results',
        (
            (
                {
                    'blah': [potential_secret_factory().json()],
                },
                {},
            ),

            # Exact same secret, so no modifications necessary
            (
                {
                    'blah': [potential_secret_factory().json()],
                },
                {
                    'blah': [potential_secret_factory().json()],
                },
            ),
        ),
    )
    def test_no_modifications(base_state, scanned_results):
        secrets = SecretsCollection.load_from_baseline({'results': base_state})
        results = SecretsCollection.load_from_baseline({'results': scanned_results})

        secrets.trim(results)

        assert secrets.json() == base_state

    @staticmethod
    def test_remove_non_existent_files():
        secrets = SecretsCollection()
        secrets.scan_file('test_data/each_secret.py')
        assert bool(secrets)

        secrets.data['does-not-exist'] = secrets.data.pop(str(Path('test_data/each_secret.py')))
        secrets.trim()

        assert not bool(secrets)

    @staticmethod
    def test_maintains_labels():
        labelled_secrets = SecretsCollection()
        labelled_secrets.scan_file('test_data/each_secret.py')
        for _, secret in labelled_secrets:
            secret.is_secret = True
            break

        secrets = SecretsCollection()
        secrets.scan_file('test_data/each_secret.py')

        labelled_secrets.trim(scanned_results=secrets)

        assert any([secret.is_secret for _, secret in labelled_secrets])


def test_bool():
    secrets = SecretsCollection()
    assert not secrets

    secrets.scan_file('test_data/each_secret.py')
    assert secrets

    secrets[str(Path('test_data/each_secret.py'))].clear()
    assert not secrets


class TestEqual:
    @staticmethod
    def test_mismatch_files():
        secretsA = SecretsCollection()
        secretsA.scan_file('test_data/each_secret.py')

        secretsB = SecretsCollection()
        secretsB.scan_file('test_data/files/file_with_secrets.py')

        assert secretsA != secretsB

    @staticmethod
    def test_strict_equality():
        secret = potential_secret_factory()
        secretsA = SecretsCollection()
        secretsA[secret.filename].add(secret)

        secret = potential_secret_factory(line_number=2)
        secretsB = SecretsCollection()
        secretsB[secret.filename].add(secret)

        assert secretsA == secretsB
        assert not secretsA.exactly_equals(secretsB)


class TestSubtraction:
    @staticmethod
    def test_basic(configure_plugins):
        with transient_settings({**configure_plugins, 'filters_used': []}):
            secrets = SecretsCollection()
            secrets.scan_file('test_data/each_secret.py')

        # This baseline will have less secrets, since it filtered out some.
        with transient_settings({
            **configure_plugins,
            'filters_used': [
                {
                    'path': 'detect_secrets.filters.regex.should_exclude_line',
                    'pattern': [
                        'EXAMPLE',
                    ],
                },
            ],
        }):
            baseline = SecretsCollection()
            baseline.scan_file('test_data/each_secret.py')

        # This tests the != operator for same file, different number of secrets.
        # It's hidden in a different test, but I didn't want to set up the boilerplate
        # again.
        assert secrets != baseline

        result = secrets - baseline
        assert len(result[str(Path('test_data/each_secret.py'))]) == 3
        assert len(secrets[str(Path('test_data/each_secret.py'))]) == 5

    @staticmethod
    def test_no_overlapping_files(configure_plugins):
        secrets_a = SecretsCollection()
        secrets_b = SecretsCollection()
        with transient_settings({**configure_plugins, 'filters_used': []}):
            secrets_a.scan_file('test_data/each_secret.py')
            secrets_b.scan_file('test_data/config.env')

        assert (secrets_a - secrets_b).files == {str(Path('test_data/each_secret.py'))}
        assert (secrets_b - secrets_a).files == {str(Path('test_data/config.env'))}
