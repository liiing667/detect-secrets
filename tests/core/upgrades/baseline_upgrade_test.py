import copy
import json
import os

import pytest

from detect_secrets.core import baseline
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.exceptions import InvalidBaselineError


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')


def _load_fixture(name):
    with open(os.path.join(FIXTURES_DIR, name)) as f:
        return json.load(f)


def test_source_fixture_upgrades_while_preserving_every_secret_record():
    source = _load_fixture('source_baseline.json')
    original_source = copy.deepcopy(source)

    upgraded = baseline.upgrade(source)

    with open(os.path.join(FIXTURES_DIR, 'upgraded_baseline.json')) as f:
        expected_upgrade = json.load(f)

    assert upgraded == expected_upgrade

    # The old-format baseline must remain untouched, so both formats stay reviewable.
    assert source == original_source

    # Fingerprint, type, location and human classification survive the migration.
    assert upgraded['results'] == source['results']
    assert upgraded['version'] == baseline.VERSION


@pytest.mark.parametrize(
        'fixture_name',
        (
            'source_baseline.json',
            'upgraded_baseline.json',
        ),
)
def test_old_and_upgraded_formats_are_both_loadable(fixture_name):
    data = _load_fixture(fixture_name)

    secrets = baseline.load(data)

    assert isinstance(secrets, SecretsCollection)
    assert sorted(secrets.files) == ['config.env', 'config.ini']
    assert len(secrets['config.env']) == 1
    assert len(secrets['config.ini']) == 2


def test_manual_classification_and_verification_are_preserved():
    upgraded = baseline.upgrade(_load_fixture('source_baseline.json'))
    secrets = baseline.load(upgraded)

    by_key = {
        (secret.secret_hash, secret.type): secret
        for secret in secrets['config.ini']
    }

    labelled = by_key[
        ('b5198bd9fe6726cf064a5b80b6dfe25ab793147f', 'Hex High Entropy String')
    ]
    unlabelled = by_key[
        ('b1c6a9a65d292f95c2bb3bc1918eed10f4dabb16', 'Secret Keyword')
    ]

    assert labelled.is_secret is True
    assert labelled.is_verified is True
    assert labelled.line_number == 2
    assert unlabelled.is_secret is None
    assert unlabelled.is_verified is False
    assert unlabelled.line_number == 10


@pytest.mark.parametrize(
        'fixture_name',
        (
            'rejected_invalid_version.json',
            'rejected_missing_fields.json',
        ),
)
def test_rejection_fixtures_fail_closed(fixture_name):
    source = _load_fixture(fixture_name)

    with pytest.raises(InvalidBaselineError):
        baseline.upgrade(source)

    # A rejected upgrade must not mutate the input.
    assert source == _load_fixture(fixture_name)


def test_compatible_fixture_is_passed_through_unchanged():
    compatible = _load_fixture('compatible_baseline.json')

    assert baseline.upgrade(compatible) == compatible


@pytest.mark.parametrize(
        'data',
        (
            {'plugins_used': [], 'results': {}},
            {'version': 'not-a-version', 'plugins_used': [], 'results': {}},
            {'version': 1, 'plugins_used': [], 'results': {}},
        ),
)
def test_missing_or_unparseable_version_fails_closed(data):
    with pytest.raises(InvalidBaselineError):
        baseline.upgrade(copy.deepcopy(data))


@pytest.mark.parametrize(
        'results',
        (
            ['unexpected-list'],
            {'': []},
            {'config.env': {}},
            {'config.env': ['not-a-secret-record']},
            {'config.env': [{'hashed_secret': 'abc'}]},
            {'config.env': [{'type': 'Some Type'}]},
            {'config.env': [{'type': 'Some Type', 'hashed_secret': ''}]},
            {
                'config.env': [
                    {
                        'type': 'Some Type',
                        'hashed_secret': 'abc',
                        'line_number': '1',
                    },
                ],
            },
        ),
)
def test_malformed_results_fail_closed(results):
    with pytest.raises(InvalidBaselineError):
        baseline.upgrade(
            {
                'version': '0.14.2',
                'plugins_used': [],
                'results': results,
            },
        )


def test_upgrade_fails_closed_if_results_drift_during_migration():
    source = _load_fixture('source_baseline.json')

    with pytest.MonkeyPatch.context() as monkeypatch:
        def tamper(baseline):
            baseline['results']['config.env'][0]['hashed_secret'] = 'tampered'

        monkeypatch.setattr(
            'detect_secrets.core.upgrades.v1_1.upgrade',
            tamper,
        )

        with pytest.raises(InvalidBaselineError):
            baseline.upgrade(source)

    # A failed upgrade must leave the original baseline untouched.
    assert source == _load_fixture('source_baseline.json')


def test_empty_list_results_from_legacy_baseline_are_accepted():
    upgraded = baseline.upgrade(
        {
            'version': '0.0.1',
            'plugins_used': [],
            'results': [],
        },
    )

    assert upgraded['results'] == []
