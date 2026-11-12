import json
from pathlib import Path

import pytest

from detect_secrets.core import baseline
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.settings import get_settings
from detect_secrets.settings import transient_settings
from testing.factories import potential_secret_factory


FILENAME = str(Path('test_data/files/file_with_duplicate_secrets.py'))
DUPLICATE_LINES = (4, 6)


@pytest.fixture
def configure_plugins():
    config = {
        'plugins_used': [
            {
                'name': 'Base64HighEntropyString',
                'limit': 4.5,
            },
        ],
        'filters_used': [],
    }
    with transient_settings(config):
        yield config


def _scan(filename=FILENAME):
    secrets = SecretsCollection()
    secrets.scan_file(filename)
    return secrets


def test_same_token_on_two_lines_reports_both_findings(configure_plugins):
    secrets = _scan()

    findings = secrets[FILENAME]
    assert len(findings) == 2
    assert sorted(secret.line_number for secret in findings) == list(DUPLICATE_LINES)
    assert len({secret.secret_hash for secret in findings}) == 1


def test_json_output_keeps_both_findings(configure_plugins):
    output = _scan().json()

    assert [item['line_number'] for item in output[FILENAME]] == list(DUPLICATE_LINES)
    assert len(output[FILENAME]) == 2


def test_scan_diff_keeps_both_added_occurrences(configure_plugins):
    from detect_secrets.core.scan import scan_diff

    diff = (
        'diff --git a/{name} b/{name}\n'
        '--- a/{name}\n'
        '+++ b/{name}\n'
        '@@ -1,3 +1,5 @@\n'
        "+a = 'c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5'\n"
        "+b = 'c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5'\n"
        " c = 'other'\n"
        " d = 'other2'\n"
        " e = 'other3'\n"
    ).format(name=FILENAME)

    findings = list(scan_diff(diff))
    assert sorted(secret.line_number for secret in findings) == [1, 2]
    assert len(findings) == 2


def test_parallel_scan_keeps_both_findings(configure_plugins):
    # scan_files fans the work out to worker processes; merging their results must not
    # collapse repeated tokens onto a single finding.
    secrets = SecretsCollection()
    secrets.scan_files(
        FILENAME,
        'test_data/files/file_with_no_secrets.py',
        num_processors=2,
    )

    assert sorted(secret.line_number for secret in secrets[FILENAME]) == list(DUPLICATE_LINES)


def test_merge_labels_do_not_bleed_between_occurrences(configure_plugins):
    old_secrets = _scan()
    labelled = next(
        secret for secret in old_secrets[FILENAME]
        if secret.line_number == DUPLICATE_LINES[0]
    )
    labelled.is_secret = False
    labelled.is_verified = True

    new_secrets = _scan()
    new_secrets.merge(old_secrets)

    by_line = {secret.line_number: secret for secret in new_secrets[FILENAME]}
    assert by_line[DUPLICATE_LINES[0]].is_secret is False
    assert by_line[DUPLICATE_LINES[0]].is_verified is True

    # The manual verdict and verification state belong to line 2 only.
    assert by_line[DUPLICATE_LINES[1]].is_secret is None
    assert by_line[DUPLICATE_LINES[1]].is_verified is False


def test_merge_follows_secret_across_inserted_line(configure_plugins):
    single_line_file = 'test_data/files/file_with_secrets.py'
    old_secrets = SecretsCollection()
    old_secrets.scan_file(single_line_file)
    labelled = next(iter(old_secrets[single_line_file]))
    labelled.is_secret = True
    labelled.is_verified = True
    old_line = labelled.line_number

    # Simulate a line being inserted above the secret: the rescanned finding moves down.
    new_secrets = SecretsCollection()
    for secret in old_secrets[single_line_file]:
        secret.line_number += 1
        new_secrets[single_line_file].add(secret)

    new_secrets.merge(old_secrets)

    migrated = next(
        secret for secret in new_secrets[single_line_file]
        if secret.line_number == old_line + 1
    )
    assert migrated.is_secret is True
    assert migrated.is_verified is True


def test_repeated_tokens_drift_together_with_labels(configure_plugins):
    old_secrets = SecretsCollection()
    first = potential_secret_factory(line_number=DUPLICATE_LINES[0])
    second = potential_secret_factory(line_number=DUPLICATE_LINES[1])
    first.is_secret = False
    second.is_secret = True
    old_secrets[FILENAME] = {first, second}

    new_secrets = SecretsCollection()
    new_secrets[FILENAME] = {
        potential_secret_factory(line_number=DUPLICATE_LINES[0] + 1),
        potential_secret_factory(line_number=DUPLICATE_LINES[1] + 1),
    }

    new_secrets.merge(old_secrets)

    by_line = {secret.line_number: secret for secret in new_secrets[FILENAME]}
    assert by_line[DUPLICATE_LINES[0] + 1].is_secret is False
    assert by_line[DUPLICATE_LINES[1] + 1].is_secret is True


def test_merge_slim_baseline_does_not_guess_with_duplicates(configure_plugins):
    # Slim baselines store no line numbers. With two occurrences present, there is no
    # unambiguous target, so neither rescanned finding may inherit the label.
    old_secrets = _scan()
    for secret in old_secrets[FILENAME]:
        secret.line_number = 0
    labelled = next(iter(old_secrets[FILENAME]))
    labelled.is_secret = False

    new_secrets = _scan()
    new_secrets.merge(old_secrets)

    assert all(secret.is_secret is None for secret in new_secrets[FILENAME])


def test_merge_slim_baseline_follows_single_occurrence(configure_plugins):
    single_line_file = 'test_data/files/file_with_secrets.py'
    old_secrets = SecretsCollection()
    old_secrets.scan_file(single_line_file)
    for secret in old_secrets[single_line_file]:
        secret.line_number = 0
        secret.is_secret = True

    new_secrets = SecretsCollection()
    new_secrets.scan_file(single_line_file)
    new_secrets.merge(old_secrets)

    assert all(secret.is_secret is True for secret in new_secrets[single_line_file])


def test_full_baseline_round_trip_preserves_duplicate_entries(configure_plugins):
    secrets = _scan()
    formatted = baseline.format_for_output(secrets)

    reloaded = baseline.load(json.loads(json.dumps(formatted)))
    assert len(reloaded[FILENAME]) == 2
    assert secrets.exactly_equals(reloaded)


def test_slim_baseline_round_trip_stays_slim(configure_plugins):
    secrets = _scan()
    formatted = baseline.format_for_output(secrets, is_slim_mode=True)

    assert all(
        'line_number' not in item
        for item in formatted['results'][FILENAME]
    )
    assert len(formatted['results'][FILENAME]) == 2


def test_legacy_baseline_without_line_numbers_still_loads(configure_plugins):
    scanned = _scan()
    legacy_data = baseline.format_for_output(scanned, is_slim_mode=True)
    # Old baselines collapsed repeated tokens into one entry; make sure the modern
    # loader still accepts that shape without error.
    legacy_data['results'][FILENAME] = legacy_data['results'][FILENAME][:1]
    legacy_data['version'] = '0.14.2'
    for plugin in legacy_data['plugins_used']:
        if plugin['name'] == 'Base64HighEntropyString':
            plugin['base64_limit'] = plugin.pop('limit')

    reloaded = baseline.load(json.loads(json.dumps(legacy_data)))
    assert len(reloaded[FILENAME]) == 1


def test_allowlist_does_not_silence_other_occurrence(configure_plugins):
    # The default filter set includes the allowlist filter.
    get_settings().configure_filters([
        {'path': 'detect_secrets.filters.allowlist.is_line_allowlisted'},
    ])

    lines = Path(FILENAME).read_text().splitlines(keepends=True)
    allowlisted_line = lines[DUPLICATE_LINES[0] - 1].rstrip()
    lines[DUPLICATE_LINES[0] - 1] = f'{allowlisted_line}  # pragma: allowlist secret\n'

    import tempfile
    with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as f:
        f.writelines(lines)
        allowlisted_file = f.name

    try:
        secrets = SecretsCollection()
        secrets.scan_file(allowlisted_file)

        assert secrets.files == {allowlisted_file}
        findings = secrets[allowlisted_file]
        assert sorted(secret.line_number for secret in findings) == [DUPLICATE_LINES[1]]
    finally:
        Path(allowlisted_file).unlink()
