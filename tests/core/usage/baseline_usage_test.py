import json
from contextlib import contextmanager

import pytest

from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.settings import get_settings
from testing.mocks import mock_named_temporary_file


@pytest.fixture
def parser():
    return ParserBuilder().add_pre_commit_arguments()


def test_baseline_optional(parser):
    parser.parse_args([])

    assert len(get_settings().plugins) == len(get_mapping_from_secret_type_to_class())


def test_no_such_file(parser):
    with pytest.raises(SystemExit):
        parser.parse_args(['--baseline', 'random-file-name'])


def test_non_valid_json(parser):
    with _mock_file('not JSON') as filename, pytest.raises(SystemExit):
        parser.parse_args(['--baseline', filename])


def test_invalid_baseline(parser):
    with _mock_file(json.dumps({'a': 2})) as filename, pytest.raises(SystemExit):
        parser.parse_args(['--baseline', filename])


@pytest.mark.parametrize(
        'contents',
        (
            {'version': 'not-a-valid-version', 'plugins_used': [], 'results': {}},
            {
                'version': '0.14.2',
                'plugins_used': [],
                'results': {
                    'config.env': [
                        {'is_verified': False, 'type': 'Some Type'},
                    ],
                },
            },
        ),
)
def test_unupgradeable_baseline_fails_closed(parser, contents):
    with _mock_file(json.dumps(contents)) as filename, pytest.raises(SystemExit):
        parser.parse_args(['--baseline', filename])


def test_success(parser):
    baseline = {
        'version': '0.0.1',
        'plugins_used': [
            {
                'name': 'AWSKeyDetector',
            },
            {
                'base64_limit': 3,
                'name': 'Base64HighEntropyString',
            },
        ],
        'results': [],
    }

    with _mock_file(json.dumps(baseline)) as filename:
        parser.parse_args(['--baseline', filename])

    assert len(get_settings().plugins) == 2
    assert 'AWSKeyDetector' in get_settings().plugins
    assert get_settings().plugins['Base64HighEntropyString'] == {'limit': 3}


@contextmanager
def _mock_file(content: str):
    with mock_named_temporary_file() as f:
        f.write(content.encode())
        f.seek(0)

        yield f.name
