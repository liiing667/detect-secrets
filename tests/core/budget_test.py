import json

import pytest

from detect_secrets import main as main_module
from detect_secrets.core import baseline
from detect_secrets.core import budget
from detect_secrets.core import scan
from detect_secrets.core.budget import MAX_TRACKED_EVENTS
from detect_secrets.core.budget import ScanBudget
from detect_secrets.core.budget import ScanBudgetTracker
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.main import parse_args
from detect_secrets.settings import transient_settings
from testing.mocks import mock_printer


@pytest.fixture(autouse=True)
def configure_plugins():
    with transient_settings({
        'plugins_used': [
            {'name': 'Base64HighEntropyString'},
        ],
    }):
        yield


@pytest.fixture
def tracker():
    return budget.get_tracker()


class TestScanBudgetConfiguration:
    @staticmethod
    def test_defaults_to_unlimited():
        assert budget.get_budget() == ScanBudget()

    @staticmethod
    def test_configure_budget_ignores_none_values():
        budget.configure_budget(max_files=5, max_file_bytes=None)

        assert budget.get_budget().max_files == 5
        assert budget.get_budget().max_file_bytes is None

    @staticmethod
    def test_environment_variable_configuration(monkeypatch):
        monkeypatch.setenv('DETECT_SECRETS_MAX_FILE_BYTES', '1024')
        monkeypatch.setenv('DETECT_SECRETS_MAX_SECRETS', '3')
        budget.reset_budget_state()

        assert budget.get_budget().max_file_bytes == 1024
        assert budget.get_budget().max_secrets == 3
        assert budget.get_budget().max_files is None

    @staticmethod
    def test_invalid_environment_variables_are_ignored():
        parsed = ScanBudget.from_env({
            'DETECT_SECRETS_MAX_FILES': 'not-a-number',
            'DETECT_SECRETS_MAX_SECRETS': '-1',
        })

        assert parsed == ScanBudget()

    @staticmethod
    def test_command_line_flags_configure_budget():
        parse_args(['scan', '--max-files', '5', '--max-line-length', '80'])

        assert budget.get_budget().max_files == 5
        assert budget.get_budget().max_line_length == 80
        assert budget.get_budget().max_file_bytes is None


class TestFileSizeBudget:
    @staticmethod
    def test_skips_oversized_files(tracker):
        budget.configure_budget(max_file_bytes=256)

        assert not list(scan.scan_file('test_data/budget/large_file.txt'))
        assert not tracker.is_complete
        assert tracker.events[0].reason == 'file_size_exceeded'
        assert tracker.events[0].filename == 'test_data/budget/large_file.txt'

    @staticmethod
    def test_scans_files_within_budget(tracker):
        budget.configure_budget(max_file_bytes=256)

        assert len(list(scan.scan_file('test_data/budget/many_files/secret_1.txt'))) == 1
        assert tracker.is_complete


class TestLineBudgets:
    @staticmethod
    def test_long_lines_are_truncated(tracker):
        budget.configure_budget(max_line_length=100)

        secrets = list(scan.scan_file('test_data/budget/long_line.txt'))

        # The secret on the second line lives past the 100 character budget,
        # so only the first secret is found.
        assert [secret.line_number for secret in secrets] == [1]
        assert [event.reason for event in tracker.events] == ['line_length_exceeded']

    @staticmethod
    def test_excess_lines_are_ignored(tracker):
        budget.configure_budget(max_lines_per_file=5)

        secrets = list(scan.scan_file('test_data/budget/many_lines.txt'))

        # The secret on line 10 is beyond the line budget.
        assert [secret.line_number for secret in secrets] == [1]
        assert [event.reason for event in tracker.events] == ['line_count_exceeded']


class TestFileCountBudget:
    @staticmethod
    def test_limits_number_of_scanned_files(tracker):
        budget.configure_budget(max_files=2)

        filenames = list(scan.get_files_to_scan(
            'test_data/budget/many_files',
            should_scan_all_files=True,
        ))

        assert len(filenames) == 2
        assert [event.reason for event in tracker.events] == ['file_count_exceeded']

    @staticmethod
    def test_unaffected_when_under_budget(tracker):
        budget.configure_budget(max_files=10)

        filenames = list(scan.get_files_to_scan(
            'test_data/budget/many_files',
            should_scan_all_files=True,
        ))

        assert len(filenames) == 3
        assert tracker.is_complete


class TestSecretCountBudget:
    @staticmethod
    def test_collection_is_capped(tracker):
        budget.configure_budget(max_secrets=2)

        secrets = SecretsCollection()
        secrets.scan_file('test_data/budget/many_secrets.txt')

        assert len(secrets) == 2
        assert [event.reason for event in tracker.events] == ['secret_count_exceeded']

    @staticmethod
    def test_collection_under_budget_is_complete(tracker):
        budget.configure_budget(max_secrets=10)

        secrets = SecretsCollection()
        secrets.scan_file('test_data/budget/many_secrets.txt')

        assert len(secrets) == 3
        assert tracker.is_complete


class TestMultiprocessingBudgets:
    @staticmethod
    def test_child_process_events_are_propagated(tracker):
        budget.configure_budget(max_file_bytes=256)

        secrets = SecretsCollection()
        secrets.scan_files(
            'test_data/budget/large_file.txt',
            'test_data/budget/many_secrets.txt',
            num_processors=2,
        )

        # The oversized file is skipped in the child process, but the parent
        # still learns about it.
        assert len(secrets) == 3
        assert [event.reason for event in tracker.events] == ['file_size_exceeded']


class TestIncompleteStatusOutput:
    @staticmethod
    def test_scan_status_is_absent_when_scan_is_complete():
        secrets = SecretsCollection()
        secrets.scan_file('test_data/budget/many_secrets.txt')

        output = baseline.format_for_output(secrets)

        assert 'scan_status' not in output

    @staticmethod
    def test_scan_status_is_present_when_budget_is_exceeded():
        budget.configure_budget(max_file_bytes=256)

        secrets = SecretsCollection()
        secrets.scan_file('test_data/budget/large_file.txt')

        output = baseline.format_for_output(secrets)

        assert output['scan_status']['is_complete'] is False
        assert output['scan_status']['events'][0]['reason'] == 'file_size_exceeded'

    @staticmethod
    def test_cli_output_flags_incomplete_scan():
        with mock_printer(main_module) as printer:
            main_module.main([
                'scan',
                '--all-files',
                '--max-file-bytes',
                '256',
                'test_data/budget',
            ])

        output = json.loads(printer.message)
        assert output['scan_status']['is_complete'] is False
        assert any(
            event['reason'] == 'file_size_exceeded'
            for event in output['scan_status']['events']
        )

    @staticmethod
    def test_cli_output_is_unchanged_for_normal_scans():
        with mock_printer(main_module) as printer:
            main_module.main(['scan', '--all-files', 'test_data/budget/many_files'])

        output = json.loads(printer.message)
        assert 'scan_status' not in output
        assert len(output['results']) == 3


class TestScanBudgetTracker:
    @staticmethod
    def test_events_are_bounded():
        tracker = ScanBudgetTracker()
        for index in range(MAX_TRACKED_EVENTS + 50):
            tracker.record('file_size_exceeded', filename=f'file_{index}')

        assert len(tracker.events) == MAX_TRACKED_EVENTS
        assert tracker.events_truncated
        assert not tracker.is_complete

    @staticmethod
    def test_record_once_only_keeps_first_event():
        tracker = ScanBudgetTracker()
        tracker.record('secret_count_exceeded', once=True)
        tracker.record('secret_count_exceeded', once=True)

        assert len(tracker.events) == 1

    @staticmethod
    def test_merge_combines_child_process_events():
        child = ScanBudgetTracker()
        child.record('file_size_exceeded', filename='large_file.txt')

        parent = ScanBudgetTracker()
        parent.merge(child.json())

        assert not parent.is_complete
        assert parent.events[0].reason == 'file_size_exceeded'
        assert parent.events[0].filename == 'large_file.txt'
