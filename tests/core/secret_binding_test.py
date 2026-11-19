from typing import Any
from typing import Generator
from typing import Set

import pytest

from detect_secrets.core import scan
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.secret_binding import is_secret_bound_to_line
from detect_secrets.plugins.base import BasePlugin
from detect_secrets.settings import transient_settings
from testing.factories import potential_secret_factory
from testing.plugins import register_plugin


FILENAME = 'test_data/files/line_binding_fixture.py'
SECRET_VALUE = 'sk_live_ReTllpYQYfIZu2Jnf2lAPFjD'
LEGITIMATE_LINE_NUMBER = 7
FORGED_LINE_NUMBER = 11


class TestIsSecretBoundToLine:
    def test_accepts_legitimate_binding(self):
        secret = potential_secret_factory(
            type='Stripe Access Key',
            filename='mock_filename',
            secret=SECRET_VALUE,
            line_number=1,
        )

        assert is_secret_bound_to_line(
            secret=secret,
            expected_filename='mock_filename',
            expected_line_number=1,
            expected_line=f'key = "{SECRET_VALUE}"',
        )

    def test_rejects_value_not_present_on_line(self):
        # The exact cross-line bug: the finding carries a real hash, but the scanned line
        # never contained the value.
        secret = potential_secret_factory(
            type='Stripe Access Key',
            filename='mock_filename',
            secret=SECRET_VALUE,
            line_number=2,
        )

        assert not is_secret_bound_to_line(
            secret=secret,
            expected_filename='mock_filename',
            expected_line_number=2,
            expected_line='print("hello world")',
        )

    def test_rejects_wrong_line_number(self):
        secret = potential_secret_factory(
            type='Stripe Access Key',
            filename='mock_filename',
            secret=SECRET_VALUE,
            line_number=2,
        )

        assert not is_secret_bound_to_line(
            secret=secret,
            expected_filename='mock_filename',
            expected_line_number=3,
            expected_line=f'key = "{SECRET_VALUE}"',
        )

    def test_rejects_wrong_filename(self):
        secret = potential_secret_factory(
            type='Stripe Access Key',
            filename='other_file.py',
            secret=SECRET_VALUE,
            line_number=1,
        )

        assert not is_secret_bound_to_line(
            secret=secret,
            expected_filename='mock_filename',
            expected_line_number=1,
            expected_line=f'key = "{SECRET_VALUE}"',
        )

    def test_rejects_forged_hash(self):
        secret = potential_secret_factory(
            type='Stripe Access Key',
            filename='mock_filename',
            secret=SECRET_VALUE,
            line_number=1,
        )
        secret.secret_hash = PotentialSecret.hash_secret('a-different-value')

        assert not is_secret_bound_to_line(
            secret=secret,
            expected_filename='mock_filename',
            expected_line_number=1,
            expected_line=f'key = "{SECRET_VALUE}"',
        )

    def test_rejects_when_secret_value_unavailable(self):
        secret = potential_secret_factory(
            type='Stripe Access Key',
            filename='mock_filename',
            secret=SECRET_VALUE,
            line_number=1,
        )
        secret.secret_value = None

        # Fail closed: an unprovable finding cannot be anchored to the line.
        assert not is_secret_bound_to_line(
            secret=secret,
            expected_filename='mock_filename',
            expected_line_number=1,
            expected_line=f'key = "{SECRET_VALUE}"',
        )

    def test_rejects_non_potential_secret_output(self):
        assert not is_secret_bound_to_line(
            secret='not a finding',  # type: ignore[arg-type]
            expected_filename='mock_filename',
            expected_line_number=1,
            expected_line=SECRET_VALUE,
        )


class ForgedLinePlugin(BasePlugin):
    """Simulates a buggy/forged plugin that overrides `analyze_line` directly (bypassing the
    base-class construction) and attaches a finding to a different line that does not contain
    the value. Only the scan-pipeline binding check can catch this one."""

    secret_type = 'Forged Line'

    def analyze_string(self, string: str) -> Generator[str, None, None]:
        if string == SECRET_VALUE:
            yield string

    def analyze_line(
        self,
        filename: str,
        line: str,
        line_number: int = 0,
        context: Any = None,
        **kwargs: Any,
    ) -> Set[PotentialSecret]:
        if SECRET_VALUE not in line:
            return set()

        return {
            PotentialSecret(
                type=self.secret_type,
                filename=filename,
                secret=SECRET_VALUE,
                # The forged location points at an unrelated line.
                line_number=FORGED_LINE_NUMBER,
            ),
        }


class MisdirectedValuePlugin(BasePlugin):
    """Goes through `BasePlugin.analyze_line`'s construction, but `analyze_string` yields a
    value that the scanned line does not contain (e.g. a cross-line state bug). The base-class
    binding check must reject it."""

    secret_type = 'Misdirected Value'

    def analyze_string(self, string: str) -> Generator[str, None, None]:
        yield SECRET_VALUE


class AlternateStripeDetector(BasePlugin):
    """A second, legitimate plugin that detects the same value on the same line, so we can
    prove valid multi-plugin hits are retained."""

    secret_type = 'Alternate Stripe'

    def analyze_string(self, string: str) -> Generator[str, None, None]:
        if SECRET_VALUE in string:
            yield SECRET_VALUE


class TestScanLineBinding:
    def test_base_plugin_discards_value_not_on_scanned_line(self):
        # A plugin going through `BasePlugin.analyze_line` cannot attach a value to a line
        # that does not contain it: the base-class binding check drops it before output.
        plugin = MisdirectedValuePlugin()

        output = plugin.analyze_line(
            filename=FILENAME,
            line='print("hello world")',
            line_number=FORGED_LINE_NUMBER,
        )

        assert output == set()

    def test_scan_pipeline_discards_forged_plugin_output(self):
        with transient_settings({'plugins_used': [{'name': 'ForgedLinePlugin'}]}):
            with register_plugin(ForgedLinePlugin()):
                results = list(scan.scan_file(FILENAME))

        assert results == []

    def test_scan_pipeline_discards_forged_line_number(self):
        class ForgedLineNumberPlugin(ForgedLinePlugin):
            secret_type = 'Forged Line Number'

            def analyze_line(
                self,
                filename: str,
                line: str,
                line_number: int = 0,
                context: Any = None,
                **kwargs: Any,
            ) -> Set[PotentialSecret]:
                if SECRET_VALUE not in line:
                    return set()

                return {
                    PotentialSecret(
                        type=self.secret_type,
                        filename=filename,
                        secret=SECRET_VALUE,
                        # The value exists on this line, but the reported line number points
                        # at an unrelated line elsewhere in the file.
                        line_number=FORGED_LINE_NUMBER,
                    ),
                }

        with transient_settings({'plugins_used': [{'name': 'ForgedLineNumberPlugin'}]}):
            with register_plugin(ForgedLineNumberPlugin()):
                results = list(scan.scan_file(FILENAME))

        assert results == []

    def test_fixture_rejects_wrong_location_but_keeps_legitimate_line(self):
        with transient_settings({'plugins_used': [{'name': 'StripeDetector'}]}):
            results = list(scan.scan_file(FILENAME))

        assert len(results) == 1
        secret = results[0]
        assert secret.secret_value == SECRET_VALUE
        assert secret.line_number == LEGITIMATE_LINE_NUMBER
        assert all(
            finding.line_number != FORGED_LINE_NUMBER
            for finding in results
        )

    def test_legitimate_multi_plugin_hits_are_retained(self):
        with transient_settings(
            {
                'plugins_used': [
                    {'name': 'StripeDetector'},
                    {'name': 'AlternateStripeDetector'},
                ],
            },
        ):
            with register_plugin(AlternateStripeDetector()):
                results = list(scan.scan_file(FILENAME))

        assert len(results) == 2
        assert {
            secret.type
            for secret in results
        } == {'Stripe Access Key', 'Alternate Stripe'}
        assert all(
            secret.line_number == LEGITIMATE_LINE_NUMBER
            and secret.secret_value == SECRET_VALUE
            for secret in results
        )


@pytest.fixture(autouse=True)
def verify_line_numbers():
    # Guard against the fixture drifting: these line numbers are the whole point of the test.
    with open(FILENAME) as f:
        lines = f.readlines()

    assert SECRET_VALUE in lines[LEGITIMATE_LINE_NUMBER - 1]
    assert SECRET_VALUE not in lines[FORGED_LINE_NUMBER - 1]
    yield
