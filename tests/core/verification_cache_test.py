import hashlib
import re

import pytest
import requests

from detect_secrets import settings
from detect_secrets.constants import VerifiedResult
from detect_secrets.core import verification_cache
from detect_secrets.core.verification_cache import verify_secret
from detect_secrets.filters.common import is_ignored_due_to_verification_policies
from detect_secrets.plugins.base import RegexBasedDetector
from detect_secrets.settings import get_settings


SECRET = 'fake-secret-123'


class FakeVerifierPlugin(RegexBasedDetector):
    """
    A fixed fake verifier: no network calls, and its verdict is fully determined by
    its initialization configuration (endpoint + revoked secrets).
    """
    secret_type = 'Fake Verifier Token'

    denylist = (
        re.compile(r'fake-secret-[0-9a-z]+'),
    )

    def __init__(self, endpoint='https://api.example.com/verify', revoked=()):
        self.endpoint = endpoint
        self.revoked = frozenset(revoked)
        self.verify_call_count = 0

    def json(self):
        return {
            'name': self.__class__.__name__,
            'endpoint': self.endpoint,
            'revoked': sorted(self.revoked),
        }

    def verify(self, secret):
        self.verify_call_count += 1
        if secret in self.revoked:
            return VerifiedResult.VERIFIED_FALSE

        return VerifiedResult.VERIFIED_TRUE


class FlakyVerifierPlugin(FakeVerifierPlugin):
    secret_type = 'Flaky Fake Verifier Token'

    def __init__(self, failures=1, **kwargs):
        super().__init__(**kwargs)
        self.failures = failures

    def verify(self, secret):
        self.verify_call_count += 1
        if self.failures:
            self.failures -= 1
            raise requests.exceptions.Timeout

        return VerifiedResult.VERIFIED_TRUE


def _scan_line(plugin, secret=SECRET):
    get_settings().filters[
        'detect_secrets.filters.common.is_ignored_due_to_verification_policies'
    ] = {'min_level': VerifiedResult.VERIFIED_TRUE.value}

    return list(
        plugin.analyze_line(
            filename='secrets.py',
            line=secret,
            line_number=1,
        ),
    )[0]


class TestCacheIdentity:
    @staticmethod
    def test_same_configuration_reuses_cached_result():
        plugin = FakeVerifierPlugin()

        assert verify_secret(plugin, SECRET) == VerifiedResult.VERIFIED_TRUE
        assert verify_secret(plugin, SECRET) == VerifiedResult.VERIFIED_TRUE
        assert plugin.verify_call_count == 1

    @staticmethod
    def test_same_configuration_on_different_instance_reuses_cached_result():
        first = FakeVerifierPlugin()
        second = FakeVerifierPlugin()

        verify_secret(first, SECRET)
        verify_secret(second, SECRET)

        assert first.verify_call_count == 1
        assert second.verify_call_count == 0

    @staticmethod
    def test_different_secrets_have_different_identities():
        plugin = FakeVerifierPlugin()

        verify_secret(plugin, 'fake-secret-aaa')
        verify_secret(plugin, 'fake-secret-bbb')

        assert plugin.verify_call_count == 2

    @staticmethod
    def test_endpoint_change_causes_cache_miss():
        old_endpoint = FakeVerifierPlugin(endpoint='https://old.example.com/verify')
        new_endpoint = FakeVerifierPlugin(endpoint='https://new.example.com/verify')

        verify_secret(old_endpoint, SECRET)
        verify_secret(new_endpoint, SECRET)

        assert old_endpoint.verify_call_count == 1
        assert new_endpoint.verify_call_count == 1

    @staticmethod
    def test_rule_change_causes_cache_miss():
        plugin = FakeVerifierPlugin()
        verify_secret(plugin, SECRET)

        original_denylist = FakeVerifierPlugin.denylist
        try:
            FakeVerifierPlugin.denylist = (
                re.compile(r'fake-secret-[0-9a-z]{3}'),
            )
            verify_secret(plugin, SECRET)
        finally:
            FakeVerifierPlugin.denylist = original_denylist

        assert plugin.verify_call_count == 2

    @staticmethod
    def test_plugin_settings_change_causes_cache_miss():
        plugin = FakeVerifierPlugin()
        verify_secret(plugin, SECRET)

        get_settings().plugins['FakeVerifierPlugin'] = {
            'endpoint': 'https://rotated.example.com/verify',
        }
        verify_secret(plugin, SECRET)

        assert plugin.verify_call_count == 2


class TestStatusSwitching:
    @staticmethod
    def test_revoked_secret_is_not_reported_as_verified():
        plugin = FakeVerifierPlugin()
        assert verify_secret(plugin, SECRET) == VerifiedResult.VERIFIED_TRUE

        # The secret is revoked server-side: the same scan under the new
        # configuration must not reuse the stale verified state.
        revoked = FakeVerifierPlugin(revoked={SECRET})
        assert verify_secret(revoked, SECRET) == VerifiedResult.VERIFIED_FALSE
        assert revoked.verify_call_count == 1

        # The old identity is untouched, and still reuses its own cached state.
        assert verify_secret(plugin, SECRET) == VerifiedResult.VERIFIED_TRUE
        assert plugin.verify_call_count == 1

    @staticmethod
    def test_analyze_line_reflects_status_switch():
        plugin = FakeVerifierPlugin()
        assert _scan_line(plugin).is_verified is True
        assert _scan_line(plugin).is_verified is True
        assert plugin.verify_call_count == 1

        revoked = FakeVerifierPlugin(revoked={SECRET})
        assert _scan_line(revoked).is_verified is False
        assert revoked.verify_call_count == 1


class TestFailureHandling:
    @staticmethod
    def test_failed_verification_does_not_pollute_cache():
        plugin = FlakyVerifierPlugin(failures=1)

        with pytest.raises(requests.exceptions.Timeout):
            verify_secret(plugin, SECRET)

        assert not verification_cache._cache

        assert verify_secret(plugin, SECRET) == VerifiedResult.VERIFIED_TRUE
        assert verify_secret(plugin, SECRET) == VerifiedResult.VERIFIED_TRUE
        assert plugin.verify_call_count == 2

    @staticmethod
    def test_cache_bust_clears_verification_cache():
        plugin = FakeVerifierPlugin()
        verify_secret(plugin, SECRET)
        assert verification_cache._cache

        settings.cache_bust()

        assert not verification_cache._cache


class TestSecretNotPersisted:
    @staticmethod
    def test_cache_only_stores_secret_fingerprints():
        plugin = FakeVerifierPlugin()
        verify_secret(plugin, SECRET)

        assert len(verification_cache._cache) == 1
        key = next(iter(verification_cache._cache))

        assert SECRET not in key
        assert hashlib.sha256(SECRET.encode('utf-8')).hexdigest() in key
        assert SECRET not in repr(verification_cache._cache)


class TestVerificationFilterIntegration:
    @staticmethod
    def test_filter_reuses_cached_results():
        get_settings().filters[
            'detect_secrets.filters.common.is_ignored_due_to_verification_policies'
        ] = {'min_level': VerifiedResult.VERIFIED_TRUE.value}

        plugin = FakeVerifierPlugin()

        assert is_ignored_due_to_verification_policies(SECRET, plugin, None) is False
        assert is_ignored_due_to_verification_policies(SECRET, plugin, None) is False
        assert plugin.verify_call_count == 1
