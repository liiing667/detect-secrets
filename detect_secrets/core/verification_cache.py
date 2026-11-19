"""
Caches the results of secret verification, so that repeated scans (and the multiple
verification call sites within a single scan) don't repeatedly perform the same
verification work.

The cache identity is derived from three components:

    1. the plugin's rules and configuration (e.g. denylist patterns, verifier
       endpoints, initialization variables),
    2. the plugin's currently configured settings, and
    3. a fingerprint of the secret itself.

As such, if any of these components change (e.g. a plugin's rules are updated, or a
verification endpoint is rotated), previously cached results will not be reused.
This prevents stale state (e.g. a since-revoked secret) from being reported as
verified.

This cache is process-local, and only ever stores fingerprints of secrets -- never
the secrets themselves.
"""
import hashlib
import json
import types
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import TYPE_CHECKING

from ..constants import VerifiedResult
from ..settings import get_settings
from ..util.inject import call_function_with_arguments

if TYPE_CHECKING:       # pragma: no cover
    from ..plugins.base import BasePlugin
    from ..util.code_snippet import CodeSnippet


_cache: Dict[str, VerifiedResult] = {}


def verify_secret(
    plugin: 'BasePlugin',
    secret: str,
    context: Optional['CodeSnippet'] = None,
) -> VerifiedResult:
    """
    Verifies a secret with the given plugin, reusing previously successful results
    whenever the plugin's rules, configuration and the secret itself are unchanged.

    Verification failures (e.g. network errors) are propagated to the caller, and
    are intentionally never cached, so that transient failures don't pollute the
    cache and are retried on subsequent attempts.
    """
    key = _get_cache_key(plugin, secret)
    if key in _cache:
        return _cache[key]

    result = call_function_with_arguments(
        plugin.verify,
        secret=secret,
        context=context,
    )
    _cache[key] = result
    return result


def clear_verification_cache() -> None:
    _cache.clear()


def _get_cache_key(plugin: 'BasePlugin', secret: str) -> str:
    secret_fingerprint = hashlib.sha256(secret.encode('utf-8')).hexdigest()
    return f'{_get_plugin_identity(plugin)}:{secret_fingerprint}'


def _get_plugin_identity(plugin: 'BasePlugin') -> str:
    payload = {
        'plugin': plugin.__class__.__name__,
        'config': _safely_serialize_plugin(plugin),
        'rules': _get_rules_fingerprint(plugin),
        'verifier': _get_verifier_fingerprint(plugin),
        'settings': get_settings().plugins.get(plugin.__class__.__name__, {}),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=repr).encode('utf-8'),
    ).hexdigest()


def _safely_serialize_plugin(plugin: 'BasePlugin') -> Dict[str, Any]:
    try:
        return plugin.json()
    except Exception:
        return {}


def _get_rules_fingerprint(plugin: 'BasePlugin') -> List[str]:
    return sorted(
        f'{pattern.pattern}::{pattern.flags}'
        for pattern in getattr(plugin, 'denylist', None) or ()
    )


def _get_verifier_fingerprint(plugin: 'BasePlugin') -> str:
    code = getattr(getattr(plugin, 'verify', None), '__code__', None)
    if code is None:
        # Non-Python verifiers (e.g. mocks) can't be fingerprinted reliably, so we
        # conservatively fall back to their representation, which avoids incorrectly
        # reusing results across different verifier implementations.
        return repr(plugin.verify)

    hasher = hashlib.sha256()
    _hash_code_object(code, hasher)
    return hasher.hexdigest()


def _hash_code_object(code: types.CodeType, hasher: Any) -> None:
    hasher.update(code.co_code)
    hasher.update(repr(code.co_names).encode('utf-8'))
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            _hash_code_object(const, hasher)
        else:
            # String constants capture hardcoded values such as verification endpoints.
            hasher.update(repr(const).encode('utf-8'))
