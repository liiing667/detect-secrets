from typing import Any
from typing import Optional

from .log import log
from .potential_secret import PotentialSecret


def is_secret_bound_to_line(
    secret: Any,
    expected_filename: str,
    expected_line_number: int,
    expected_line: str,
) -> bool:
    """
    A plugin's finding is only trustworthy when three independent pieces of evidence agree:

    1. the plugin output (the ``PotentialSecret`` it returned),
    2. the raw content of the line that was actually scanned, and
    3. the hash recorded on the finding.

    This guards against plugins (including custom ones) that attach a detected value to a
    line that never contained it: whether the mismatch comes from a cross-line bug or a
    deliberately forged result, it fails closed -- the finding is dropped rather than
    pointing auditors at the wrong line.

    :returns: True only when the finding can be proven to belong to ``expected_line``.
    """
    if not isinstance(secret, PotentialSecret):
        log.warning(
            f'Discarding plugin output of unexpected type '
            f'`{type(secret).__name__}` (expected PotentialSecret).',
        )
        return False

    if secret.filename != expected_filename:
        log.warning(
            f'Discarding finding for `{expected_filename}`: plugin reported filename '
            f'`{secret.filename}` instead of `{expected_filename}`.',
        )
        return False

    if secret.line_number != expected_line_number:
        log.warning(
            f'Discarding finding for `{expected_filename}:{expected_line_number}`: '
            f'plugin reported line number `{secret.line_number}`.',
        )
        return False

    # Without the raw value we cannot prove the finding belongs to this line. Fail closed:
    # an unprovable finding must never be presented as if it were anchored to this line.
    secret_value: Optional[str] = secret.secret_value
    if secret_value is None:
        log.warning(
            f'Discarding finding for `{expected_filename}:{expected_line_number}`: '
            f'secret value is unavailable for line binding.',
        )
        return False

    if PotentialSecret.hash_secret(secret_value) != secret.secret_hash:
        log.warning(
            f'Discarding finding for `{expected_filename}:{expected_line_number}`: '
            f'recorded hash does not match reported value.',
        )
        return False

    if secret_value not in expected_line:
        log.warning(
            f'Discarding finding for `{expected_filename}:{expected_line_number}`: '
            f'reported value is not present on the scanned line.',
        )
        return False

    return True
