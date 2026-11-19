"""
This module provides configurable resource budgets for scans, so that scanning
hostile or pathological repositories (e.g. extremely long lines, a huge number
of files, or files with abnormal encodings that blow up in-memory usage) cannot
silently consume unbounded resources.

When a budget is exceeded, the scan is truncated in a controlled manner and the
event is recorded in a module-level tracker. Callers (e.g. baseline output) can
then surface a visible "incomplete" status, rather than returning results that
look like a clean scan.

Budgets are disabled by default (i.e. unlimited), preserving existing behavior.
They can be configured through:

    1. Environment variables (e.g. `DETECT_SECRETS_MAX_FILE_BYTES=1048576`),
    2. Command line flags (see `detect_secrets/core/usage/scan.py`), or
    3. Programmatically, through `configure_budget`.
"""
import os
from dataclasses import asdict
from dataclasses import dataclass
from typing import Any
from typing import Dict
from typing import List
from typing import Mapping
from typing import Optional
from typing import Set
from typing import Tuple

from .log import log


# The tracker itself must be bounded, otherwise recording budget violations for
# a pathological repository would become its own memory problem.
MAX_TRACKED_EVENTS = 100

_ENVIRONMENT_VARIABLES = {
    'DETECT_SECRETS_MAX_FILES': 'max_files',
    'DETECT_SECRETS_MAX_FILE_BYTES': 'max_file_bytes',
    'DETECT_SECRETS_MAX_LINES_PER_FILE': 'max_lines_per_file',
    'DETECT_SECRETS_MAX_LINE_LENGTH': 'max_line_length',
    'DETECT_SECRETS_MAX_SECRETS': 'max_secrets',
}


@dataclass
class ScanBudget:
    """
    Resource limits applied while scanning. A value of None means unbounded
    (the historical default behavior).
    """

    # Maximum number of files to scan.
    max_files: Optional[int] = None

    # Maximum size (in bytes) of an individual file. Larger files are skipped.
    max_file_bytes: Optional[int] = None

    # Maximum number of lines scanned per file. Remaining lines are ignored.
    max_lines_per_file: Optional[int] = None

    # Maximum line length (in characters). Longer lines are truncated.
    max_line_length: Optional[int] = None

    # Maximum number of secrets collected in a single scan.
    max_secrets: Optional[int] = None

    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> 'ScanBudget':
        if environ is None:
            environ = os.environ

        budget = cls()
        for env_var, attribute in _ENVIRONMENT_VARIABLES.items():
            raw_value = environ.get(env_var)
            if raw_value is None:
                continue

            try:
                value = int(raw_value)
                if value < 0:
                    raise ValueError
            except ValueError:
                log.warning(f'Ignoring invalid budget value: {env_var}={raw_value}')
                continue

            setattr(budget, attribute, value)

        return budget


@dataclass
class BudgetEvent:
    """A single occurrence of a budget being exceeded."""
    reason: str
    filename: Optional[str] = None
    detail: Optional[str] = None


class ScanBudgetTracker:
    """Collects budget violations during a scan, in a bounded fashion."""

    def __init__(self) -> None:
        self.events: List[BudgetEvent] = []
        self.events_truncated = False
        self._seen: Set[Tuple[str, Optional[str]]] = set()

    def record(
        self,
        reason: str,
        filename: Optional[str] = None,
        detail: Optional[str] = None,
        once: bool = False,
    ) -> None:
        """
        :param once: if True, only the first event with this reason is recorded
            (used for global budgets, e.g. max_files, where one event suffices).
        """
        key = (reason, None if once else filename)
        if key in self._seen:
            return
        self._seen.add(key)

        if len(self.events) >= MAX_TRACKED_EVENTS:
            self.events_truncated = True
            return

        self.events.append(BudgetEvent(reason=reason, filename=filename, detail=detail))

        location = f' ({filename})' if filename else ''
        log.warning(f'Scan budget exceeded: {reason}{location}. {detail or ""}'.strip())

    def merge(self, data: Dict[str, Any]) -> None:
        """Merges events reported by a child process into this tracker."""
        for event in data.get('events', []):
            self.record(
                reason=event['reason'],
                filename=event.get('filename'),
                detail=event.get('detail'),
            )

        if data.get('events_truncated'):
            self.events_truncated = True

    @property
    def is_complete(self) -> bool:
        return not self.events and not self.events_truncated

    def json(self) -> Dict[str, Any]:
        return {
            'is_complete': self.is_complete,
            'events': [asdict(event) for event in self.events],
            'events_truncated': self.events_truncated,
        }


_budget: Optional[ScanBudget] = None
_tracker: Optional[ScanBudgetTracker] = None


def get_budget() -> ScanBudget:
    """Returns the active budget, lazily initialized from the environment."""
    global _budget
    if _budget is None:
        _budget = ScanBudget.from_env()

    return _budget


def configure_budget(**kwargs: Optional[int]) -> ScanBudget:
    """
    Overrides individual budget limits (e.g. from command line flags).
    Values of None are ignored, so that they don't clobber limits configured
    through other means (e.g. environment variables).
    """
    budget = get_budget()
    for key, value in kwargs.items():
        if value is not None:
            setattr(budget, key, value)

    return budget


def set_budget(budget: ScanBudget) -> None:
    """Replaces the active budget wholesale (used for child processes)."""
    global _budget
    _budget = budget


def get_tracker() -> ScanBudgetTracker:
    global _tracker
    if _tracker is None:
        _tracker = ScanBudgetTracker()

    return _tracker


def reset_tracker() -> None:
    global _tracker
    _tracker = ScanBudgetTracker()


def reset_budget_state() -> None:
    """Restores the default (unlimited) budget and clears all recorded events."""
    global _budget
    _budget = None
    reset_tracker()
