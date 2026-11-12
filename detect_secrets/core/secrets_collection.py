import multiprocessing as mp
import os
from collections import defaultdict
from typing import Any
from typing import Dict
from typing import Generator
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

from . import scan
from ..util.path import convert_local_os_path
from .potential_secret import PotentialSecret
from detect_secrets.settings import configure_settings_from_baseline
from detect_secrets.settings import get_settings


class PatchedFile:
    """This exists so that we can do typecasting, without importing unidiff."""
    path: str

    def __iter__(self) -> Generator:
        pass


class SecretsCollection:
    def __init__(self, root: str = '') -> None:
        """
        :param root: if specified, will scan as if the root was the value provided,
            rather than the current working directory. We still store results as if
            relative to root, since we're running as if it was in a different directory,
            rather than scanning a different directory.
        """
        self.data: Dict[str, Set[PotentialSecret]] = defaultdict(set)
        self.root = root

    @classmethod
    def load_from_baseline(cls, baseline: Dict[str, Any]) -> 'SecretsCollection':
        output = cls()
        for filename in baseline['results']:
            for item in baseline['results'][filename]:
                secret = PotentialSecret.load_secret_from_dict({'filename': filename, **item})
                output[convert_local_os_path(filename)].add(secret)

        return output

    @property
    def files(self) -> Set[str]:
        return set(self.data.keys())

    def scan_files(self, *filenames: str, num_processors: Optional[int] = None) -> None:
        """Just like scan_file, but optimized through parallel processing."""
        if len(filenames) == 1:
            self.scan_file(filenames[0])
            return

        if not num_processors:
            num_processors = mp.cpu_count()

        child_process_settings = get_settings().json()

        with mp.Pool(
            processes=num_processors,
            initializer=configure_settings_from_baseline,
            initargs=(child_process_settings,),
        ) as p:
            for secrets in p.imap_unordered(
                _scan_file_and_serialize,
                [os.path.join(self.root, filename) for filename in filenames],
            ):
                for secret in secrets:
                    self[os.path.relpath(secret.filename, self.root)].add(secret)

    def scan_file(self, filename: str) -> None:
        for secret in scan.scan_file(os.path.join(self.root, convert_local_os_path(filename))):
            self[convert_local_os_path(filename)].add(secret)

    def scan_diff(self, diff: str) -> None:
        """
        :raises: UnidiffParseError
        """
        try:
            for secret in scan.scan_diff(diff):
                self[secret.filename].add(secret)
        except ImportError:     # pragma: no cover
            raise NotImplementedError(
                'SecretsCollection.scan_diff requires `unidiff` to work. Try pip '
                'installing that package, and try again.',
            )

    def merge(self, old_results: 'SecretsCollection') -> None:
        """
        We operate under an assumption that the latest results are always more accurate,
        assuming that the baseline is created on the same repository. However, we cannot
        merely discard the old results in favor of the new, since there is valuable information
        that ought to be preserved: verification of secrets, both automated and manual.

        Therefore, this function serves to extract this information from the old results,
        and amend the new results with it.
        """
        for filename in old_results.files:
            if filename not in self.files:
                continue

            for old_secret, new_secret in _pair_secrets(
                old_results.data[filename],
                self.data[filename],
            ):
                # Only override if there's no newer value.
                if new_secret.is_secret is None:
                    new_secret.is_secret = old_secret.is_secret

                # If the old value is false, it won't make a difference.
                if not new_secret.is_verified:
                    new_secret.is_verified = old_secret.is_verified

    def trim(
        self,
        scanned_results: Optional['SecretsCollection'] = None,
        filelist: Optional[List[str]] = None,
    ) -> None:
        """
        Removes invalid entries in the current SecretsCollection.

        This behaves *kinda* like set intersection and left-join. That is, for matching files,
        a set intersection is performed. For non-matching files, only the files in `self` will
        be kept.

        This is because we may not be constructing the other SecretsCollection with the same
        information as we are with the current SecretsCollection, and we cannot infer based on
        incomplete information. As such, we will keep the status quo.

        Assumptions:
            1. Both `scanned_results` and the current SecretsCollection are constructed using
               the same settings (otherwise, we can't determine whether a missing secret is due
               to newly filtered secrets, or actually removed).

        :param scanned_results: if None, will just clear out non-existent files.
        :param filelist: files without secrets are not present in `scanned_results`. Therefore,
            by supplying this additional filelist, we can assert that if an entry is missing in
            `scanned_results`, it must not have secrets in it.
        """
        if scanned_results is None:
            scanned_results = SecretsCollection()
            filelist = [
                filename
                for filename in self.files
                if not os.path.exists(filename)
            ]

        if not filelist:
            fileset = set()
        else:
            fileset = set(filelist)

        # We can't merely do a set intersection: not only do we want to update the line
        # numbers (if applicable), but duplicate occurrences of the same secret hash/type are
        # distinct findings now. Matching therefore happens through the line-agnostic baseline
        # identity, with line numbers used only to pair duplicates deterministically.
        result: Dict[str, Set[PotentialSecret]] = defaultdict(set)

        for filename in scanned_results.files:
            if filename not in self.files:
                continue

            for existing_secret, secret in _pair_secrets(
                self[filename],
                scanned_results[filename],
            ):
                if existing_secret.line_number:
                    # Only update line numbers if we're tracking them.
                    existing_secret.line_number = secret.line_number

                result[filename].add(existing_secret)

        for filename in self.files:
            # If this is already populated by scanned_results, then the set intersection
            # is already completed.
            if filename in result:
                continue

            # All secrets relating to that file was removed.
            # We know this because:
            #   1. It's a file that was scanned (in filelist)
            #   2. It would have been in the baseline, if there were secrets...
            #   3. ...but it isn't.
            if filename in fileset:
                continue

            result[filename] = self[filename]

        self.data = result

    def json(self) -> Dict[str, Any]:
        """Custom JSON encoder"""
        output = defaultdict(list)
        for filename, secret in self:
            output[filename].append(secret.json())

        return dict(output)

    def exactly_equals(self, other: Any) -> bool:
        return self.__eq__(other, strict=True)      # type: ignore

    def __getitem__(self, filename: str) -> Set[PotentialSecret]:
        return self.data[filename]

    def __setitem__(self, filename: str, value: Set[PotentialSecret]) -> None:
        self.data[filename] = value

    def __iter__(self) -> Generator[Tuple[str, PotentialSecret], None, None]:
        for filename in sorted(self.files):
            secrets = self[filename]

            # NOTE: If line numbers aren't supplied, they are supposed to default to 0.
            for secret in sorted(
                secrets,
                key=lambda secret: (
                    getattr(secret, 'line_number', 0),
                    secret.secret_hash,
                    secret.type,
                ),
            ):
                yield filename, secret

    def __bool__(self) -> bool:
        # This checks whether there are secrets, rather than just empty files.
        # Empty files can occur with SecretsCollection subtraction.
        return bool(list(self))

    def __eq__(self, other: Any, strict: bool = False) -> bool:
        """
        :param strict: if strict, will return False even if secrets match
            (e.g. if line numbers are different)
        """
        if not isinstance(other, SecretsCollection):
            raise NotImplementedError

        if self.files != other.files:
            return False

        for filename in self.files:
            self_groups = _group_by_baseline_identity(self[filename])
            other_groups = _group_by_baseline_identity(other[filename])

            if set(self_groups.keys()) != set(other_groups.keys()):
                return False

            for identity, self_secrets in self_groups.items():
                other_secrets = other_groups[identity]
                if len(self_secrets) != len(other_secrets):
                    return False

                if not strict:
                    continue

                # Both collections are ordered by line number in `__iter__`, so zipping them
                # compares matching occurrences of the same logical secret.
                ordered_pairs = zip(
                    sorted(self_secrets, key=lambda secret: secret.line_number),
                    sorted(other_secrets, key=lambda secret: secret.line_number),
                )
                for secretA, secretB in ordered_pairs:
                    valuesA = vars(secretA)
                    valuesA.pop('secret_value')
                    valuesB = vars(secretB)
                    valuesB.pop('secret_value')

                    if valuesA['line_number'] == 0 or valuesB['line_number'] == 0:
                        # If line numbers are not provided (for either one), then don't compare
                        # line numbers.
                        valuesA.pop('line_number')
                        valuesB.pop('line_number')

                    if valuesA != valuesB:
                        return False

        return True

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __sub__(self, other: Any) -> 'SecretsCollection':
        """This behaves like set subtraction.

        Matching uses the line-agnostic baseline identity (filename, secret hash, type), so a
        secret that merely moved to another line is not reported as new. When a secret occurs on
        multiple lines, each occurrence is consumed at most once, so an additional, unlabelled
        occurrence is correctly reported as new.
        """
        if not isinstance(other, SecretsCollection):
            raise NotImplementedError

        # We want to create a copy to follow convention and adhere to the principle
        # of least surprise.
        output = SecretsCollection()
        for filename in other.files:
            if filename not in self.files:
                continue

            matched_new_secrets = {
                new_secret
                for _, new_secret in _pair_secrets(
                    other[filename],
                    self[filename],
                )
            }
            output[filename] = {
                secret
                for secret in self[filename]
                if secret not in matched_new_secrets
            }

        for filename in self.files:
            if filename in other.files:
                continue

            output[filename] = self[filename]

        return output

    def __len__(self) -> int:
        """Returns the total number of secrets in the collection."""
        return sum(len(secrets) for secrets in self.data.values())


def _scan_file_and_serialize(filename: str) -> List[PotentialSecret]:
    """Used for multiprocessing, since lambdas can't be serialized."""
    return list(scan.scan_file(filename))


def _group_by_baseline_identity(
    secrets: Iterable[PotentialSecret],
) -> Dict[Tuple[str, str, str], List[PotentialSecret]]:
    groups: Dict[Tuple[str, str, str], List[PotentialSecret]] = defaultdict(list)
    for secret in secrets:
        groups[secret.baseline_identity].append(secret)

    return groups


def _pair_secrets(
    reference: Iterable[PotentialSecret],
    current: Iterable[PotentialSecret],
) -> List[Tuple[PotentialSecret, PotentialSecret]]:
    """Matches secrets across two scans of the same file, tolerating line-number drift.

    Secrets are grouped by their line-agnostic baseline identity (filename, secret hash, type).
    Within each group, occurrences sitting on the same line are paired first; any remaining
    occurrences are paired in line order so that line drift (e.g. inserted lines) still maps
    onto the old annotation. Unpaired secrets on either side are simply omitted.

    Because every secret participates in at most one pair, labels from one occurrence never
    leak onto a separate, duplicate occurrence of the same secret.
    """
    reference_groups = _group_by_baseline_identity(reference)
    current_groups = _group_by_baseline_identity(current)

    pairs: List[Tuple[PotentialSecret, PotentialSecret]] = []
    for identity in reference_groups:
        if identity not in current_groups:
            continue

        remaining_reference = list(reference_groups[identity])
        remaining_current = list(current_groups[identity])

        # Exact line-number matches take priority.
        for reference_secret in list(remaining_reference):
            for current_secret in list(remaining_current):
                if (
                    reference_secret.line_number
                    and reference_secret.line_number == current_secret.line_number
                ):
                    pairs.append((reference_secret, current_secret))
                    remaining_reference.remove(reference_secret)
                    remaining_current.remove(current_secret)
                    break

        # Any leftovers are matched in line order, which handles line-number drift and
        # baselines that don't record line numbers.
        remaining_reference.sort(key=lambda secret: secret.line_number)
        remaining_current.sort(key=lambda secret: secret.line_number)
        pairs.extend(zip(remaining_reference, remaining_current))

    return pairs
