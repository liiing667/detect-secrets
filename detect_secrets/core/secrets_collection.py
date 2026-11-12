import multiprocessing as mp
import os
from collections import defaultdict
from typing import Any
from typing import Dict
from typing import Generator
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

            mapping = _match_baseline_secrets(old_results.data[filename], self.data[filename])
            for old_secret, new_secret in mapping.items():
                _carry_over_secret_labels(old_secret, new_secret)

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

        # Unfortunately, we can't merely do a set intersection since we want to update the line
        # numbers (if applicable). Therefore, this does it manually.
        result: Dict[str, Set[PotentialSecret]] = defaultdict(set)

        for filename in scanned_results.files:
            if filename not in self.files:
                continue

            # Preserve labelled baseline entries, while tracking where the same secret now
            # lives in the freshly scanned results.
            matched_existing_secrets: Set[PotentialSecret] = set()
            mapping = _match_baseline_secrets(scanned_results[filename], self[filename])
            for scanned_secret, existing_secret in mapping.items():
                matched_existing_secrets.add(existing_secret)

                # Currently, we assume that the `scanned_results` have no labelled data, so
                # we only want to obtain the latest line number from it.
                if existing_secret.line_number:
                    # Only update line numbers if we're tracking them.
                    existing_secret.line_number = scanned_secret.line_number

                result[filename].add(existing_secret)

            # Baseline entries without an unambiguous match are kept as-is, unless the same
            # logical secret no longer appears anywhere in the scanned file -- in that case,
            # the secret was removed (or filtered out), so it should be trimmed away.
            scanned_identities = {
                secret.identity_key for secret in scanned_results[filename]
            }
            for existing_secret in self[filename]:
                if existing_secret in matched_existing_secrets:
                    continue

                if existing_secret.identity_key in scanned_identities:
                    # The secret still exists, but matching was ambiguous (e.g. it shows up
                    # on multiple lines). Keep the labelled entry untouched, rather than
                    # attaching its labels to the wrong occurrence.
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
            # Identity keys match findings across line drift, so that rescans against
            # line-number-less (e.g. slim) baselines still compare equal. Counts matter:
            # a token appearing twice must not be treated like a single occurrence.
            self_identities = [secret.identity_key for secret in self[filename]]
            other_identities = [secret.identity_key for secret in other[filename]]
            if sorted(self_identities) != sorted(other_identities):
                return False

            if not strict:
                continue

            # In strict mode, distinct occurrences must line up on the same line. Match
            # by location key (which falls back to identity key when lines are unknown).
            self_by_location = {
                secret.location_key: secret
                for secret in self[filename]
            }
            other_by_location = {
                secret.location_key: secret
                for secret in other[filename]
            }
            if sorted(self_by_location) != sorted(other_by_location):
                return False

            for key, secretA in self_by_location.items():
                secretB = other_by_location[key]

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
        """This behaves like set subtraction."""
        if not isinstance(other, SecretsCollection):
            raise NotImplementedError

        # We want to create a copy to follow convention and adhere to the principle
        # of least surprise.
        output = SecretsCollection()
        for filename in other.files:
            if filename not in self.files:
                continue

            # Exact location matches are consumed first, so that a genuinely new
            # occurrence (on a line the baseline doesn't know about) is what gets
            # reported. Any baseline entries left over then match by identity instead,
            # which keeps line drift (including line-number-less slim baselines) quiet.
            other_secrets = list(other[filename])
            matched_other: List[PotentialSecret] = []
            for baseline_secret in other_secrets:
                for current_secret in self[filename]:
                    if current_secret in matched_other:
                        continue
                    if current_secret.location_key == baseline_secret.location_key:
                        matched_other.append(current_secret)
                        break

            leftover_identities = [
                secret.identity_key
                for secret in other_secrets
                if secret not in matched_other
            ]
            remaining: List[PotentialSecret] = []
            for secret in self[filename]:
                if secret in matched_other:
                    continue
                if secret.identity_key in leftover_identities:
                    leftover_identities.remove(secret.identity_key)
                else:
                    remaining.append(secret)

            output[filename] = set(remaining)

        for filename in self.files:
            if filename in other.files:
                continue

            output[filename] = self[filename]

        return output

    def __len__(self) -> int:
        """Returns the total number of secrets in the collection."""
        return sum(len(secrets) for secrets in self.data.values())


def _carry_over_secret_labels(
    old_secret: PotentialSecret,
    new_secret: PotentialSecret,
) -> None:
    """Copies audit information from a baseline entry onto its rescanned counterpart."""
    # Only override if there's no newer value.
    if new_secret.is_secret is None:
        new_secret.is_secret = old_secret.is_secret

    # If the old value is false, it won't make a difference.
    if not new_secret.is_verified:
        new_secret.is_verified = old_secret.is_verified


def _match_baseline_secrets(
    labelled_secrets: Set[PotentialSecret],
    current_secrets: Set[PotentialSecret],
) -> Dict[PotentialSecret, PotentialSecret]:
    """Pairs baseline entries up with their rescanned counterparts.

    Matching happens in four passes:

    1. Exact location matches (same logical secret and same known line number) are always
       preferred, so labels never bleed across distinct occurrences of a repeated token.
    2. Entries without a known line number (slim / adhoc baselines) may then match across
       line drift -- but only when the match is unambiguous. When the same secret appears
       on multiple lines, there is no safe way to tell which occurrence the label belongs
       to, so such entries are left unmatched instead of guessing.
    3. Labelled entries whose recorded line no longer holds (e.g. lines were inserted
       above the secret) follow the same unambiguous single-occurrence fallback.
    4. Identical multisets of repeated tokens that drift together are paired up in line
       order, since each side describes the same occurrences shifted by the same offset.

    :returns: mapping of ``labelled_secret -> current_secret``
    """
    current_by_location = {
        secret.location_key: secret
        for secret in current_secrets
    }
    current_by_identity: Dict[Tuple, List[PotentialSecret]] = defaultdict(list)
    for secret in current_secrets:
        current_by_identity[secret.identity_key].append(secret)

    mapping: Dict[PotentialSecret, PotentialSecret] = {}
    claimed: Set[PotentialSecret] = set()

    # First pass: pin findings with known line numbers to their exact locations.
    for labelled_secret in labelled_secrets:
        if labelled_secret.line_number:
            current_secret = current_by_location.get(labelled_secret.location_key)
            if current_secret is not None:
                mapping[labelled_secret] = current_secret
                claimed.add(current_secret)

    # Second pass: entries without a known line number (slim / adhoc baselines) may match
    # across line drift without further checks, since they carry no location information.
    for labelled_secret in labelled_secrets:
        if labelled_secret in mapping or labelled_secret.line_number:
            continue

        candidates = [
            secret
            for secret in current_by_identity.get(labelled_secret.identity_key, [])
            if secret not in claimed
        ]
        if len(candidates) == 1:
            mapping[labelled_secret] = candidates[0]
            claimed.add(candidates[0])

    # Third pass: entries that moved to a different line (e.g. lines were inserted above
    # them) are followed across line drift too -- but only when exactly one occurrence of
    # the same logical secret remains unmatched. With repeated tokens, matching would be
    # ambiguous, so the labelled entry is intentionally left untouched.
    for labelled_secret in labelled_secrets:
        if labelled_secret in mapping:
            continue

        candidates = [
            secret
            for secret in current_by_identity.get(labelled_secret.identity_key, [])
            if secret not in claimed
        ]
        if len(candidates) == 1:
            mapping[labelled_secret] = candidates[0]
            claimed.add(candidates[0])

    # Fourth pass: repeated tokens can drift as a group (e.g. a line inserted above both
    # occurrences). When every remaining candidate is claimed by a sibling of the same
    # logical secret, pairing the entries up in line order is unambiguous, since each side
    # describes the same multiset of occurrences.
    for identity_key, current_group in current_by_identity.items():
        unlabelled_group = [
            secret
            for secret in labelled_secrets
            if secret not in mapping and secret.identity_key == identity_key
        ]
        unclaimed_group = [
            secret for secret in current_group if secret not in claimed
        ]
        if (
            unlabelled_group
            and all(secret.line_number for secret in unlabelled_group)
            and all(secret.line_number for secret in unclaimed_group)
            and len(unlabelled_group) == len(current_group)
            and len(unclaimed_group) == len(current_group)
        ):
            for labelled_secret, current_secret in zip(
                sorted(unlabelled_group, key=lambda secret: secret.line_number),
                sorted(unclaimed_group, key=lambda secret: secret.line_number),
            ):
                mapping[labelled_secret] = current_secret
                claimed.add(current_secret)

    return mapping


def _scan_file_and_serialize(filename: str) -> List[PotentialSecret]:
    """Used for multiprocessing, since lambdas can't be serialized."""
    return list(scan.scan_file(filename))
