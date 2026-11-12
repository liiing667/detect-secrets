import hashlib
from typing import Any
from typing import Dict
from typing import Optional
from typing import Tuple
from typing import Union

from ..util.color import AnsiColor
from ..util.color import colorize
from ..util.path import convert_local_os_path


class PotentialSecret:
    """This custom data type represents a string found, matching the
    plugin rules defined in SecretsCollection, that has the potential
    to be a secret that we actually care about.

    "Potential" is the operative word here, because of the nature of
    false positives.

    We use this custom class so that we can more easily generate data
    structures and do object-based comparisons with other PotentialSecrets,
    without actually knowing what the secret is.
    """

    def __init__(
        self,
        type: str,
        filename: str,
        secret: str,
        line_number: int = 0,
        is_secret: Optional[bool] = None,
        is_verified: bool = False,
    ) -> None:
        """
        :param type: human-readable secret type, defined by the plugin
            that generated this PotentialSecret. e.g. "High Entropy String"
        :param filename: name of file that this secret was found
        :param secret: the actual secret identified
        :param line_number: location of secret, within filename.
            Merely used as a reference for easy triage.
        :param is_secret: whether or not the secret is a true- or false- positive
        :param is_verified: whether the secret has been externally verified
        """
        self.type = type
        self.filename = filename
        self.line_number = line_number
        self.set_secret(secret)
        self.is_secret = is_secret
        self.is_verified = is_verified

        # If two PotentialSecrets have the same values for these fields, they refer to the
        # same logical secret. Note that line numbers aren't included in this, because line
        # numbers are subject to change (e.g. when lines are inserted above a secret).
        self.fields_to_compare = ['filename', 'secret_hash', 'type']

    @property
    def identity_key(self) -> Tuple:
        """Identifies the logical secret, regardless of its location.

        This is used to match findings against baseline entries that may have drifted to
        a different line (e.g. slim baselines, which don't store line numbers at all).
        """
        return (self.filename, self.secret_hash, self.type)

    @property
    def location_key(self) -> Tuple:
        """Identifies a specific occurrence of a secret within a file.

        The line number is only included when it is known: findings without a known line
        number intentionally collide on :attr:`identity_key`, so that they remain able to
        match baseline entries across line drift.
        """
        if self.line_number:
            return (*self.identity_key, self.line_number)

        return self.identity_key

    def set_secret(self, secret: str) -> None:
        self.secret_hash: str = self.hash_secret(secret)

        # Note: Originally, we never wanted to keep the secret value in memory,
        #       after finding it in the codebase. However, to support verifiable
        #       secrets (and avoid the pain of re-scanning again), we need to
        #       keep the plaintext in memory as such.
        #
        #       This value should never appear in the baseline though, seeing that
        #       we don't want to create a file that contains all plaintext secrets
        #       in the repository.
        self.secret_value: Optional[str] = secret

    @staticmethod
    def hash_secret(secret: str) -> str:
        """This offers a way to coherently test this class, without mocking self.secret_hash."""
        return hashlib.sha1(secret.encode('utf-8')).hexdigest()

    @classmethod
    def load_secret_from_dict(cls, data: Dict[str, Union[str, int, bool]]) -> 'PotentialSecret':
        """Custom JSON decoder"""
        kwargs: Dict[str, Any] = {
            'type': str(data['type']),
            'filename': convert_local_os_path(str(data['filename'])),
            'secret': 'will be replaced',
        }

        # Optional parameters
        for parameter in {
            'line_number',
            'is_secret',
            'is_verified',
        }:
            if parameter in data:
                kwargs[parameter] = data[parameter]

        output = cls(**kwargs)
        output.secret_value = None
        output.secret_hash = str(data['hashed_secret'])

        return output

    def json(self) -> Dict[str, Union[str, int, bool]]:
        """Custom JSON encoder"""
        attributes: Dict[str, Union[str, int, bool]] = {
            'type': self.type,
            'filename': self.filename,
            'hashed_secret': self.secret_hash,
            'is_verified': self.is_verified,
        }

        if hasattr(self, 'line_number') and self.line_number:
            attributes['line_number'] = self.line_number

        if hasattr(self, 'is_secret') and self.is_secret is not None:
            attributes['is_secret'] = self.is_secret

        return attributes

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, PotentialSecret):
            return NotImplemented

        if any(
            getattr(self, field) != getattr(other, field)
            for field in self.fields_to_compare
        ):
            return False

        # When both occurrences have known line numbers, distinct lines are distinct
        # findings: the same token appearing on two lines must not collapse into one.
        # If either line number is unknown (e.g. slim / adhoc baselines), we preserve
        # the historical cross-line matching behavior.
        if self.line_number and other.line_number:
            return self.line_number == other.line_number

        return True

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        # Hashing deliberately excludes the line number, so that sets can still be used as
        # keyed lookup tables across line drift. Equality is a refinement of this hash:
        # equal objects always hash the same, while distinct-line occurrences merely share
        # a hash bucket (and can coexist within the same set).
        return hash(self.identity_key)

    def __str__(self) -> str:
        return (
            f'Secret Type: {colorize(self.type, AnsiColor.BOLD)}\n'
            f'Location:    {self.filename}:{self.line_number}\n'
        )
