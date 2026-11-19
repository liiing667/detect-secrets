#!/usr/bin/python
# This fixture supports the line-binding guarantee: a plugin finding must be proven
# jointly by the plugin output, the raw scanned line, and the recorded hash.

# A legitimate line that must keep producing findings.
SAFE_CONFIG = 'nothing to see here'
LEGITIMATE_SECRET = 'sk_live_ReTllpYQYfIZu2Jnf2lAPFjD'

# The raw value above must never be reported on this line,
# because this line does not contain it.
UNRELATED_CODE = 'print("hello world")'
