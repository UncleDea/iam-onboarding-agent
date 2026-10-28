"""Retries for transient provider failures.

Real identity APIs fail sometimes: a timeout, a 429, a brief outage.
A professional system retries those instead of dying halfway through
an on-boarding. Permanent errors (bad input, unknown user, duplicate
account) are NOT retried -- retrying those just fails slower.
"""

import time


class TransientError(Exception):
    """A failure that may succeed if tried again shortly."""


def call_with_retry(fn, attempts: int = 3, base_delay: float = 0.1):
    """Call fn(), retrying TransientError with exponential backoff.

    attempts counts the total tries, not the retries. Delays are
    base_delay, 2x base_delay, 4x ... -- small by default so tests
    stay fast; a real deployment passes a larger base_delay.
    """
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except TransientError as exc:
            last_exc = exc
            if attempt < attempts - 1:
                time.sleep(base_delay * (2 ** attempt))
    raise last_exc
