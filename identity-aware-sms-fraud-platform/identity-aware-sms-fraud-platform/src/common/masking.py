"""MSISDN masking and pseudonymisation helpers."""
from __future__ import annotations
import hashlib
import hmac


def mask_msisdn(msisdn: str, keep_head: int = 4, keep_tail: int = 2) -> str:
    """628123456789 -> 6281******89. Short values are fully masked."""
    s = str(msisdn)
    if len(s) <= keep_head + keep_tail:
        return "*" * len(s)
    return s[:keep_head] + "*" * (len(s) - keep_head - keep_tail) + s[-keep_tail:]


def pseudonymize(value: str, key: bytes) -> str:
    """Stable keyed hash (HMAC-SHA256) so records can be correlated without exposing the number."""
    if not key:
        raise ValueError("a non-empty key is required")
    return hmac.new(key, str(value).encode(), hashlib.sha256).hexdigest()[:16]


def mask_frame(df, columns):
    out = df.copy()
    for c in columns:
        if c in out.columns:
            out[c] = out[c].astype(str).map(mask_msisdn)
    return out
