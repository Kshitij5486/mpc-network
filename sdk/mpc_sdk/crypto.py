# ============================================
# crypto.py — Core MPC cryptography in Python
# ============================================
# Mirrors the Rust crypto crate for the SDK.
# Used by all demos and SDK functions.
# ============================================

import random
import hashlib
from typing import List, Tuple

PRIME = 2_305_843_009_213_693_951

def field_add(a: int, b: int) -> int:
    return (a + b) % PRIME

def field_sub(a: int, b: int) -> int:
    return (a - b) % PRIME

def field_mul(a: int, b: int) -> int:
    return (a * b) % PRIME

def field_inv(a: int) -> int:
    return pow(a, PRIME - 2, PRIME)

def eval_poly(coeffs: List[int], x: int) -> int:
    result = 0
    for coeff in reversed(coeffs):
        result = field_add(field_mul(result, x), coeff)
    return result

def share_secret(
    secret: int,
    threshold: int,
    n_shares: int
) -> List[Tuple[int, int]]:
    assert secret < PRIME
    coeffs = [secret] + [
        random.randint(1, PRIME - 1)
        for _ in range(threshold - 1)
    ]
    return [(i, eval_poly(coeffs, i)) for i in range(1, n_shares + 1)]

def reconstruct_secret(shares: List[Tuple[int, int]]) -> int:
    result = 0
    for i, (xi, yi) in enumerate(shares):
        num, den = yi, 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            num = field_mul(num, field_sub(0, xj))
            den = field_mul(den, field_sub(xi, xj))
        result = field_add(result, field_mul(num, field_inv(den)))
    return result

def compute_mac(value: int, alpha: int) -> int:
    return field_mul(alpha, value)

def verify_mac(value: int, alpha: int, tag: int) -> bool:
    return compute_mac(value, alpha) == tag

def hash_value(value: int) -> str:
    return hashlib.sha256(str(value).encode()).hexdigest()