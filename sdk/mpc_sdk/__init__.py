# ============================================
# mpc_sdk — Python SDK for MPC Network
# ============================================

from .client import MpcClient
from .job import MpcJob, Operation, JobStatus
from .result import MpcResult
from .crypto import (
    share_secret,
    reconstruct_secret,
    compute_mac,
    verify_mac,
    PRIME,
)

__version__ = "0.1.0"
__all__ = [
    "MpcClient",
    "MpcJob",
    "MpcResult",
    "Operation",
    "JobStatus",
    "share_secret",
    "reconstruct_secret",
    "compute_mac",
    "verify_mac",
    "PRIME",
]