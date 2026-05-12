# ============================================
# result.py — MPC computation result
# ============================================

from dataclasses import dataclass
from typing import Optional, List

@dataclass
class MpcResult:
    job_id: str
    operation: str
    result: int
    n_parties: int
    success: bool
    proof_valid: bool = True
    error: Optional[str] = None

    def __repr__(self) -> str:
        if self.success:
            return (
                f"MpcResult(job={self.job_id[:8]}..., "
                f"result={self.result:,}, "
                f"proof={'✅' if self.proof_valid else '❌'})"
            )
        return f"MpcResult(FAILED: {self.error})"

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "operation": self.operation,
            "result": self.result,
            "n_parties": self.n_parties,
            "success": self.success,
            "proof_valid": self.proof_valid,
            "error": self.error,
        }