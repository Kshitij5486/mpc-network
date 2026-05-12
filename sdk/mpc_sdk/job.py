# ============================================
# job.py — MPC Job definition
# ============================================

import uuid
from enum import Enum
from typing import List, Optional
from dataclasses import dataclass, field

class Operation(Enum):
    SUM = "sum"
    AVERAGE = "average"
    PRODUCT = "product"
    MAX = "max"
    MIN = "min"
    PSI = "private_set_intersection"

class JobStatus(Enum):
    CREATED = "created"
    SUBMITTED = "submitted"
    ACTIVE = "active"
    COMPLETE = "complete"
    FAILED = "failed"

@dataclass
class MpcJob:
    operation: Operation
    n_parties: int
    my_input: int
    job_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: JobStatus = JobStatus.CREATED
    result: Optional[int] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "operation": self.operation.value,
            "n_parties": self.n_parties,
            "status": self.status.value,
            "result": self.result,
        }

    def __repr__(self) -> str:
        return (
            f"MpcJob(id={self.job_id[:8]}..., "
            f"op={self.operation.value}, "
            f"status={self.status.value})"
        )