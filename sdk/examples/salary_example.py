# ============================================
# SDK Example — Private Salary Average
# ============================================
# Shows how a developer uses the SDK
# in just 5 lines of meaningful code.
# ============================================

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from mpc_sdk import MpcClient, Operation

def main():
    print("\n" + "="*50)
    print("  MPC SDK — Salary Average Example")
    print("="*50)

    # ── 5 lines of developer code ──────────
    client = MpcClient(party_id=1, n_parties=3)
    client.connect(["localhost:8002", "localhost:8003"])
    result = client.compute(Operation.AVERAGE, my_input=85_000)
    print(f"\n✅ Result: {result.result:,} OMR/year average salary")
    print(f"   Proof valid: {result.proof_valid}")
    # ───────────────────────────────────────

    print("\nJob details:")
    print(f"  Job ID    : {result.job_id}")
    print(f"  Operation : {result.operation}")
    print(f"  Parties   : {result.n_parties}")
    print(f"  Success   : {result.success}")

if __name__ == "__main__":
    main()