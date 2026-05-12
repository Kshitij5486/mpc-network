# ============================================
# Demo 1 — Private Salary Average
# ============================================
# Scenario:
# 3 employees want to know their average salary.
# Nobody wants to reveal their own salary.
#
# Without MPC:
# They would need a trusted third party
# to collect all salaries and compute the average.
# That third party is a privacy risk.
#
# With MPC (this demo):
# Each employee runs a node with their salary
# as private input. The network computes the
# average. Nobody learns anyone else's salary.
#
# This demo simulates the full MPC protocol
# locally — 3 parties, 1 computation, 0 leaks.
# ============================================

import random
import hashlib
import json
import time
from typing import List, Tuple

# ============================================
# Field arithmetic (mirrors our Rust field.rs)
# ============================================

PRIME = 2_305_843_009_213_693_951  # Mersenne prime

def field_add(a: int, b: int) -> int:
    return (a + b) % PRIME

def field_sub(a: int, b: int) -> int:
    return (a - b) % PRIME

def field_mul(a: int, b: int) -> int:
    return (a * b) % PRIME

def field_inv(a: int) -> int:
    """Modular inverse using Fermat's little theorem."""
    return pow(a, PRIME - 2, PRIME)

def field_div(a: int, b: int) -> int:
    return field_mul(a, field_inv(b))

# ============================================
# Shamir Secret Sharing (mirrors shamir.rs)
# ============================================

def eval_poly(coeffs: List[int], x: int) -> int:
    """Evaluate polynomial at x using Horner's method."""
    result = 0
    for coeff in reversed(coeffs):
        result = field_add(field_mul(result, x), coeff)
    return result

def split_secret(secret: int, threshold: int, n_shares: int) -> List[Tuple[int, int]]:
    """Split secret into n shares, any threshold can reconstruct."""
    assert secret < PRIME, "Secret must be less than PRIME"
    coeffs = [secret] + [random.randint(1, PRIME - 1) for _ in range(threshold - 1)]
    shares = [(i, eval_poly(coeffs, i)) for i in range(1, n_shares + 1)]
    return shares

def reconstruct_secret(shares: List[Tuple[int, int]]) -> int:
    """Reconstruct secret from shares using Lagrange interpolation."""
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        numerator = yi
        denominator = 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            numerator = field_mul(numerator, field_sub(0, xj))
            denominator = field_mul(denominator, field_sub(xi, xj))
        term = field_mul(numerator, field_inv(denominator))
        secret = field_add(secret, term)
    return secret

# ============================================
# MAC Authentication (mirrors mac.rs)
# ============================================

class MacKey:
    def __init__(self):
        self.alpha = random.randint(1, PRIME - 1)

    def compute_tag(self, value: int) -> int:
        return field_mul(self.alpha, value)

    def verify(self, value: int, tag: int) -> bool:
        return self.compute_tag(value) == tag

class AuthenticatedShare:
    def __init__(self, x: int, y: int, mac_key: MacKey):
        self.x = x
        self.y = y
        self.tag = mac_key.compute_tag(y)
        self.mac_key = mac_key

    def verify(self) -> bool:
        return self.mac_key.verify(self.y, self.tag)

    def tamper(self, new_value: int):
        """Simulate a cheating party."""
        self.y = new_value
        # tag is NOT updated — cheating detected on verify

# ============================================
# MPC Party (one participant)
# ============================================

class MpcParty:
    def __init__(self, party_id: int, salary: int, n_parties: int):
        self.party_id = party_id
        self.salary = salary
        self.n_parties = n_parties
        self.mac_key = MacKey()
        self.received_shares = {}
        self.name = f"Employee {party_id}"

    def create_shares(self) -> List[AuthenticatedShare]:
        """Split salary into shares for each party."""
        threshold = self.n_parties // 2 + 1
        raw_shares = split_secret(self.salary, threshold, self.n_parties)
        auth_shares = []
        for x, y in raw_shares:
            share = AuthenticatedShare(x, y, self.mac_key)
            auth_shares.append(share)
        return auth_shares

    def receive_share(self, from_party: int, share: AuthenticatedShare):
        """Receive a share from another party."""
        self.received_shares[from_party] = share

    def verify_all_shares(self) -> bool:
        """Verify MAC tags on all received shares."""
        for party_id, share in self.received_shares.items():
            if not share.verify():
                print(f"  ❌ Party {self.party_id}: MAC verification FAILED for share from party {party_id}")
                return False
        return True

    def compute_local_sum(self) -> int:
        """Add all received share values together."""
        total = 0
        for share in self.received_shares.values():
            total = field_add(total, share.y)
        return total

# ============================================
# MPC Network — orchestrates the computation
# ============================================

class MpcNetwork:
    def __init__(self, parties: List[MpcParty]):
        self.parties = parties
        self.n = len(parties)

    def run_private_average(self) -> dict:
        """Run the full MPC protocol to compute average salary."""
        print("\n" + "="*60)
        print("  MPC PRIVATE SALARY AVERAGE — DEMO")
        print("="*60)

        # Step 1: Each party splits their salary
        print("\n📦 Step 1: Each party splits their salary into shares")
        all_shares = {}
        for party in self.parties:
            shares = party.create_shares()
            all_shares[party.party_id] = shares
            print(f"  {party.name} splits salary → {self.n} shares (each looks random)")

        # Step 2: Distribute shares
        print("\n📡 Step 2: Parties exchange shares over secure channels")
        for sender in self.parties:
            for i, receiver in enumerate(self.parties):
                share = all_shares[sender.party_id][i]
                receiver.receive_share(sender.party_id, share)
        print(f"  Each party now holds {self.n} shares (one per employee)")
        print("  No party can see any other employee's salary from these shares")

        # Step 3: Verify MAC tags
        print("\n🔐 Step 3: Each party verifies MAC authentication tags")
        for party in self.parties:
            ok = party.verify_all_shares()
            status = "✅ Valid" if ok else "❌ TAMPERED"
            print(f"  {party.name}: {status}")

        # Step 4: Each party computes local sum
        print("\n⚙️  Step 4: Each party adds their shares locally (no communication)")
        local_sums = []
        for party in self.parties:
            local_sum = party.compute_local_sum()
            local_sums.append((party.party_id, local_sum))
            print(f"  {party.name}: local sum = {local_sum} (meaningless without other parties)")

        # Step 5: Reconstruct the total sum
        print("\n🔓 Step 5: Parties combine local sums to get total")
        total_salary = reconstruct_secret(local_sums)
        average_salary = total_salary // self.n

        print(f"\n{'='*60}")
        print(f"  ✅ RESULT: Average salary = {average_salary:,}")
        print(f"{'='*60}")
        print(f"\n  Individual salaries that were NEVER revealed:")
        for party in self.parties:
            print(f"  {party.name}: {party.salary:,} (private — never shared)")

        return {
            "average": average_salary,
            "total": total_salary,
            "n_parties": self.n,
            "individual_salaries_revealed": False,
        }

    def run_cheat_detection_demo(self):
        """Show what happens when a party tries to cheat."""
        print("\n" + "="*60)
        print("  CHEAT DETECTION DEMO")
        print("="*60)
        print("\n🦹 Party 1 tries to tamper with their share...")

        all_shares = {}
        for party in self.parties:
            shares = party.create_shares()
            all_shares[party.party_id] = shares

        # Distribute shares
        for sender in self.parties:
            for i, receiver in enumerate(self.parties):
                share = all_shares[sender.party_id][i]
                receiver.receive_share(sender.party_id, share)

        # Party 1 tampers with their share sent to Party 2
        tampered_share = all_shares[1][1]  # Party 1's share for Party 2
        tampered_share.tamper(999999999)   # change value but not MAC tag

        print("  Party 1 changed their share value but not the MAC tag")
        print("\n🔐 MAC verification running...")

        for party in self.parties:
            ok = party.verify_all_shares()
            if not ok:
                print(f"  ❌ {party.name} detected CHEATING — aborting computation")
                print(f"  → SlashingContract.confirmSlash() would fire here")
                print(f"  → Party 1 loses their staked tokens")
                return False

        return True

# ============================================
# Main — run the demo
# ============================================

def main():
    print("\n🚀 Starting MPC Private Salary Average Demo")
    print("   This demonstrates Phases 1-4 of the MPC Network")
    print("   running a real privacy-preserving computation\n")

    # Create 3 employees with private salaries
    salaries = [
        (1, 85000),   # Employee 1: 85,000 OMR/year
        (2, 92000),   # Employee 2: 92,000 OMR/year
        (3, 78000),   # Employee 3: 78,000 OMR/year
    ]

    expected_average = sum(s for _, s in salaries) // len(salaries)

    parties = [MpcParty(pid, salary, len(salaries))
               for pid, salary in salaries]
    network = MpcNetwork(parties)

    # Run Demo 1: Private average
    result = network.run_private_average()

    # Verify result
    print(f"\n✅ Verification:")
    print(f"   Expected average : {expected_average:,}")
    print(f"   MPC result       : {result['average']:,}")
    print(f"   Correct          : {result['average'] == expected_average}")

    # Run Demo 2: Cheat detection
    parties2 = [MpcParty(pid, salary, len(salaries))
                for pid, salary in salaries]
    network2 = MpcNetwork(parties2)
    network2.run_cheat_detection_demo()

    print("\n" + "="*60)
    print("  Demo complete.")
    print("  This computation used:")
    print("  • Shamir secret sharing (shamir.rs)")
    print("  • MAC authentication (mac.rs)")
    print("  • Field arithmetic (field.rs)")
    print("  • SPDZ protocol logic (spdz.rs)")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()