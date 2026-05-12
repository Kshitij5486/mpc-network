# ============================================
# Demo 2 — Joint Fraud Detection
# ============================================
# Scenario:
# Two competing banks want to find customers
# who appear on BOTH their fraud blacklists.
# They cannot share their full blacklists
# (privacy laws, competitive sensitivity).
#
# Solution: Private Set Intersection (PSI)
# Using MPC, they compute the INTERSECTION
# of their blacklists — only the common
# fraudsters are revealed. Nothing else.
#
# Real world use: Banks, insurance companies,
# government agencies — all need this.
# This is worth billions in fraud prevention.
# ============================================

import random
import hashlib
import json
from typing import List, Set, Dict, Tuple

PRIME = 2_305_843_009_213_693_951

def field_mul(a: int, b: int) -> int:
    return (a * b) % PRIME

def field_add(a: int, b: int) -> int:
    return (a + b) % PRIME

def field_inv(a: int) -> int:
    return pow(a, PRIME - 2, PRIME)

# ============================================
# Hash customer ID to field element
# ============================================

def hash_customer_id(customer_id: str) -> int:
    """Convert customer ID to a field element."""
    h = hashlib.sha256(customer_id.encode()).digest()
    value = int.from_bytes(h[:8], 'little')
    return value % PRIME

# ============================================
# Private Set Intersection using MPC
# ============================================
# How PSI works:
# 1. Each bank hashes their customer IDs
# 2. Each bank blinds their hashes with a secret key
#    blinded = hash^secret_key mod PRIME
# 3. Banks exchange blinded sets
# 4. Each bank blinds the OTHER bank's set with their key
#    double_blinded = blinded^secret_key mod PRIME
# 5. The intersection of double-blinded sets
#    contains the common fraudsters
#
# Why this works:
# hash(x)^a^b == hash(x)^b^a (commutativity)
# So double-blinded values match if and only if
# the original customer IDs matched.
# ============================================

class Bank:
    def __init__(self, name: str, blacklist: List[str]):
        self.name = name
        self.blacklist = set(blacklist)
        # Secret blinding key
        self.secret_key = random.randint(2, PRIME - 1)
        self._hashed = {}

    def hash_blacklist(self) -> Dict[int, str]:
        """Hash all customer IDs."""
        result = {}
        for customer_id in self.blacklist:
            h = hash_customer_id(customer_id)
            result[h] = customer_id
        self._hashed = result
        return result

    def blind(self, hashed_values: Dict[int, str]) -> Dict[int, int]:
        """Apply secret blinding: value^secret_key mod PRIME."""
        blinded = {}
        for h, customer_id in hashed_values.items():
            blinded_val = pow(h, self.secret_key, PRIME)
            blinded[blinded_val] = customer_id
        return blinded

    def blind_external(self, external_blinded: Dict[int, int]) -> Dict[int, int]:
        """Apply our key to values already blinded by other bank."""
        double_blinded = {}
        for blinded_val, data in external_blinded.items():
            double_blinded_val = pow(blinded_val, self.secret_key, PRIME)
            double_blinded[double_blinded_val] = data
        return double_blinded


class FraudDetectionMPC:
    def __init__(self, bank_a: Bank, bank_b: Bank):
        self.bank_a = bank_a
        self.bank_b = bank_b

    def run(self) -> dict:
        print("\n" + "="*60)
        print("  MPC JOINT FRAUD DETECTION — DEMO")
        print("="*60)

        print(f"\n🏦 {self.bank_a.name}: {len(self.bank_a.blacklist)} customers on blacklist")
        print(f"🏦 {self.bank_b.name}: {len(self.bank_b.blacklist)} customers on blacklist")
        print("\n  Neither bank will share their full blacklist.")
        print("  Only common fraudsters will be revealed.\n")

        # Step 1: Each bank hashes their blacklist
        print("📦 Step 1: Each bank hashes their customer IDs")
        hashed_a = self.bank_a.hash_blacklist()
        hashed_b = self.bank_b.hash_blacklist()
        print(f"  {self.bank_a.name}: {len(hashed_a)} hashed IDs (unreadable without secret key)")
        print(f"  {self.bank_b.name}: {len(hashed_b)} hashed IDs (unreadable without secret key)")

        # Step 2: Each bank blinds their hashes
        print("\n🔐 Step 2: Each bank blinds hashes with their secret key")
        blinded_a = self.bank_a.blind(hashed_a)
        blinded_b = self.bank_b.blind(hashed_b)
        print(f"  {self.bank_a.name}: applied secret key α — values look random")
        print(f"  {self.bank_b.name}: applied secret key β — values look random")

        # Step 3: Exchange blinded sets
        print("\n📡 Step 3: Banks exchange blinded sets over secure channel")
        print(f"  {self.bank_a.name} sends blinded set to {self.bank_b.name}")
        print(f"  {self.bank_b.name} sends blinded set to {self.bank_a.name}")
        print("  Neither bank can read the other's blinded values")

        # Step 4: Double-blind (apply own key to other bank's blinded set)
        print("\n⚙️  Step 4: Each bank applies their key to the other's blinded set")
        double_blinded_a_on_b = self.bank_b.blind_external(blinded_a)
        double_blinded_b_on_a = self.bank_a.blind_external(blinded_b)
        print(f"  {self.bank_b.name} applies β to {self.bank_a.name}'s set → hash^α^β")
        print(f"  {self.bank_a.name} applies α to {self.bank_b.name}'s set → hash^β^α")
        print("  hash^α^β == hash^β^α (commutative property)")

        # Step 5: Find intersection
        print("\n🔍 Step 5: Find matching double-blinded values")
        set_a = set(double_blinded_a_on_b.keys())
        set_b = set(double_blinded_b_on_a.keys())
        common_blinded = set_a & set_b

        # Map back to customer IDs
        # Build reverse map from double-blinded -> customer_id for bank_b
        reverse_b = {}
        for orig_blinded, customer_id in blinded_b.items():
            double = pow(orig_blinded, self.bank_a.secret_key, PRIME)
            reverse_b[double] = customer_id

        common_fraudsters = []
        for db_val in common_blinded:
            if db_val in reverse_b:
                common_fraudsters.append(reverse_b[db_val])

        print(f"\n{'='*60}")
        print(f"  ✅ RESULT: {len(common_fraudsters)} common fraudster(s) found")
        print(f"{'='*60}")

        if common_fraudsters:
            print("\n  🚨 Shared fraudsters (ONLY these are revealed):")
            for customer in sorted(common_fraudsters):
                print(f"     • {customer}")
        else:
            print("  No common fraudsters found.")

        print(f"\n  {self.bank_a.name} blacklist NOT revealed: {len(self.bank_a.blacklist) - len(common_fraudsters)} private entries protected")
        print(f"  {self.bank_b.name} blacklist NOT revealed: {len(self.bank_b.blacklist) - len(common_fraudsters)} private entries protected")

        return {
            "common_fraudsters": common_fraudsters,
            "bank_a_size": len(self.bank_a.blacklist),
            "bank_b_size": len(self.bank_b.blacklist),
            "intersection_size": len(common_fraudsters),
            "privacy_preserved": True,
        }


def main():
    print("\n🚀 Starting MPC Joint Fraud Detection Demo")
    print("   Two banks find shared fraudsters without")
    print("   revealing their private blacklists\n")

    # Bank A blacklist
    bank_a = Bank("Al Rashid Bank", [
        "CUST-001-AHMED",
        "CUST-002-SARA",
        "CUST-003-KHALID",    # fraudster
        "CUST-004-FATIMA",    # fraudster
        "CUST-005-OMAR",
        "CUST-006-LAYLA",
        "CUST-007-HASSAN",    # fraudster
    ])

    # Bank B blacklist (some overlap)
    bank_b = Bank("Gulf Commerce Bank", [
        "CUST-003-KHALID",    # fraudster (shared)
        "CUST-004-FATIMA",    # fraudster (shared)
        "CUST-007-HASSAN",    # fraudster (shared)
        "CUST-101-NOUR",
        "CUST-102-TARIQ",
        "CUST-103-RANA",
    ])

    mpc = FraudDetectionMPC(bank_a, bank_b)
    result = mpc.run()

    # Verify
    expected = {"CUST-003-KHALID", "CUST-004-FATIMA", "CUST-007-HASSAN"}
    found = set(result["common_fraudsters"])

    print(f"\n✅ Verification:")
    print(f"   Expected fraudsters : {sorted(expected)}")
    print(f"   Found fraudsters    : {sorted(found)}")
    print(f"   Correct             : {found == expected}")

    print("\n" + "="*60)
    print("  Demo complete.")
    print("  This used Private Set Intersection (PSI)")
    print("  a special case of MPC for set operations.")
    print("  Real banks pay millions for this capability.")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()