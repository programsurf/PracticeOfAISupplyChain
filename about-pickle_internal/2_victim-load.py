#!/usr/bin/env python3
"""
Victim Script - Demonstrates Vulnerable Model Loading
======================================================
This script simulates a victim loading an untrusted PyTorch model.
The malicious payload will execute automatically during torch.load().

Usage:
    python3 2_victim-load.py

⚠ WARNING: This script will execute the malicious payload!
"""

import torch
import os


# ============================================================================
# Configuration
# ============================================================================

MALICIOUS_MODEL = 'models_attack/small_normal_malicious.pt'


# ============================================================================
# Victim's Vulnerable Code
# ============================================================================

def load_untrusted_model():
    """
    Simulates a victim loading an untrusted model file.
    This is VULNERABLE to pickle deserialization attacks!
    """

    print("=" * 70)
    print("[VICTIM] Loading PyTorch Model")
    print("=" * 70)

    # Check if model exists
    if not os.path.exists(MALICIOUS_MODEL):
        print(f"\n[ERROR] Model file not found: {MALICIOUS_MODEL}")
        print(f"Please run attack.py first to create the malicious model.")
        return False

    model_size = os.path.getsize(MALICIOUS_MODEL)
    print(f"\nModel file: {MALICIOUS_MODEL}")
    print(f"File size: {model_size / (1024*1024):.2f} MB ({model_size:,} bytes)")

    print(f"\n[INFO] Loading model with torch.load()...")
    print(f"[INFO] weights_only=False (VULNERABLE!)")
    print()

    # ⚠ VULNERABLE CODE: torch.load() with weights_only=False
    # This allows arbitrary code execution via pickle deserialization
    print("─" * 70)
    print("EXECUTING: torch.load('{}', weights_only=False)".format(MALICIOUS_MODEL))
    print("─" * 70)
    print()

    try:
        # This will trigger the malicious payload!
        model = torch.load(MALICIOUS_MODEL, weights_only=False)

        print()
        print("─" * 70)
        print("[DANGER] Model loaded successfully")
        print("[DANGER] Malicious payload was executed during unpickling!")
        print("─" * 70)

        print(f"\nModel type: {type(model)}")
        if isinstance(model, dict) and '__malicious_payload__' in model:
            print(f"⚠ Malicious payload detected in model: {type(model['__malicious_payload__'])}")

        return True

    except Exception as e:
        print()
        print("─" * 70)
        print(f"[ERROR] Failed to load model: {e}")
        print("─" * 70)
        return False


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    print()
    print("⚠" * 35)
    print("WARNING: VULNERABLE CODE DEMONSTRATION")
    print("⚠" * 35)
    print()
    print("This script demonstrates the danger of loading untrusted PyTorch models.")
    print("The malicious payload will execute AUTOMATICALLY during model loading.")
    print()
    print("In a real attack scenario:")
    print("  1. Attacker distributes a poisoned .pt file")
    print("  2. Victim downloads and loads it with torch.load()")
    print("  3. Malicious code executes immediately (RCE)")
    print()
    print("=" * 70)

    input("Press Enter to continue with the vulnerable loading...")

    success = load_untrusted_model()

    print()
    print("=" * 70)
    if success:
        print("[DEMONSTRATION] Attack Successful!")
        print()
        print("💡 Key Takeaway:")
        print("   - NEVER use torch.load() with weights_only=False on untrusted files")
        print("   - Use weights_only=True or verify model signatures")
        print("   - This is why self-verifying models are important!")
    else:
        print("[ERROR] Demonstration failed")
    print("=" * 70)

    exit(0 if success else 1)
