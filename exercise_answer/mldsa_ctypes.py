#!/usr/bin/env python3
"""
ML-DSA (Dilithium) using ctypes Exercise
ctypes를 이용한 ML-DSA 전자서명 실습
"""

import ctypes
import os
from pathlib import Path


# ML-DSA-44 파라미터
MLDSA44_PUBLICKEYBYTES = 1312
MLDSA44_SECRETKEYBYTES = 2560
MLDSA44_BYTES = 2420


class MLDSA44:
    """ML-DSA-44 wrapper using ctypes"""

    def __init__(self, lib_path=None):
        """
        Initialize ML-DSA-44 library

        Args:
            lib_path: Path to libmldsa44.so (default: ../ML-DSA/crypto_sign/ml-dsa-44/1_clean/libmldsa44.so)
        """
        if lib_path is None:
            # 기본 경로 설정
            current_dir = Path(__file__).parent
            lib_path = current_dir.parent / "ML-DSA" / "crypto_sign" / "ml-dsa-44" / "1_clean" / "libmldsa44.so"

        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"ML-DSA library not found: {lib_path}")

        print(f"[*] Loading ML-DSA library from: {lib_path}")
        self.lib = ctypes.CDLL(str(lib_path))

        # 함수 시그니처 설정
        # int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
        self.lib.crypto_sign_keypair.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8)
        ]
        self.lib.crypto_sign_keypair.restype = ctypes.c_int

        # int crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
        self.lib.crypto_sign_signature.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8)
        ]
        self.lib.crypto_sign_signature.restype = ctypes.c_int

        # int crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
        self.lib.crypto_sign_verify.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8)
        ]
        self.lib.crypto_sign_verify.restype = ctypes.c_int

        print("[+] ML-DSA library loaded successfully!")

    def keypair(self):
        """
        Generate ML-DSA-44 key pair

        Returns:
            (public_key, secret_key) as bytes
        """
        print("[*] Generating ML-DSA-44 key pair...")

        # 버퍼 생성
        pk = (ctypes.c_uint8 * MLDSA44_PUBLICKEYBYTES)()
        sk = (ctypes.c_uint8 * MLDSA44_SECRETKEYBYTES)()

        # 키 생성
        ret = self.lib.crypto_sign_keypair(pk, sk)

        if ret != 0:
            raise RuntimeError(f"Key generation failed with code: {ret}")

        print(f"[+] Key pair generated!")
        print(f"    Public key size: {MLDSA44_PUBLICKEYBYTES} bytes")
        print(f"    Secret key size: {MLDSA44_SECRETKEYBYTES} bytes")

        return bytes(pk), bytes(sk)

    def sign(self, message, secret_key):
        """
        Sign a message with ML-DSA-44

        Args:
            message: Message to sign (bytes)
            secret_key: Secret key (bytes)

        Returns:
            signature (bytes)
        """
        print(f"[*] Signing message (length: {len(message)} bytes)...")

        if len(secret_key) != MLDSA44_SECRETKEYBYTES:
            raise ValueError(f"Invalid secret key size: {len(secret_key)}")

        # 버퍼 생성
        sig = (ctypes.c_uint8 * MLDSA44_BYTES)()
        siglen = ctypes.c_size_t(0)

        # 메시지를 ctypes 배열로 변환
        m = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
        sk = (ctypes.c_uint8 * MLDSA44_SECRETKEYBYTES).from_buffer_copy(secret_key)

        # 서명 생성
        ret = self.lib.crypto_sign_signature(sig, ctypes.byref(siglen), m, len(message), sk)

        if ret != 0:
            raise RuntimeError(f"Signing failed with code: {ret}")

        print(f"[+] Signature created (length: {siglen.value} bytes)")

        return bytes(sig[:siglen.value])

    def verify(self, signature, message, public_key):
        """
        Verify a signature with ML-DSA-44

        Args:
            signature: Signature to verify (bytes)
            message: Original message (bytes)
            public_key: Public key (bytes)

        Returns:
            True if valid, False otherwise
        """
        print("[*] Verifying signature...")

        if len(public_key) != MLDSA44_PUBLICKEYBYTES:
            raise ValueError(f"Invalid public key size: {len(public_key)}")

        # ctypes 배열로 변환
        sig = (ctypes.c_uint8 * len(signature)).from_buffer_copy(signature)
        m = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
        pk = (ctypes.c_uint8 * MLDSA44_PUBLICKEYBYTES).from_buffer_copy(public_key)

        # 서명 검증
        ret = self.lib.crypto_sign_verify(sig, len(signature), m, len(message), pk)

        if ret == 0:
            print("[+] Signature is VALID!")
            return True
        else:
            print(f"[-] Signature is INVALID (code: {ret})")
            return False


def save_keys(public_key, secret_key, prefix="mldsa_key"):
    """키를 파일로 저장"""
    with open(f"{prefix}_public.bin", "wb") as f:
        f.write(public_key)

    with open(f"{prefix}_secret.bin", "wb") as f:
        f.write(secret_key)

    print(f"[+] Keys saved: {prefix}_public.bin, {prefix}_secret.bin")


def main():
    print("=" * 60)
    print("ML-DSA-44 Digital Signature Exercise (using ctypes)")
    print("=" * 60)
    print()

    try:
        # 1. ML-DSA 라이브러리 로드
        mldsa = MLDSA44()
        print()

        # 2. 키 생성
        public_key, secret_key = mldsa.keypair()
        print()

        # 3. 테스트 메시지
        message = b"This is a test message for ML-DSA-44 digital signature."
        print(f"[*] Original message: {message.decode()}")
        print()

        # 4. 서명 생성
        signature = mldsa.sign(message, secret_key)
        print()

        # 5. 서명 검증 (올바른 메시지)
        print("--- Test 1: Verify with correct message ---")
        mldsa.verify(signature, message, public_key)
        print()

        # 6. 서명 검증 (변조된 메시지)
        print("--- Test 2: Verify with tampered message ---")
        tampered_message = b"This is a MODIFIED message."
        mldsa.verify(signature, tampered_message, public_key)
        print()

        # 7. 서명 검증 (변조된 서명)
        print("--- Test 3: Verify with tampered signature ---")
        tampered_signature = bytearray(signature)
        tampered_signature[0] ^= 0xFF  # 첫 바이트 변조
        mldsa.verify(bytes(tampered_signature), message, public_key)
        print()

        # 8. 키 저장
        save_keys(public_key, secret_key, "mldsa")
        print()

        print("=" * 60)
        print("Exercise completed!")
        print("=" * 60)

    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
