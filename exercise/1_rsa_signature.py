#!/usr/bin/env python3
"""
RSA Digital Signature Exercise
RSA 전자서명 (keygen, sign, verify) 실습
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


def generate_rsa_keypair(key_size=2048):
    """
    RSA 키 쌍 생성

    Args:
        key_size: 키 크기 (기본값: 2048 bits)

    Returns:
        (private_key, public_key) tuple
    """
    print(f"[*] Generating RSA key pair ({key_size} bits)...")

    # TODO: rsa.generate_private_key() 함수를 사용하여 개인키를 생성하세요
    # 힌트: public_exponent=65537, key_size=key_size, backend=default_backend()
    private_key = None  # 여기를 수정하세요

    # TODO: 개인키로부터 공개키를 추출하세요
    # 힌트: private_key.public_key() 메서드를 사용하세요
    public_key = None  # 여기를 수정하세요

    print("[+] Key pair generated successfully!")
    return private_key, public_key


def sign_message(private_key, message):
    """
    메시지에 RSA 서명 생성

    Args:
        private_key: RSA 개인키
        message: 서명할 메시지 (bytes)

    Returns:
        signature (bytes)
    """
    print(f"[*] Signing message (length: {len(message)} bytes)...")

    # TODO: private_key.sign() 메서드를 사용하여 메시지에 서명하세요
    # 힌트: 첫 번째 인자는 message
    # 힌트: 두 번째 인자는 padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    # 힌트: 세 번째 인자는 hashes.SHA256()
    signature = None  # 여기를 수정하세요

    print(f"[+] Signature created (length: {len(signature)} bytes)")
    return signature


def verify_signature(public_key, message, signature):
    """
    RSA 서명 검증

    Args:
        public_key: RSA 공개키
        message: 원본 메시지 (bytes)
        signature: 서명 (bytes)

    Returns:
        True if valid, False otherwise
    """
    print("[*] Verifying signature...")

    try:
        # TODO: public_key.verify() 메서드를 사용하여 서명을 검증하세요
        # 힌트: 첫 번째 인자는 signature
        # 힌트: 두 번째 인자는 message
        # 힌트: 세 번째 인자는 padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
        # 힌트: 네 번째 인자는 hashes.SHA256()
        pass  # 여기에 코드를 작성하세요

        print("[+] Signature is VALID!")
        return True
    except Exception as e:
        print(f"[-] Signature is INVALID: {e}")
        return False


def save_keys(private_key, public_key, prefix="rsa_key"):
    """
    키를 PEM 파일로 저장
    """
    # Private key 저장
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(f"{prefix}_private.pem", "wb") as f:
        f.write(private_pem)

    # Public key 저장
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(f"{prefix}_public.pem", "wb") as f:
        f.write(public_pem)

    print(f"[+] Keys saved: {prefix}_private.pem, {prefix}_public.pem")


def main():
    print("=" * 60)
    print("RSA Digital Signature Exercise")
    print("=" * 60)
    print()

    # 1. 키 생성
    private_key, public_key = generate_rsa_keypair(2048)
    print()

    # 2. 테스트 메시지
    message = b"This is a test message for RSA digital signature."
    print(f"[*] Original message: {message.decode()}")
    print()

    # 3. 서명 생성
    signature = sign_message(private_key, message)
    print()

    # 4. 서명 검증 (올바른 메시지)
    print("--- Test 1: Verify with correct message ---")
    verify_signature(public_key, message, signature)
    print()

    # 5. 서명 검증 (변조된 메시지)
    print("--- Test 2: Verify with tampered message ---")
    # TODO: 변조된 메시지를 만드세요 (예: b"This is a MODIFIED message.")
    tampered_message = None  # 여기를 수정하세요
    verify_signature(public_key, tampered_message, signature)
    print()

    # 6. 서명 검증 (변조된 서명)
    print("--- Test 3: Verify with tampered signature ---")
    # TODO: 서명을 변조하세요
    # 힌트: bytearray(signature)로 변환 후 첫 번째 바이트를 XOR 연산 (^= 0xFF)으로 변조
    tampered_signature = None  # 여기를 수정하세요
    verify_signature(public_key, message, bytes(tampered_signature))
    print()

    # 7. 키 저장
    save_keys(private_key, public_key, "rsa_sig")
    print()

    print("=" * 60)
    print("Exercise completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
