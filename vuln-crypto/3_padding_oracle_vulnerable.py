#!/usr/bin/env python3
"""
취약점: Padding Oracle
문제: 패딩 검증 오류를 다르게 처리하여 공격자가 복호화를 수행할 수 있음
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

SECRET_KEY = b'SECRET_KEY_16BYT'

def encrypt(plaintext: str) -> tuple:
    """데이터를 CBC 모드로 암호화"""
    iv = get_random_bytes(16)
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_vulnerable(ciphertext_b64: str) -> tuple:
    """
    취약한 복호화 함수
    패딩 오류를 명시적으로 알려줌 (보안 취약점!)

    Returns:
        (success: bool, message: str, plaintext: str or None)
    """
    try:
        data = base64.b64decode(ciphertext_b64)
        iv = data[:16]
        ciphertext = data[16:]

        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)

        # 패딩 검증 (취약점: 오류 타입을 구분하여 반환)
        try:
            plaintext = unpad(padded_plaintext, AES.block_size)
            return (True, "Success", plaintext.decode())
        except ValueError as e:
            # 패딩 오류를 명시적으로 반환 (취약!)
            return (False, "Padding Error", None)

    except Exception as e:
        # 다른 오류
        return (False, f"Decryption Error: {str(e)}", None)

class VulnerableAuthSystem:
    """패딩 오라클 취약점이 있는 인증 시스템"""

    def create_auth_token(self, username: str, role: str) -> str:
        """인증 토큰 생성"""
        data = f"user:{username}|role:{role}"
        return encrypt(data)

    def verify_token(self, token: str) -> dict:
        """토큰 검증 (취약함!)"""
        success, message, plaintext = decrypt_vulnerable(token)

        if not success:
            # 오류 타입을 반환하여 공격자에게 정보 제공 (취약!)
            return {"valid": False, "error": message}

        if success and plaintext:
            # 토큰 파싱
            parts = plaintext.split('|')
            user_part = parts[0].split(':')[1]
            role_part = parts[1].split(':')[1]
            return {
                "valid": True,
                "username": user_part,
                "role": role_part
            }

        return {"valid": False, "error": "Invalid token"}

if __name__ == "__main__":
    print("=== Padding Oracle 취약점 데모 ===\n")

    auth_system = VulnerableAuthSystem()

    # 정상 토큰 생성
    token = auth_system.create_auth_token("alice", "user")
    print(f"생성된 토큰: {token}\n")

    # 토큰 검증
    result = auth_system.verify_token(token)
    print(f"검증 결과: {result}\n")

    # 잘못된 토큰 테스트
    print("=== 오류 메시지 차이 (취약점) ===\n")

    # 1. 올바른 패딩, 잘못된 데이터
    fake_data = base64.b64encode(get_random_bytes(16) + get_random_bytes(32)).decode()
    result1 = auth_system.verify_token(fake_data)
    print(f"랜덤 데이터: {result1}")

    # 2. 잘못된 패딩
    data = base64.b64decode(token)
    iv = data[:16]
    ct = data[16:]
    # 마지막 바이트 변조
    ct_modified = ct[:-1] + bytes([ct[-1] ^ 0x01])
    fake_token = base64.b64encode(iv + ct_modified).decode()
    result2 = auth_system.verify_token(fake_token)
    print(f"변조된 토큰: {result2}")

    print("\n[!] 오류 메시지가 다름! 이것이 Padding Oracle 취약점입니다.")
