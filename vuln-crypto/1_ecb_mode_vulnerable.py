#!/usr/bin/env python3
"""
취약점: ECB (Electronic Codebook) 모드 사용
문제: 동일한 평문 블록이 동일한 암호문 블록을 생성하여 패턴이 노출됨
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# 고정된 비밀 키 (실제로는 절대 하드코딩하면 안됨)
SECRET_KEY = b'YELLOW_SUBMARINE'

def encrypt_data(plaintext: str) -> str:
    """ECB 모드로 데이터 암호화 (취약함)"""
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    padded = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return base64.b64encode(ciphertext).decode()

def decrypt_data(ciphertext_b64: str) -> str:
    """ECB 모드로 데이터 복호화"""
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

def encrypt_user_data(user_input: str) -> str:
    """사용자 데이터와 비밀 데이터를 함께 암호화"""
    secret_suffix = "SECRET:admin_password=SuperSecret123!"
    combined = user_input + secret_suffix
    return encrypt_data(combined)

if __name__ == "__main__":
    # 데모: 동일한 데이터가 동일한 암호문을 생성
    print("=== ECB 모드 취약점 데모 ===\n")

    # 반복되는 패턴이 암호문에서도 반복됨
    plaintext1 = "AAAAAAAAAAAAAAAA" * 3  # 16바이트 블록이 3번 반복
    ciphertext1 = encrypt_data(plaintext1)
    print(f"평문 (반복): {plaintext1[:48]}...")
    print(f"암호문: {ciphertext1}\n")

    # 다른 데이터
    plaintext2 = "Hello World!!!!!"
    ciphertext2 = encrypt_data(plaintext2)
    print(f"평문: {plaintext2}")
    print(f"암호문: {ciphertext2}\n")

    # 사용자 입력과 비밀 데이터
    user_input = "username=attacker"
    encrypted = encrypt_user_data(user_input)
    print(f"사용자 입력: {user_input}")
    print(f"암호화된 결과: {encrypted}")
