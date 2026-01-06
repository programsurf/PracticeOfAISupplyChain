#!/usr/bin/env python3
"""
취약점: 약한 난수 생성기 사용
문제: 예측 가능한 난수로 암호화 키, 토큰 등을 생성
"""

import random
import time
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

class VulnerableKeyGenerator:
    """취약한 키 생성기"""

    @staticmethod
    def generate_key_weak() -> bytes:
        """
        약한 키 생성 (취약!)
        random 모듈은 암호학적으로 안전하지 않음
        """
        random.seed(int(time.time()))  # 현재 시간으로 시드 (예측 가능!)
        key_bytes = [random.randint(0, 255) for _ in range(16)]
        return bytes(key_bytes)

    @staticmethod
    def generate_session_token_weak() -> str:
        """약한 세션 토큰 생성"""
        random.seed(int(time.time()))
        token = ''.join(random.choices('0123456789abcdef', k=32))
        return token

    @staticmethod
    def generate_password_reset_token_weak(user_id: str) -> str:
        """
        약한 비밀번호 재설정 토큰
        사용자 ID와 현재 시간만으로 생성 (예측 가능!)
        """
        timestamp = int(time.time())
        data = f"{user_id}:{timestamp}"
        return hashlib.md5(data.encode()).hexdigest()

class VulnerableEncryptionService:
    """취약한 암호화 서비스"""

    def __init__(self):
        # 시작할 때마다 약한 방법으로 키 생성
        self.key = self.generate_predictable_key()

    def generate_predictable_key(self) -> bytes:
        """예측 가능한 키 생성"""
        # 현재 시간 기반 (매우 취약!)
        timestamp = int(time.time())
        random.seed(timestamp)
        return bytes([random.randint(0, 255) for _ in range(16)])

    def encrypt(self, plaintext: str) -> str:
        """데이터 암호화"""
        # IV도 약한 난수로 생성 (취약!)
        random.seed(int(time.time()) + 1)
        iv = bytes([random.randint(0, 255) for _ in range(16)])

        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded = pad(plaintext.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded)
        return base64.b64encode(iv + ciphertext).decode()

    def decrypt(self, ciphertext_b64: str) -> str:
        """데이터 복호화"""
        data = base64.b64decode(ciphertext_b64)
        iv = data[:16]
        ciphertext = data[16:]

        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode()

class VulnerableAuthService:
    """약한 난수를 사용하는 인증 서비스"""

    def __init__(self):
        self.users = {}

    def generate_api_key(self, username: str) -> str:
        """
        API 키 생성 (취약!)
        사용자 이름과 현재 시간만으로 생성
        """
        timestamp = int(time.time())
        data = f"{username}:{timestamp}"
        api_key = hashlib.sha256(data.encode()).hexdigest()
        self.users[username] = api_key
        return api_key

    def generate_otp_weak(self, user_id: str) -> str:
        """
        약한 OTP 생성
        시간 기반이지만 랜덤성이 부족
        """
        timestamp = int(time.time()) // 30  # 30초 윈도우
        random.seed(timestamp + hash(user_id))
        otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        return otp

if __name__ == "__main__":
    print("=== 약한 난수 생성 취약점 데모 ===\n")

    # 1. 약한 키 생성
    print("1. 약한 키 생성:")
    key_gen = VulnerableKeyGenerator()

    print("   현재 시간으로 키 생성 (3번 시도):")
    for i in range(3):
        key = key_gen.generate_key_weak()
        print(f"   키 {i+1}: {key.hex()}")
        time.sleep(1)

    # 2. 약한 세션 토큰
    print("\n2. 약한 세션 토큰:")
    for i in range(3):
        token = key_gen.generate_session_token_weak()
        print(f"   토큰 {i+1}: {token}")
        time.sleep(1)

    # 3. 약한 비밀번호 재설정 토큰
    print("\n3. 비밀번호 재설정 토큰 (예측 가능):")
    reset_token = key_gen.generate_password_reset_token_weak("user123")
    print(f"   user123의 토큰: {reset_token}")

    # 4. 예측 가능한 암호화
    print("\n4. 예측 가능한 키를 사용한 암호화:")
    service = VulnerableEncryptionService()
    encrypted = service.encrypt("Secret message")
    print(f"   암호문: {encrypted}")
    print(f"   사용된 키: {service.key.hex()}")

    # 5. 약한 API 키
    print("\n5. 약한 API 키 생성:")
    auth_service = VulnerableAuthService()
    api_key = auth_service.generate_api_key("alice")
    print(f"   alice의 API 키: {api_key}")

    # 6. 약한 OTP
    print("\n6. 약한 OTP:")
    otp = auth_service.generate_otp_weak("user123")
    print(f"   user123의 OTP: {otp}")
