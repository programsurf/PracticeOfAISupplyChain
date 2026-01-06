#!/usr/bin/env python3
"""
취약점: 타이밍 공격에 취약한 문자열 비교
문제: 문자열 비교 시 바이트별로 순차 비교하여 시간 차이가 발생
"""

import hashlib
import hmac
import time

class VulnerableAuthenticator:
    """타이밍 공격에 취약한 인증 시스템"""

    def __init__(self):
        self.secret_key = "super_secret_key_12345"
        self.valid_tokens = {}

    def generate_token(self, username: str) -> str:
        """사용자 토큰 생성"""
        data = f"{username}:{int(time.time())}"
        token = hashlib.sha256((data + self.secret_key).encode()).hexdigest()
        self.valid_tokens[username] = token
        return token

    def verify_token_vulnerable(self, username: str, provided_token: str) -> bool:
        """
        취약한 토큰 검증 (타이밍 공격 가능!)
        바이트별로 순차 비교하므로 시간 차이 발생
        """
        if username not in self.valid_tokens:
            return False

        expected_token = self.valid_tokens[username]

        # 취약한 비교: 한 글자씩 비교
        if len(provided_token) != len(expected_token):
            return False

        for i in range(len(expected_token)):
            if provided_token[i] != expected_token[i]:
                return False  # 다른 문자를 발견하면 즉시 반환
            # 실제 시스템에서는 여기서 미세한 지연이 발생할 수 있음

        return True

    def verify_token_secure(self, username: str, provided_token: str) -> bool:
        """
        안전한 토큰 검증
        상수 시간 비교 사용
        """
        if username not in self.valid_tokens:
            return False

        expected_token = self.valid_tokens[username]
        # hmac.compare_digest는 상수 시간 비교
        return hmac.compare_digest(expected_token, provided_token)

class VulnerablePasswordChecker:
    """타이밍 공격에 취약한 비밀번호 검증"""

    def __init__(self):
        # 하드코딩된 비밀번호 (예시용)
        self.password_hash = hashlib.sha256(b"MySecretPass123").hexdigest()

    def check_password_vulnerable(self, password: str) -> bool:
        """
        취약한 비밀번호 검증
        해시를 바이트별로 비교
        """
        provided_hash = hashlib.sha256(password.encode()).hexdigest()

        # 취약한 비교
        for i in range(len(self.password_hash)):
            if i >= len(provided_hash) or provided_hash[i] != self.password_hash[i]:
                return False

        return True

    def check_password_secure(self, password: str) -> bool:
        """안전한 비밀번호 검증"""
        provided_hash = hashlib.sha256(password.encode()).hexdigest()
        return hmac.compare_digest(self.password_hash, provided_hash)

class VulnerableAPIKeyValidator:
    """API 키 검증 시스템"""

    def __init__(self):
        self.valid_api_keys = {
            "user1": "abc123def456ghi789jkl",
            "user2": "xyz789uvw456rst123opq",
        }

    def validate_api_key_vulnerable(self, user: str, api_key: str) -> bool:
        """취약한 API 키 검증"""
        if user not in self.valid_api_keys:
            return False

        expected_key = self.valid_api_keys[user]

        # 직접 == 비교 (Python은 최적화되어 있지만 원칙적으로 취약)
        return api_key == expected_key

    def validate_api_key_with_delay(self, user: str, api_key: str) -> bool:
        """
        의도적인 지연이 있는 취약한 검증
        (타이밍 공격 데모용)
        """
        if user not in self.valid_api_keys:
            return False

        expected_key = self.valid_api_keys[user]

        for i in range(min(len(api_key), len(expected_key))):
            if api_key[i] != expected_key[i]:
                return False
            # 각 문자 비교마다 미세한 지연
            time.sleep(0.0001)  # 0.1ms 지연

        return len(api_key) == len(expected_key)

    def validate_api_key_secure(self, user: str, api_key: str) -> bool:
        """안전한 API 키 검증"""
        if user not in self.valid_api_keys:
            return False

        expected_key = self.valid_api_keys[user]
        return hmac.compare_digest(expected_key, api_key)

if __name__ == "__main__":
    print("=== 타이밍 공격 취약점 데모 ===\n")

    # 1. 토큰 검증
    print("1. 토큰 검증 시스템:")
    auth = VulnerableAuthenticator()
    token = auth.generate_token("alice")
    print(f"   alice의 올바른 토큰: {token}\n")

    # 취약한 검증
    test_tokens = [
        "0" * 64,  # 완전히 틀림
        token[:10] + "0" * 54,  # 앞 10자만 일치
        token[:30] + "0" * 34,  # 앞 30자만 일치
        token,  # 완전히 일치
    ]

    print("   취약한 검증 (시간 측정):")
    for test_token in test_tokens:
        start = time.perf_counter()
        result = auth.verify_token_vulnerable("alice", test_token)
        elapsed = time.perf_counter() - start
        matching_chars = sum(a == b for a, b in zip(token, test_token))
        print(f"   일치 문자: {matching_chars:2d}, 시간: {elapsed*1000000:.2f}μs, 결과: {result}")

    # 2. 지연이 있는 API 키 검증
    print("\n2. API 키 검증 (의도적 지연):")
    api_validator = VulnerableAPIKeyValidator()
    correct_key = api_validator.valid_api_keys["user1"]
    print(f"   올바른 키: {correct_key}\n")

    test_keys = [
        "x" * len(correct_key),  # 완전히 틀림
        correct_key[:5] + "x" * (len(correct_key) - 5),  # 앞 5자만 일치
        correct_key[:10] + "x" * (len(correct_key) - 10),  # 앞 10자만 일치
        correct_key,  # 완전히 일치
    ]

    print("   취약한 검증 (지연 포함):")
    for test_key in test_keys:
        start = time.perf_counter()
        result = api_validator.validate_api_key_with_delay("user1", test_key)
        elapsed = time.perf_counter() - start
        matching_chars = sum(a == b for a, b in zip(correct_key, test_key))
        print(f"   일치 문자: {matching_chars:2d}, 시간: {elapsed*1000:.2f}ms, 결과: {result}")

    print("\n[!] 일치하는 문자가 많을수록 검증 시간이 길어집니다!")
    print("    공격자는 이 시간 차이를 이용하여 비밀 값을 한 글자씩 추측할 수 있습니다.")
