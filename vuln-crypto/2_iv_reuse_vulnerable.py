#!/usr/bin/env python3
"""
취약점: IV (Initialization Vector) 재사용
문제: CBC 모드에서 같은 IV를 재사용하면 평문 간의 관계가 노출됨
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

SECRET_KEY = b'SIXTEEN_BYTE_KEY'
FIXED_IV = b'FIXED_IV_16BYTES'  # 고정된 IV (취약!)

def encrypt_with_reused_iv(plaintext: str) -> str:
    """고정된 IV로 암호화 (취약함)"""
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, FIXED_IV)
    padded = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return base64.b64encode(ciphertext).decode()

def decrypt_with_iv(ciphertext_b64: str) -> str:
    """복호화"""
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, FIXED_IV)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

class VulnerableMessageSystem:
    """취약한 메시지 시스템"""

    def encrypt_message(self, message: str) -> str:
        """항상 같은 IV로 메시지 암호화"""
        return encrypt_with_reused_iv(message)

    def send_secure_message(self, user_id: str, amount: int) -> str:
        """보안 메시지 전송 (하지만 IV를 재사용함)"""
        message = f"user_id:{user_id}|amount:{amount}|timestamp:1234567890"
        return self.encrypt_message(message)

if __name__ == "__main__":
    print("=== IV 재사용 취약점 데모 ===\n")

    system = VulnerableMessageSystem()

    # 여러 메시지를 같은 IV로 암호화
    msg1 = "Transfer 1000 won to Alice"
    msg2 = "Transfer 2000 won to Alice"
    msg3 = "Transfer 1000 won to Bob  "  # 같은 길이로 맞춤

    enc1 = system.encrypt_message(msg1)
    enc2 = system.encrypt_message(msg2)
    enc3 = system.encrypt_message(msg3)

    print(f"메시지 1: {msg1}")
    print(f"암호문 1: {enc1}\n")

    print(f"메시지 2: {msg2}")
    print(f"암호문 2: {enc2}\n")

    print(f"메시지 3: {msg3}")
    print(f"암호문 3: {enc3}\n")

    # 보안 메시지 예시
    secure_msg1 = system.send_secure_message("user123", 1000)
    secure_msg2 = system.send_secure_message("user123", 5000)

    print(f"보안 메시지 1 (user123, 1000원): {secure_msg1}")
    print(f"보안 메시지 2 (user123, 5000원): {secure_msg2}")
