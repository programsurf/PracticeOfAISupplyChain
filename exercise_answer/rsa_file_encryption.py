#!/usr/bin/env python3
"""
RSA File Encryption/Decryption Exercise
RSA를 사용한 파일 암호화 및 복호화 실습
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    print("[+] Key pair generated successfully!")
    return private_key, public_key


def encrypt_file_hybrid(public_key, input_file, output_file):
    """
    하이브리드 암호화를 사용한 파일 암호화
    (AES로 파일 암호화 + RSA로 AES 키 암호화)

    Args:
        public_key: RSA 공개키
        input_file: 암호화할 파일 경로
        output_file: 암호화된 파일 저장 경로
    """
    print(f"[*] Encrypting file: {input_file}")

    # 1. 파일 읽기
    with open(input_file, "rb") as f:
        plaintext = f.read()

    print(f"    File size: {len(plaintext)} bytes")

    # 2. AES 키 생성 (256-bit)
    aes_key = os.urandom(32)
    iv = os.urandom(16)

    print(f"    Generated AES-256 key and IV")

    # 3. AES로 파일 암호화 (CBC mode)
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    # 패딩 추가 (AES block size = 16 bytes)
    padding_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + bytes([padding_length] * padding_length)

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    print(f"    File encrypted with AES-256-CBC")

    # 4. RSA로 AES 키 암호화
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print(f"    AES key encrypted with RSA-OAEP")

    # 5. 암호화된 파일 저장 형식:
    # [encrypted_key_length (4 bytes)] [encrypted_key] [iv (16 bytes)] [ciphertext]
    with open(output_file, "wb") as f:
        # Encrypted key length
        f.write(len(encrypted_key).to_bytes(4, byteorder='big'))
        # Encrypted AES key
        f.write(encrypted_key)
        # IV
        f.write(iv)
        # Encrypted data
        f.write(ciphertext)

    print(f"[+] File encrypted successfully: {output_file}")
    print(f"    Output size: {os.path.getsize(output_file)} bytes")


def decrypt_file_hybrid(private_key, input_file, output_file):
    """
    하이브리드 복호화를 사용한 파일 복호화

    Args:
        private_key: RSA 개인키
        input_file: 암호화된 파일 경로
        output_file: 복호화된 파일 저장 경로
    """
    print(f"[*] Decrypting file: {input_file}")

    # 1. 암호화된 파일 읽기
    with open(input_file, "rb") as f:
        # Encrypted key length
        encrypted_key_length = int.from_bytes(f.read(4), byteorder='big')
        # Encrypted AES key
        encrypted_key = f.read(encrypted_key_length)
        # IV
        iv = f.read(16)
        # Encrypted data
        ciphertext = f.read()

    print(f"    File size: {os.path.getsize(input_file)} bytes")

    # 2. RSA로 AES 키 복호화
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print(f"    AES key decrypted with RSA-OAEP")

    # 3. AES로 파일 복호화
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    print(f"    File decrypted with AES-256-CBC")

    # 4. 패딩 제거
    padding_length = padded_plaintext[-1]
    plaintext = padded_plaintext[:-padding_length]

    # 5. 복호화된 파일 저장
    with open(output_file, "wb") as f:
        f.write(plaintext)

    print(f"[+] File decrypted successfully: {output_file}")
    print(f"    Output size: {len(plaintext)} bytes")


def save_keys(private_key, public_key, prefix="rsa_key"):
    """키를 PEM 파일로 저장"""
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


def create_sample_file(filename, size=1024):
    """테스트용 샘플 파일 생성"""
    content = f"This is a sample file for RSA encryption test.\n"
    content += f"File size: {size} bytes\n"
    content += "=" * 50 + "\n"
    content += "Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n" * 10

    # 지정된 크기까지 패딩
    while len(content) < size:
        content += "X"

    content = content[:size]

    with open(filename, "w") as f:
        f.write(content)

    print(f"[+] Sample file created: {filename} ({size} bytes)")


def verify_files_match(file1, file2):
    """두 파일이 동일한지 확인"""
    with open(file1, "rb") as f1, open(file2, "rb") as f2:
        content1 = f1.read()
        content2 = f2.read()

    if content1 == content2:
        print(f"[+] Files match! Decryption successful.")
        return True
    else:
        print(f"[-] Files do NOT match! Decryption failed.")
        return False


def main():
    print("=" * 60)
    print("RSA File Encryption/Decryption Exercise")
    print("=" * 60)
    print()

    # 파일 이름 설정
    original_file = "sample.txt"
    encrypted_file = "sample.txt.enc"
    decrypted_file = "sample_decrypted.txt"

    # 1. 키 생성
    private_key, public_key = generate_rsa_keypair(2048)
    print()

    # 2. 키 저장
    save_keys(private_key, public_key, "rsa_file")
    print()

    # 3. 샘플 파일 생성
    create_sample_file(original_file, size=2048)
    print()

    # 4. 파일 암호화
    print("--- Encryption ---")
    encrypt_file_hybrid(public_key, original_file, encrypted_file)
    print()

    # 5. 파일 복호화
    print("--- Decryption ---")
    decrypt_file_hybrid(private_key, encrypted_file, decrypted_file)
    print()

    # 6. 검증
    print("--- Verification ---")
    verify_files_match(original_file, decrypted_file)
    print()

    # 7. 파일 크기 비교
    print("--- File Size Comparison ---")
    print(f"Original:  {os.path.getsize(original_file):6d} bytes - {original_file}")
    print(f"Encrypted: {os.path.getsize(encrypted_file):6d} bytes - {encrypted_file}")
    print(f"Decrypted: {os.path.getsize(decrypted_file):6d} bytes - {decrypted_file}")
    print()

    print("=" * 60)
    print("Exercise completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
