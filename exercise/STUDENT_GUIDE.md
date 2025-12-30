#  암호학 실습 가이드 (학생용)

과학고 학생들을 위한 암호학 실습 가이드입니다.

##  실습 개요

이 실습에서는 Python을 사용하여 현대 암호학의 핵심 개념들을 직접 구현해봅니다:
1. **RSA 전자서명** - 디지털 서명의 원리 이해
2. **RSA 파일 암호화** - 하이브리드 암호화 시스템 구현

##  학습 목표

- 공개키 암호화의 개념 이해
- 디지털 서명의 생성과 검증 원리 학습
- 하이브리드 암호화 시스템 이해
- Python 암호화 라이브러리 사용법 익히기

## 🔧 준비사항

### 1. Python 라이브러리 설치

```bash
pip install cryptography
```

### 2. 파일 구조 확인

```
exercise/
├── 1_rsa_signature.py          # RSA 전자서명 실습
├── 2_rsa_file_encryption.py    # RSA 파일 암호화 실습
├── STUDENT_GUIDE.md            # 이 파일
└── README.md                   # 전체 설명
```

##  실습 1: RSA 전자서명 (`1_rsa_signature.py`)

### 목표
RSA 전자서명의 생성, 검증, 그리고 변조 탐지를 직접 구현합니다.

### TODO 리스트

#### 1️⃣ `generate_rsa_keypair()` 함수
**할 일:** RSA 키 쌍을 생성하세요.

```python
# TODO 1: 개인키 생성
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=key_size,
    backend=default_backend()
)

# TODO 2: 공개키 추출
public_key = private_key.public_key()
```

**힌트:**
- `rsa.generate_private_key()`: RSA 개인키를 생성하는 함수
- `public_exponent=65537`: 일반적으로 사용되는 공개 지수 (2^16 + 1)
- `.public_key()`: 개인키에서 공개키를 추출하는 메서드

#### 2️⃣ `sign_message()` 함수
**할 일:** 메시지에 디지털 서명을 생성하세요.

```python
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

**힌트:**
- PSS: Probabilistic Signature Scheme (확률적 서명 방식)
- MGF1: Mask Generation Function
- SHA-256: 해시 알고리즘

#### 3️⃣ `verify_signature()` 함수
**할 일:** 서명을 검증하세요.

```python
public_key.verify(
    signature,
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

**힌트:**
- 서명 검증이 실패하면 Exception이 발생합니다
- try-except로 예외를 처리하여 True/False를 반환합니다

#### 4️⃣ `main()` 함수
**할 일:** 메시지를 변조하여 서명 검증이 실패하는 것을 확인하세요.

```python
# 변조된 메시지 생성
tampered_message = b"This is a MODIFIED message."

# 변조된 서명 생성
tampered_signature = bytearray(signature)
tampered_signature[0] ^= 0xFF  # 첫 바이트 XOR 연산
```

**힌트:**
- `bytearray()`: bytes를 수정 가능한 배열로 변환
- `^= 0xFF`: XOR 연산자 (비트 반전)

### 실행 방법

```bash
cd exercise
python3 1_rsa_signature.py
```

### 예상 출력

```
============================================================
RSA Digital Signature Exercise
============================================================

[*] Generating RSA key pair (2048 bits)...
[+] Key pair generated successfully!

[*] Original message: This is a test message for RSA digital signature.

[*] Signing message (length: 49 bytes)...
[+] Signature created (length: 256 bytes)

--- Test 1: Verify with correct message ---
[*] Verifying signature...
[+] Signature is VALID!

--- Test 2: Verify with tampered message ---
[*] Verifying signature...
[-] Signature is INVALID

--- Test 3: Verify with tampered signature ---
[*] Verifying signature...
[-] Signature is INVALID
```

---

## 📝 실습 2: RSA 파일 암호화 (`2_rsa_file_encryption.py`)

### 목표
하이브리드 암호화 시스템을 구현하여 파일을 안전하게 암호화하고 복호화합니다.

### 하이브리드 암호화란?

```
[큰 파일] --AES--> [암호화된 파일]
    ↓
[AES 키] --RSA--> [암호화된 AES 키]
```

- **AES**: 빠른 대칭키 암호화로 파일 암호화
- **RSA**: 느리지만 안전한 공개키 암호화로 AES 키 암호화

### TODO 리스트

#### 1️⃣ `encrypt_file_hybrid()` 함수

**TODO 1: 파일 읽기**
```python
with open(input_file, "rb") as f:
    plaintext = f.read()
```

**TODO 2: AES 키 생성**
```python
aes_key = os.urandom(32)  # 256-bit
iv = os.urandom(16)       # 128-bit IV
```

**TODO 3: AES 암호화**
```python
cipher = Cipher(
    algorithms.AES(aes_key),
    modes.CBC(iv),
    backend=default_backend()
)
ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
```

**TODO 4: RSA로 AES 키 암호화**
```python
encrypted_key = public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
```

#### 2️⃣ `decrypt_file_hybrid()` 함수

**TODO 1: RSA로 AES 키 복호화**
```python
aes_key = private_key.decrypt(
    encrypted_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
```

**TODO 2: AES 복호화**
```python
cipher = Cipher(
    algorithms.AES(aes_key),
    modes.CBC(iv),
    backend=default_backend()
)
padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
```

#### 3️⃣ `main()` 함수

**TODO: 파일 이름 설정**
```python
original_file = "sample.txt"
encrypted_file = "sample.txt.enc"
decrypted_file = "sample_decrypted.txt"
```

### 실행 방법

```bash
cd exercise
python3 2_rsa_file_encryption.py
```

### 예상 출력

```
============================================================
RSA File Encryption/Decryption Exercise
============================================================

[*] Generating RSA key pair (2048 bits)...
[+] Key pair generated successfully!

[+] Keys saved: rsa_file_private.pem, rsa_file_public.pem

[+] Sample file created: sample.txt (2048 bytes)

--- Encryption ---
[*] Encrypting file: sample.txt
    File size: 2048 bytes
    Generated AES-256 key and IV
    File encrypted with AES-256-CBC
    AES key encrypted with RSA-OAEP
[+] File encrypted successfully: sample.txt.enc
    Output size: 2340 bytes

--- Decryption ---
[*] Decrypting file: sample.txt.enc
    File size: 2340 bytes
    AES key decrypted with RSA-OAEP
    File decrypted with AES-256-CBC
[+] File decrypted successfully: sample_decrypted.txt
    Output size: 2048 bytes

--- Verification ---
[+] Files match! Decryption successful.
```

---

##  주요 개념 정리

### RSA (Rivest-Shamir-Adleman)
- **공개키 암호화**: 공개키로 암호화, 개인키로 복호화
- **전자서명**: 개인키로 서명, 공개키로 검증
- **키 크기**: 2048-bit 이상 권장

### AES (Advanced Encryption Standard)
- **대칭키 암호화**: 같은 키로 암호화/복호화
- **블록 크기**: 128-bit (16 bytes)
- **키 크기**: 128, 192, 256-bit

### 패딩 (Padding)
- **PSS**: RSA 서명에 사용
- **OAEP**: RSA 암호화에 사용
- **PKCS#7**: AES 블록 암호화에 사용

### 해시 함수
- **SHA-256**: 임의 길이 데이터를 256-bit로 압축
- **용도**: 무결성 검증, 디지털 서명

##  자주 하는 질문

### Q1: `None`은 왜 에러가 발생하나요?
**A:** TODO 부분을 아직 채우지 않아서입니다. 힌트를 참고하여 적절한 코드를 작성하세요.

### Q2: 암호화와 서명의 차이는?
**A:**
- **암호화**: 데이터를 숨김 (기밀성)
- **서명**: 데이터의 출처와 무결성 보장

### Q3: 왜 하이브리드 암호화를 사용하나요?
**A:** RSA는 느리고 큰 데이터 암호화가 어렵습니다. AES는 빠르지만 키 교환이 어렵습니다. 둘을 결합하면 장점만 취할 수 있습니다.

### Q4: 실제 프로덕션에서도 이렇게 사용하나요?
**A:** 기본 원리는 같지만, 실제로는 더 복잡한 키 관리, 인증서, 프로토콜(TLS/SSL) 등이 사용됩니다.

##  참고 자료

- [Python Cryptography 공식 문서](https://cryptography.io/)
- [RSA 알고리즘 설명](https://ko.wikipedia.org/wiki/RSA_%EC%95%94%ED%98%B8)
- [AES 알고리즘 설명](https://ko.wikipedia.org/wiki/%EA%B3%A0%EA%B8%89_%EC%95%94%ED%98%B8%ED%99%94_%ED%91%9C%EC%A4%80)

##  추가 도전 과제

1. **키 크기 변경**: RSA 키를 4096-bit로 변경하고 성능 차이를 측정해보세요.
2. **다른 해시 함수**: SHA-256 대신 SHA-512를 사용해보세요.
3. **다른 AES 모드**: CBC 대신 GCM 모드를 사용해보세요.
4. **큰 파일 테스트**: 10MB 이상의 파일로 암호화 성능을 테스트해보세요.

## ⚠️ 주의사항

1. 이 코드는 **교육 목적**입니다.
2. 실제 프로덕션에서는 **검증된 라이브러리**와 **프로토콜**을 사용하세요.
3. **개인키는 절대 공유하지 마세요**.
4. 암호화 키는 **안전하게 보관**하세요.

---

**Happy Coding! **
