# 암호화 보안 치트 시트 (Cheat Sheet)

## 🚫 절대 하지 말아야 할 것들

### ❌ ECB 모드 사용
```python
# 나쁜 예
cipher = AES.new(key, AES.MODE_ECB)
```

### ❌ 고정된 IV 사용
```python
# 나쁜 예
FIXED_IV = b'1234567890123456'
cipher = AES.new(key, AES.MODE_CBC, FIXED_IV)
```

### ❌ random 모듈로 암호학적 데이터 생성
```python
# 나쁜 예
import random
random.seed(time.time())
key = bytes([random.randint(0, 255) for _ in range(16)])
```

### ❌ 직접 비교로 토큰/키 검증
```python
# 나쁜 예
if provided_token == expected_token:
    return True
```

### ❌ 패딩 오류 구분하여 반환
```python
# 나쁜 예
try:
    plaintext = unpad(data, 16)
    return True, "Success"
except ValueError:
    return False, "Padding Error"  # 정보 유출!
```

---

## ✅ 올바른 방법

### 1. 안전한 대칭 암호화 (간단한 방법)

```python
from cryptography.fernet import Fernet

# 키 생성
key = Fernet.generate_key()
cipher = Fernet(key)

# 암호화
ciphertext = cipher.encrypt(b"secret message")

# 복호화
plaintext = cipher.decrypt(ciphertext)
```

### 2. AES-GCM (인증된 암호화)

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# 키 생성
key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)

# 암호화 (Nonce는 매번 랜덤하게)
nonce = os.urandom(12)  # GCM 권장 nonce 크기
ciphertext = aesgcm.encrypt(nonce, b"message", b"associated_data")

# 복호화 (인증 자동 검증)
plaintext = aesgcm.decrypt(nonce, ciphertext, b"associated_data")
```

### 3. AES-CBC (올바른 방법)

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# 암호화
key = get_random_bytes(16)
iv = get_random_bytes(16)  # 매번 새로운 IV!
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

# IV와 암호문 함께 저장
data = iv + ciphertext

# 복호화
iv = data[:16]
ciphertext = data[16:]
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
```

### 4. 안전한 난수 생성

```python
import secrets
import os

# 토큰 생성
token = secrets.token_hex(32)  # 64자 hex 문자열
token_bytes = secrets.token_bytes(32)  # 32바이트
token_url = secrets.token_urlsafe(32)  # URL 안전한 토큰

# 바이트 생성
random_bytes = os.urandom(32)

# 암호화 키 생성
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=os.urandom(16),
    iterations=100000,
)
key = kdf.derive(password.encode())
```

### 5. 상수 시간 비교

```python
import hmac

# 토큰 비교
def verify_token(expected, provided):
    return hmac.compare_digest(expected, provided)

# 해시 비교
def verify_password_hash(expected_hash, provided_hash):
    return hmac.compare_digest(expected_hash, provided_hash)
```

### 6. HMAC (메시지 인증)

```python
import hmac
import hashlib

# HMAC 생성
secret_key = b'secret_key'
message = b'message'
mac = hmac.new(secret_key, message, hashlib.sha256).digest()

# HMAC 검증
def verify_hmac(message, mac, secret_key):
    expected_mac = hmac.new(secret_key, message, hashlib.sha256).digest()
    return hmac.compare_digest(mac, expected_mac)
```

### 7. 비밀번호 해싱

```python
from argon2 import PasswordHasher

# Argon2 (현재 가장 권장되는 방법)
ph = PasswordHasher()

# 해시 생성
hash = ph.hash("password")

# 검증
try:
    ph.verify(hash, "password")
    print("올바른 비밀번호")
except:
    print("잘못된 비밀번호")

# 또는 bcrypt
import bcrypt

# 해시 생성
hash = bcrypt.hashpw(b"password", bcrypt.gensalt())

# 검증
if bcrypt.checkpw(b"password", hash):
    print("올바른 비밀번호")
```

---

## 📋 보안 체크리스트

### 암호화 구현 전

- [ ] 어떤 데이터를 보호하려는가? (기밀성, 무결성, 인증)
- [ ] 키를 어떻게 관리할 것인가?
- [ ] 검증된 라이브러리를 사용하는가?

### 암호화 모드 선택

- [ ] 인증이 필요한가? → GCM, EAX, ChaCha20-Poly1305
- [ ] 스트리밍이 필요한가? → CTR, GCM
- [ ] ECB는 절대 사용하지 않는다!

### IV/Nonce

- [ ] 매번 랜덤하게 생성하는가?
- [ ] 암호학적으로 안전한 난수 생성기를 사용하는가?
- [ ] IV를 암호문과 함께 저장하는가?

### 난수 생성

- [ ] `secrets` 또는 `os.urandom()` 사용
- [ ] `random` 모듈은 절대 사용하지 않는다!
- [ ] 시간 기반 시드는 사용하지 않는다!

### 비교 연산

- [ ] 토큰/키 비교 시 `hmac.compare_digest()` 사용
- [ ] 타이밍 공격을 고려했는가?

### 오류 처리

- [ ] 모든 오류에 동일한 메시지 반환
- [ ] 패딩 오류를 구분하지 않는다!
- [ ] 타이밍을 일정하게 유지

### 키 관리

- [ ] 하드코딩 금지!
- [ ] 환경 변수 또는 안전한 저장소 사용
- [ ] 키 로테이션 계획이 있는가?

---

## 🛡️ 권장 라이브러리

### Python

1. **cryptography** (가장 권장)
   - Fernet (간단한 대칭 암호화)
   - AESGCM (인증된 암호화)
   - 다양한 암호화 프리미티브

2. **PyCryptodome** (교육용/호환성)
   - Crypto.Cipher
   - 다양한 암호화 알고리즘

3. **PyNaCl** (libsodium 바인딩)
   - 사용하기 쉬운 고수준 API
   - 현대적인 암호화

### 비밀번호 해싱

- **argon2-cffi** (최우선 권장)
- **bcrypt**
- ❌ ~~hashlib.md5/sha1~~ (비밀번호에는 사용 금지!)

---

## 🔗 빠른 참조

### 데이터 암호화가 필요할 때

```python
# 가장 간단한 방법
from cryptography.fernet import Fernet
key = Fernet.generate_key()
f = Fernet(key)
encrypted = f.encrypt(b"data")
decrypted = f.decrypt(encrypted)
```

### 토큰 생성이 필요할 때

```python
import secrets
token = secrets.token_urlsafe(32)
```

### 비밀번호 저장이 필요할 때

```python
from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash(password)
# 저장: hash
# 검증: ph.verify(hash, password)
```

### 데이터 무결성 검증이 필요할 때

```python
import hmac
import hashlib
mac = hmac.new(key, message, hashlib.sha256).digest()
# 검증: hmac.compare_digest(mac, received_mac)
```

---

## 📚 더 배우기

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Python Cryptography Documentation](https://cryptography.io/)
- [Libsodium Documentation](https://doc.libsodium.org/)
- [CryptoPals Challenges](https://cryptopals.com/)

---

**원칙**: 직접 구현하지 말고, 검증된 라이브러리의 고수준 API를 사용하라!
