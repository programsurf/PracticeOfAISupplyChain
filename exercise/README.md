# Cryptography Exercise

암호학 실습 디렉토리입니다. Python을 사용한 RSA 전자서명, ML-DSA 전자서명, RSA 파일 암호화/복호화 실습을 포함합니다.

##  실습 목록

### 1. RSA 전자서명 (rsa_signature.py)
RSA 알고리즘을 사용한 디지털 서명의 생성과 검증을 실습합니다.

**기능:**
- RSA 키 쌍 생성 (2048-bit)
- 메시지에 대한 디지털 서명 생성
- 서명 검증 (정상, 변조된 메시지, 변조된 서명)
- 키를 PEM 파일로 저장

**실행:**
```bash
# exercise 디렉토리로 이동
cd exercise

# 스크립트 실행
python3 rsa_signature.py
```

**사용 라이브러리:**
- `cryptography` (RSA, PSS padding, SHA-256)

---

### 2. ML-DSA 전자서명 (mldsa_ctypes.py)
ctypes를 사용하여 ML-DSA-44 (Dilithium) C 라이브러리를 호출하는 실습입니다.

**기능:**
- ML-DSA-44 키 쌍 생성
- 메시지에 대한 디지털 서명 생성
- 서명 검증 (정상, 변조된 메시지, 변조된 서명)
- 키를 바이너리 파일로 저장

**실행:**
```bash
# exercise 디렉토리로 이동
cd exercise

# 스크립트 실행
python3 mldsa_ctypes.py
```

**사용 라이브러리:**
- `ctypes` (C 라이브러리 인터페이스)
- ML-DSA-44 shared library (`../ML-DSA/crypto_sign/ml-dsa-44/1_clean/libmldsa44.so`)

**파라미터:**
- Public key: 1312 bytes
- Secret key: 2560 bytes
- Signature: ~2420 bytes

---

### 3. RSA 파일 암호화/복호화 (rsa_file_encryption.py)
하이브리드 암호화를 사용한 파일 암호화 및 복호화를 실습합니다.

**기능:**
- RSA 키 쌍 생성
- 하이브리드 암호화 (AES-256-CBC + RSA-OAEP)
  - AES로 파일 암호화
  - RSA로 AES 키 암호화
- 파일 복호화
- 원본과 복호화된 파일 비교

**실행:**
```bash
# exercise 디렉토리로 이동
cd exercise

# 스크립트 실행
python3 rsa_file_encryption.py
```

**사용 라이브러리:**
- `cryptography` (RSA, AES-256-CBC, OAEP padding)

**하이브리드 암호화 방식:**
1. 랜덤 AES-256 키 생성
2. AES-CBC로 파일 암호화
3. RSA-OAEP로 AES 키 암호화
4. 암호화된 키 + IV + 암호문 저장

---

##  필수 패키지 설치

```bash
pip install cryptography
```

##  생성되는 파일

실습을 실행하면 다음과 같은 파일들이 생성됩니다:

### RSA 서명 실습
- `rsa_sig_private.pem` - RSA 개인키
- `rsa_sig_public.pem` - RSA 공개키

### ML-DSA 실습
- `mldsa_public.bin` - ML-DSA 공개키
- `mldsa_secret.bin` - ML-DSA 개인키

### RSA 파일 암호화 실습
- `rsa_file_private.pem` - RSA 개인키
- `rsa_file_public.pem` - RSA 공개키
- `sample.txt` - 테스트용 원본 파일
- `sample.txt.enc` - 암호화된 파일
- `sample_decrypted.txt` - 복호화된 파일

**참고**: 모든 파일은 exercise 디렉토리 내에 생성됩니다.

## ⚠️ 주의사항

1. **교육 목적**: 이 실습들은 교육 목적으로만 사용하세요.
2. **키 보안**: 생성된 개인키 파일은 안전하게 관리하세요.
3. **실제 환경**: 실제 프로덕션 환경에서는 더 강력한 키 관리와 보안 조치가 필요합니다.
4. **ML-DSA 라이브러리**: ML-DSA 실습은 상위 디렉토리의 라이브러리를 참조합니다.

##  테스트 시나리오

각 실습 파일은 다음과 같은 테스트를 포함합니다:

1. **정상 서명/암호화 검증** - 모든 것이 올바르게 작동하는 경우
2. **메시지 변조 검증** - 메시지가 변조된 경우 (검증 실패 예상)
3. **서명 변조 검증** - 서명이 변조된 경우 (검증 실패 예상)

이를 통해 디지털 서명의 무결성 보장 특성을 확인할 수 있습니다.

##  참고 자료

- [Cryptography library documentation](https://cryptography.io/)
- [RSA PSS Signature](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/)
