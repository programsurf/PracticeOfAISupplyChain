#!/bin/bash
# 취약한 암호화 데모 - 자동 설치 스크립트 (비대화식)

echo "========================================"
echo "취약한 암호화 데모 - 자동 환경 설정"
echo "========================================"
echo ""

# 스크립트 디렉토리로 이동
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Python 버전 확인
echo "[1/3] Python 버전 확인..."
if command -v python3 &> /dev/null; then
    PYTHON_CMD=python3
    PYTHON_VERSION=$(python3 --version)
    echo "✓ Python 발견: $PYTHON_VERSION"
else
    echo "✗ Python 3가 설치되어 있지 않습니다!"
    echo ""
    echo "설치 방법:"
    echo "  Ubuntu/Debian: sudo apt install python3"
    echo "  RHEL/CentOS:   sudo yum install python3"
    echo "  macOS:         brew install python3"
    exit 1
fi

# pip 확인
echo ""
echo "[2/3] pip 확인..."
if command -v pip3 &> /dev/null; then
    PIP_CMD=pip3
    echo "✓ pip3 발견"
else
    echo "✗ pip이 설치되어 있지 않습니다!"
    echo ""
    echo "설치 방법:"
    echo "  Ubuntu/Debian: sudo apt install python3-pip"
    echo "  RHEL/CentOS:   sudo yum install python3-pip"
    exit 1
fi

# 의존성 설치
echo ""
echo "[3/3] Python 패키지 설치 중..."
echo "  - pycryptodome (암호화 라이브러리)"
echo ""

# 자동으로 --break-system-packages 사용
echo "설치 진행 중... (--break-system-packages 사용)"
$PIP_CMD install --break-system-packages pycryptodome 2>&1 | grep -E "(Successfully|already satisfied|Requirement already)" || {
    echo ""
    echo "⚠️  설치 실패. 대안 방법 시도..."
    echo ""

    # 시스템 패키지로 설치 시도 안내
    if command -v apt &> /dev/null; then
        echo "다음 명령어로 시스템 패키지를 설치하세요:"
        echo "  sudo apt install python3-pycryptodome"
    elif command -v yum &> /dev/null; then
        echo "다음 명령어로 시스템 패키지를 설치하세요:"
        echo "  sudo yum install python3-pycryptodome"
    else
        echo "수동 설치가 필요합니다:"
        echo "  pip3 install --break-system-packages pycryptodome"
    fi
    exit 1
}

# 설치 확인
echo ""
echo "설치 확인 중..."
$PYTHON_CMD -c "from Crypto.Cipher import AES; print('✓ pycryptodome 설치 확인')" 2>/dev/null || {
    echo ""
    echo "⚠️  기본 경로에서 확인 실패. PATH 확인..."
    export PATH="$HOME/.local/bin:$PATH"
    $PYTHON_CMD -c "from Crypto.Cipher import AES; print('✓ pycryptodome 설치 확인')" || {
        echo ""
        echo "✗ pycryptodome 설치 실패"
        echo ""
        echo "다음 방법을 시도해보세요:"
        echo "1. 시스템 패키지 설치:"
        echo "   sudo apt install python3-pycryptodome  # Ubuntu/Debian"
        echo ""
        echo "2. 가상 환경 사용:"
        echo "   python3 -m venv venv"
        echo "   source venv/bin/activate"
        echo "   pip install pycryptodome"
        exit 1
    }
}

echo ""
echo "========================================"
echo "✓ 환경 설정 완료!"
echo "========================================"
echo ""
echo "모든 의존성이 설치되었습니다."
echo ""
echo "다음 명령어로 데모를 실행할 수 있습니다:"
echo "  python3 1_ecb_mode_vulnerable.py"
echo "  python3 1_ecb_mode_exploit.py"
echo "  python3 run_all_demos.py"
echo ""
echo "모든 스크립트 목록:"
echo "  - 1_ecb_mode_vulnerable.py / 1_ecb_mode_exploit.py"
echo "  - 2_iv_reuse_vulnerable.py / 2_iv_reuse_exploit.py"
echo "  - 3_padding_oracle_vulnerable.py / 3_padding_oracle_exploit.py"
echo "  - 4_weak_random_vulnerable.py / 4_weak_random_exploit.py"
echo "  - 5_timing_attack_vulnerable.py / 5_timing_attack_exploit.py"
echo ""
