#!/bin/bash
# 취약한 암호화 데모 - 의존성 자동 설치 스크립트

echo "========================================"
echo "취약한 암호화 데모 - 환경 설정"
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
    exit 1
fi

# 의존성 설치
echo ""
echo "[3/3] Python 패키지 설치 중..."
echo "  - pycryptodome (암호화 라이브러리)"
echo ""

# 설치 방법 선택
echo "설치 방법을 선택하세요:"
echo "  1) --user (사용자 레벨 설치, 권장)"
echo "  2) --break-system-packages (시스템 레벨, 주의 필요)"
echo ""
read -p "선택 [1/2] (기본값: 1): " choice
choice=${choice:-1}

if [ "$choice" = "1" ]; then
    echo ""
    echo "사용자 레벨로 설치 중..."
    $PIP_CMD install --user pycryptodome
elif [ "$choice" = "2" ]; then
    echo ""
    echo "⚠️  시스템 레벨로 설치 중... (주의: 시스템 Python에 영향)"
    $PIP_CMD install --break-system-packages pycryptodome
else
    echo "잘못된 선택입니다."
    exit 1
fi

# 설치 확인
echo ""
echo "설치 확인 중..."
$PYTHON_CMD -c "from Crypto.Cipher import AES; print('✓ pycryptodome 설치 확인')" 2>/dev/null || {
    echo ""
    echo "⚠️  기본 경로에서 확인 실패. PATH 확인..."
    export PATH="$HOME/.local/bin:$PATH"
    $PYTHON_CMD -c "from Crypto.Cipher import AES; print('✓ pycryptodome 설치 확인')" || {
        echo "✗ pycryptodome 설치 실패"
        echo ""
        echo "대안: 다음 명령어로 수동 설치:"
        echo "  pip3 install --user pycryptodome"
        echo "  또는"
        echo "  sudo apt install python3-pycryptodome  # Ubuntu/Debian"
        exit 1
    }
}

echo ""
echo "========================================"
echo "✓ 환경 설정 완료!"
echo "========================================"
echo ""
echo "다음 명령어로 데모를 실행할 수 있습니다:"
echo "  python3 1_ecb_mode_vulnerable.py"
echo "  python3 run_all_demos.py"
echo ""

# PATH 경고
if [ "$choice" = "1" ]; then
    echo "참고: --user로 설치한 경우 다음 경로가 PATH에 있어야 합니다:"
    echo "  ~/.local/bin"
    echo ""
fi
