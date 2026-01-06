#!/usr/bin/env python3
"""
모든 취약점 데모를 순차적으로 실행하는 스크립트
"""

import subprocess
import sys
import os

def run_demo(script_name, description):
    """데모 스크립트 실행"""
    print("\n" + "=" * 70)
    print(f"🔍 {description}")
    print("=" * 70)

    try:
        result = subprocess.run(
            [sys.executable, script_name],
            cwd=os.path.dirname(__file__),
            capture_output=False,
            text=True
        )

        if result.returncode == 0:
            print(f"\n✅ {script_name} 완료")
        else:
            print(f"\n❌ {script_name} 오류 발생")

    except Exception as e:
        print(f"\n❌ 오류: {e}")

    input("\n⏸️  계속하려면 Enter를 누르세요...")

def main():
    """메인 함수"""
    demos = [
        ("1_ecb_mode_vulnerable.py", "1. ECB 모드 취약점 - 취약한 코드"),
        ("1_ecb_mode_exploit.py", "1. ECB 모드 취약점 - Exploit"),
        ("2_iv_reuse_vulnerable.py", "2. IV 재사용 취약점 - 취약한 코드"),
        ("2_iv_reuse_exploit.py", "2. IV 재사용 취약점 - Exploit"),
        ("3_padding_oracle_vulnerable.py", "3. Padding Oracle - 취약한 코드"),
        ("3_padding_oracle_exploit.py", "3. Padding Oracle - Exploit"),
        ("4_weak_random_vulnerable.py", "4. 약한 난수 생성기 - 취약한 코드"),
        ("4_weak_random_exploit.py", "4. 약한 난수 생성기 - Exploit"),
        ("5_timing_attack_vulnerable.py", "5. 타이밍 공격 - 취약한 코드"),
        ("5_timing_attack_exploit.py", "5. 타이밍 공격 - Exploit"),
    ]

    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 15 + "취약한 암호화 데모 - 전체 실행" + " " * 20 + "║")
    print("╚" + "=" * 68 + "╝")

    print("\n📚 총 {}개의 데모를 실행합니다.\n".format(len(demos)))

    for i, (script, desc) in enumerate(demos, 1):
        print(f"{i}. {desc}")

    print("\n" + "=" * 70)
    choice = input("\n계속하시겠습니까? (y/n): ")

    if choice.lower() != 'y':
        print("종료합니다.")
        return

    for script, desc in demos:
        run_demo(script, desc)

    print("\n" + "=" * 70)
    print("✅ 모든 데모가 완료되었습니다!")
    print("=" * 70)

if __name__ == "__main__":
    main()
