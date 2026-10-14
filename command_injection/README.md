# Command Injection (CWE-78) Demo Web Application

Flask 기반으로 제작된 OS Command Injection 취약점 실습용 웹 애플리케이션입니다.

## 취약점 개요 (CWE-78)
사용자로부터 입력받은 호스트 값(`host`)을 검증 없이 쉘 명령어 문자열에 직접 결합(`f"ping -c 1 {host}"`)하고, `subprocess.check_output(..., shell=True)`를 통해 실행합니다.
공격자는 세미콜론(`;`), 파이프(`|`), 앰퍼샌드(`&&`) 등의 쉘 메타문자를 주입하여 시스템 명령어를 임의로 실행할 수 있습니다.

## 실행 방법

### 1. 패키지 설치
```bash
pip install -r requirements.txt
```

### 2. 애플리케이션 실행
```bash
python app.py
```
브라우저에서 `http://127.0.0.1:5000`으로 접속합니다.

## 보안 조치 (Remediation)
1. `shell=True` 사용을 지양하고 명령어 인자를 리스트(배열) 형태로 전달합니다.
   ```python
   # 안전한 방식 예시
   subprocess.check_output(["ping", "-c", "1", host], shell=False)
   ```
2. 사용자 입력값에 대해 IP/도메인 형식 검증(화이트리스트 정규표현식 등)을 적용합니다.
