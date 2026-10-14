# Code Execution (CWE-94 / CWE-95) Demo Web Application

Flask 기반으로 제작된 Code Execution (Eval Injection) 취약점 실습용 웹 애플리케이션입니다.

## 취약점 개요 (CWE-94 / CWE-95)
사용자로부터 전달받은 수식 문자열(`expr`)을 검증 없이 파이썬 내장 함수 `eval()`에 직접 전달하여 실행합니다.
이로 인해 공격자는 단순 사칙연산 외에 악의적인 파이썬 코드 및 시스템 명령을 주입하여 임의 코드를 실행(RCE)할 수 있습니다.

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
1. `eval()` 사용을 지양하고 단순 리터럴 파싱 시 `ast.literal_eval()`을 사용합니다.
2. 수학 수식 계산이 필요한 경우 수식 파서 라이브러리(`simpleeval` 등)나 AST 기반의 화이트리스트 파서를 구현하여 사용합니다.
