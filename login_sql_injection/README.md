# SQL Injection (CWE-89) Demo Web Application

Flask와 SQLite를 기반으로 제작된 SQL Injection 취약점 실습용 로그인 웹 애플리케이션입니다.

## 취약점 개요 (CWE-89)
사용자의 입력값(`username`, `password`)을 검증이나 파라미터 바인딩 없이 SQL 쿼리 문자열에 직접 결합(`f-string` 포맷팅)할 때 발생합니다.
공격자는 입력값을 조작하여 쿼리의 구조를 변경하고, 비밀번호 검증을 우회하여 관리자 권한으로 로그인할 수 있습니다.

## 사전 준비 및 실행 방법

### 1. 패키지 설치
```bash
pip install -r requirements.txt
```

### 2. 애플리케이션 실행
```bash
python app.py
```
실행 후 웹 브라우저에서 `http://127.0.0.1:5000`으로 접속합니다.

## 테스트 시나리오

### 1. 정상 로그인
* **Username:** `admin`
* **Password:** `admin1234`
* **결과:** `Login Succeed!`

### 2. 잘못된 비밀번호 입력
* **Username:** `admin`
* **Password:** `wrongpassword`
* **결과:** `Login Failed!`

### 3. SQL Injection을 이용한 인증 우회 (Password 몰라도 로그인 성공)
* **공격 페이로드 1:**
  * **Username:** `admin' --`
  * **Password:** (아무 값이나 입력)
  * **실행 쿼리:** `SELECT * FROM users WHERE username = 'admin' --' AND password = '...'`
  * **결과:** `Login Succeed!` (`admin` 계정으로 우회 로그인)
* **공격 페이로드 2:**
  * **Username:** `' OR '1'='1`
  * **Password:** (아무 값이나 입력)
  * **실행 쿼리:** `SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '...'`
  * **결과:** `Login Succeed!`

## 보안 조치 (Remediation)
SQL 쿼리 작성 시 동적 문자열 연결 대신 **파라미터화된 쿼리 (Parameterized Query / Prepared Statement)**를 사용합니다.

```python
# 보안 조치 예시
cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
```
