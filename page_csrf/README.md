# Cross-Site Request Forgery (CSRF) 취약점 실습 예제

이 프로젝트는 **CWE-352: Cross-Site Request Forgery (CSRF)** 취약점을 학습하고 재현하기 위해 제작된 Flask 웹 애플리케이션 예제입니다.

---

## 1. 취약점 개요

- **취약점 분류**: CWE-352 (Cross-Site Request Forgery)
- **발생 원인**:
  - 비밀번호 변경(`POST /change-password`) 및 이메일 변경(`POST /change-email`)과 같은 주요 상태 변경(State-changing) 요청을 처리할 때 **Anti-CSRF 토큰** 검증 부재.
  - 브라우저의 기본 세션 쿠키 전송 메커니즘을 맹신하여, 요청이 실제 사용자의 의도로 발생한 것인지 검증하지 않음.

---

## 2. 프로젝트 구조

```
page_csrf/
├── README.md               # 실습 가이드 및 취약점 설명
├── requirements.txt        # 의존성 패키지 목록 (Flask, requests)
├── app.py                  # Flask 백엔드 애플리케이션 및 취약 엔드포인트
└── templates/
    ├── login.html          # 사용자 로그인 화면
    ├── profile.html        # 마이페이지 및 비밀번호/이메일 변경 폼 (취약점 존재)
    └── attacker.html       # 공격자가 호스팅하는 악성 CSRF 유도 페이지 (PoC)
```

---

## 3. 실행 방법

### 3.1 의존성 설치
```bash
pip install -r requirements.txt
```

### 3.2 애플리케이션 실행
```bash
python app.py
```
- 서버가 실행되면 브라우저에서 `http://127.0.0.1:8000` 으로 접속합니다.

---

## 4. 취약점 재현 및 공격 시나리오

1. **사용자 로그인**:
   - `http://127.0.0.1:8000/login` 에 접속합니다.
   - 테스트 계정: 아이디 `alice`, 비밀번호 `password123`
   - 로그인에 성공하면 `/profile` 페이지로 이동합니다.

2. **공격자 페이지 접속 (CSRF 공격 트리거)**:
   - 사용자가 로그인된 상태에서 새로운 브라우저 탭을 열고 `http://127.0.0.1:8000/attacker` 에 접속합니다.
   - 1.5초 후 자바스크립트에 의해 백그라운드에서 `/change-password`로 `new_password=hacked_password_999` 요청이 자동 전송됩니다.

3. **결과 확인**:
   - 비밀번호가 사용자의 의지와 무관하게 `hacked_password_999`로 강제 변경된 것을 확인할 수 있습니다.

---

## 5. 보안 대책 (Remediation)

1. **Anti-CSRF 토큰 적용 (Flask-WTF 등)**:
   - 모든 상태 변경 요청(POST, PUT, DELETE)에 예측 불가능한 일회용 CSRF 토큰을 발급하고 서버에서 검증합니다.
   ```python
   from flask_wtf.csrf import CSRFProtect
   csrf = CSRFProtect(app)
   ```
2. **SameSite 쿠키 속성 설정**:
   - 세션 쿠키 발급 시 `SameSite=Lax` 또는 `SameSite=Strict` 속성을 부여하여 타 사이트로부터 시작된 요청 시 쿠키 전송을 제한합니다.
   ```python
   app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
   ```
3. **중요 기능에 대한 재인증 요구**:
   - 비밀번호 변경 등 민감한 작업 시 현재 비밀번호(Current Password)를 다시 입력받아 검증합니다.
