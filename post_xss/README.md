# Cross-Site Scripting (XSS / CWE-79) Demo Web Application

Flask와 SQLite를 기반으로 제작된 **XSS(Cross-Site Scripting, CWE-79)** 취약점 실습용 게시판 웹 애플리케이션입니다.

## 취약점 개요 (CWE-79)
사용자가 입력한 문자열(`title`, `content`)을 HTML 인코딩(HTML Entity Encoding / Escape)하지 않고 웹 페이지 템플릿(`| safe`) 및 자바스크립트 문맥에 그대로 렌더링할 때 발생합니다.
공격자는 악의적인 자바스크립트 코드를 삽입하여 사용자의 세션 쿠키 탈취, 비인가 작업 수행, 피싱 페이지 유도 등을 수행할 수 있습니다.

## 실행 방법

### 1. 가상환경 생성 및 패키지 설치
```bash
cd post_xss
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. 애플리케이션 실행
```bash
python app.py
```
웹 브라우저에서 `http://127.0.0.1:8000` 또는 `http://127.0.0.1:8000/post`에 접속합니다.

## 테스트 시나리오

### 1. 일반 게시글 작성
* **제목:** `안녕하세요`
* **내용:** `첫 번째 게시글입니다.`
* **동작:** 저장 버튼 클릭 시 작성한 내용이 브라우저 메시지 박스(`alert`)로 출력되며 게시글이 등록됩니다.

### 2. Stored / Reflected XSS 공격 테스트
* **제목:** `XSS 테스트`
* **내용 (스크립트 삽입):**
  ```html
  <script>alert('XSS Attack Succeeded!')</script>
  ```
* **동작:**
  * 저장 즉시 브라우저에서 삽입된 스크립트가 실행되어 `XSS Attack Succeeded!` 메시지 박스가 표시됩니다.
  * 게시글 목록 페이지를 새로고침하거나 다른 사용자가 조회할 때마다 저장된 스크립트가 브라우저에서 계속 재실행됩니다 (Stored XSS).

### 3. 다양한 페이로드 테스트
* **Image OnError:**
  ```html
  <img src="invalid_img" onerror="alert('XSS Executed via Image onerror!')">
  ```
* **SVG OnLoad:**
  ```html
  <svg onload="alert('XSS Executed via SVG onload!')">
  ```

## 보안 조치 (Remediation)
1. **HTML 자동 이스케이프(Auto-escaping) 적용**: 템플릿 렌더링 시 `| safe` 필터를 제거하고 특수문자(`<`, `>`, `&`, `"`, `'`)를 HTML 엔티티(`&lt;`, `&gt;` 등)로 치환합니다.
2. **입력값 정제 (Sanitization)**: 허용된 HTML 태그만 렌더링해야 하는 경우 `bleach` 등의 검증된 라이브러리를 사용하여 허용되지 않은 스크립트 태그를 필터링합니다.
