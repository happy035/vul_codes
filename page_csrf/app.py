import sqlite3
import os
import secrets
from flask import Flask, request, render_template, redirect, url_for, session, flash, abort

app = Flask(__name__)
app.secret_key = "super-secret-key-for-csrf-demo"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
DB_FILE = "csrf_demo.db"


@app.before_request
def ensure_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)


@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=session.get("csrf_token", ""))


def init_db():
    """SQLite 데이터베이스 초기화 및 기본 사용자 계정 생성"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL
        )
    """)
    # 기본 테스트 계정 생성: alice / password123
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            ("alice", "password123", "alice@example.com")
        )
        conn.commit()
    conn.close()


def get_user_by_username(username):
    """사용자 정보 조회"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, email FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user


def update_password(username, new_password):
    """사용자 비밀번호 변경"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, username))
    conn.commit()
    conn.close()


def update_email(username, new_email):
    """사용자 이메일 변경"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET email = ? WHERE username = ?", (new_email, username))
    conn.commit()
    conn.close()


@app.route("/", methods=["GET"])
def index():
    if "username" in session:
        return redirect(url_for("profile"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = get_user_by_username(username)
        if user and user[2] == password:
            session.clear()
            session["username"] = username
            session["csrf_token"] = secrets.token_hex(32)
            flash("로그인에 성공했습니다!", "success")
            return redirect(url_for("profile"))
        else:
            flash("아이디 또는 비밀번호가 올바르지 않습니다.", "danger")

    return render_template("login.html")


@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    flash("로그아웃되었습니다.", "info")
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET"])
def profile():
    if "username" not in session:
        flash("로그인이 필요합니다.", "warning")
        return redirect(url_for("login"))

    user = get_user_by_username(session["username"])
    return render_template("profile.html", user=user)


# ==============================================================================
# [CWE-352: Cross-Site Request Forgery (CSRF) 취약점 발생 지점]
# CSRF 토큰(Anti-CSRF Token) 검증 없이 오직 세션 쿠키(session["username"])만으로
# 비밀번호 변경 요청을 승인합니다.
# 공격자는 피해자가 로그인된 상태에서 악성 사이트를 방문하도록 유도하여,
# 피해자의 브라우저를 통해 백그라운드에서 비밀번호 변경 요청을 강제로 전송할 수 있습니다.
# ==============================================================================
@app.route("/change-password", methods=["POST"])
def change_password():
    if "username" not in session:
        flash("로그인이 필요합니다.", "warning")
        return redirect(url_for("login"))

    csrf_token = request.form.get("csrf_token")
    if not csrf_token or csrf_token != session.get("csrf_token"):
        abort(403, description="CSRF token validation failed.")

    new_password = request.form.get("new_password", "").strip()
    if new_password:
        update_password(session["username"], new_password)
        flash(f"비밀번호가 성공적으로 변경되었습니다! (새 비밀번호: {new_password})", "success")
    else:
        flash("새 비밀번호를 입력해주세요.", "danger")

    return redirect(url_for("profile"))


@app.route("/change-email", methods=["POST"])
def change_email():
    if "username" not in session:
        flash("로그인이 필요합니다.", "warning")
        return redirect(url_for("login"))

    csrf_token = request.form.get("csrf_token")
    if not csrf_token or csrf_token != session.get("csrf_token"):
        abort(403, description="CSRF token validation failed.")

    new_email = request.form.get("new_email", "").strip()
    if new_email:
        update_email(session["username"], new_email)
        flash(f"이메일이 성공적으로 변경되었습니다! (새 이메일: {new_email})", "success")
    else:
        flash("새 이메일을 입력해주세요.", "danger")

    return redirect(url_for("profile"))


# ==============================================================================
# [CSRF 공격 시연용 엔드포인트]
# 공격자가 개설한 피싱/악성 웹페이지를 모사한 엔드포인트입니다.
# 사용자가 이 페이지에 접속하면 자바스크립트에 의해 즉시 /change-password 로
# 위조된 POST 요청이 자동으로 전송됩니다.
# ==============================================================================
@app.route("/attacker", methods=["GET"])
def attacker_page():
    return render_template("attacker.html")


if __name__ == "__main__":
    init_db()
    print("Starting Flask CSRF Demo application on http://127.0.0.1:8000")
    print("Default user: alice / password123")
    print("CSRF Attack simulation URL: http://127.0.0.1:8000/attacker")
    app.run(host="0.0.0.0", port=8000, debug=True)
