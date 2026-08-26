import sqlite3
import os
from flask import Flask, request, render_template, render_template_string

app = Flask(__name__)
DB_FILE = "users.db"


def init_db():
    """SQLite 데이터베이스 초기화 및 데모 계정 생성"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)
    # 데모 계정 (admin / admin1234) 추가
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES ('admin', 'admin1234', 'administrator')"
        )
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES ('guest', 'guest1234', 'guest_user')"
        )
        conn.commit()
    conn.close()


def authenticate_user_vulnerable(username, password):
    """
    [취약한 인증 모듈] - CWE-89: SQL Injection 방지를 위해 매개변수화된 쿼리 사용으로 수정됨
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # SECURE: 파라미터 바인딩 적용
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    print(f"[*] Executing Parameterized SQL Query: {query}")

    try:
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
    except sqlite3.Error as e:
        print(f"[!] Database Error: {e}")
        user = None
    finally:
        conn.close()

    return user, query


def authenticate_user_secure(username, password):
    """
    [안전한 인증 모듈] - 매개변수화된 쿼리 (Parameterized Query / Prepared Statement)
    플레이스홀더(?)를 사용하여 사용자 입력값을 데이터로만 처리하므로 SQL Injection이 방어됩니다.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # SECURE: 파라미터 바인딩 적용
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    user = cursor.fetchone()
    conn.close()

    return user, query


@app.route("/", methods=["GET"])
def index():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # 안전한 인증 함수 호출
    user, executed_query = authenticate_user_secure(username, password)

    if user:
        # 로그인 성공
        message = "Login Succeed!"
        status = "success"
        user_info = {
            "id": user[0],
            "username": user[1],
            "role": user[3]
        }
    else:
        # 로그인 실패
        message = "Login Failed!"
        status = "danger"
        user_info = None

    return render_template(
        "login.html",
        message=message,
        status=status,
        username=username,
        user_info=user_info,
        executed_query=executed_query
    )


if __name__ == "__main__":
    init_db()
    print("Starting Flask application on http://127.0.0.1:5000")
    print("Demo Account: admin / admin1234")
    print("SQL Injection Payload Example: admin' --")
    app.run(host="0.0.0.0", port=5000, debug=True)
