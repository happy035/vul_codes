import sqlite3
import os
from flask import Flask, request, render_template

app = Flask(__name__)
DB_FILE = "posts.db"


def init_db():
    """SQLite 데이터베이스 초기화 및 기본 게시글 등록"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # 초기 샘플 게시글 추가
    cursor.execute("SELECT COUNT(*) FROM posts")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            "INSERT INTO posts (title, content) VALUES (?, ?)",
            ("환영합니다!", "보안 실습용 게시판입니다. 자유롭게 글을 작성해보세요.")
        )
        conn.commit()
    conn.close()


def get_all_posts():
    """모든 게시글 조회"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, content, created_at FROM posts ORDER BY id DESC")
    posts = cursor.fetchall()
    conn.close()
    return posts


def add_post(title, content):
    """
    게시글 저장
    [CWE-79: Cross-site Scripting (XSS) 취약점 발생 지점]
    사용자 입력값(title, content)에 대한 HTML 태그 및 특수문자 필터링(Escape) 없이
    원문 그대로 데이터베이스에 저장합니다.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO posts (title, content) VALUES (?, ?)", (title, content))
    conn.commit()
    conn.close()


@app.route("/", methods=["GET"])
@app.route("/post", methods=["GET"])
def post_page():
    posts = get_all_posts()
    return render_template("post.html", posts=posts)


@app.route("/post", methods=["POST"])
def create_post():
    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()

    if title and content:
        add_post(title, content)
        # 새로 등록된 글에 대한 알림용 데이터 전달
        last_saved = {
            "title": title,
            "content": content
        }
    else:
        last_saved = None

    posts = get_all_posts()
    return render_template("post.html", posts=posts, last_saved=last_saved)


if __name__ == "__main__":
    init_db()
    print("Starting Flask XSS Demo application on http://127.0.0.1:8000")
    print("XSS Payload Example: <script>alert('XSS Attack Succeeded!')</script>")
    app.run(host="0.0.0.0", port=8000, debug=True)
