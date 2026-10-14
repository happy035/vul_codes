import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>Network Ping Tool</title>
</head>
<body style="font-family: sans-serif; max-width: 650px; margin: 40px auto; line-height: 1.6;">
    <h2>네트워크 Ping 테스트 도구 (Command Injection 취약점 실습)</h2>
    <form method="POST" action="/ping">
        <label for="host">호스트 IP 또는 도메인:</label><br>
        <input type="text" id="host" name="host" placeholder="예: 127.0.0.1" style="width: 80%; padding: 8px; margin: 8px 0;" required>
        <button type="submit" style="padding: 8px 16px;">Ping 실행</button>
    </form>
    {% if host %}
    <div style="margin-top: 20px; padding: 15px; background: #f4f4f4; border-radius: 5px;">
        <p><strong>요청 호스트:</strong> {{ host }}</p>
        <pre style="background: #222; color: #00ff00; padding: 10px; border-radius: 4px; overflow-x: auto;">{{ output }}</pre>
    </div>
    {% endif %}
</body>
</html>
"""


def execute_ping_vulnerable(host: str) -> str:
    """
    [취약점] CWE-78: OS Command Injection
    사용자 입력값(host)을 검증 없이 쉘 명령어 문자열에 직접 결합하고
    shell=True 옵션으로 실행하여 임의의 OS 명령어가 주입될 수 있습니다.
    """
    # VULNERABLE: shell=True 및 문자열 포맷팅을 통한 OS 명령어 실행
    cmd = f"ping -c 1 {host}"
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True, timeout=5)
    except subprocess.CalledProcessError as e:
        output = e.output
    except subprocess.TimeoutExpired:
        output = "Command timed out."
    return output


@app.route("/", methods=["GET"])
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/ping", methods=["POST"])
def ping():
    host = request.form.get("host", "").strip()
    output = execute_ping_vulnerable(host) if host else ""
    return render_template_string(HTML_TEMPLATE, host=host, output=output)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
