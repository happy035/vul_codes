from flask import Flask, request, render_template_string

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>Code Execution Calculator</title>
</head>
<body style="font-family: sans-serif; max-width: 600px; margin: 40px auto; line-height: 1.6;">
    <h2>수식 계산기 (Code Execution 취약점 실습)</h2>
    <form method="POST" action="/calculate">
        <label for="expr">수식 입력:</label><br>
        <input type="text" id="expr" name="expr" placeholder="예: 2 + 3 * 4" style="width: 80%; padding: 8px; margin: 8px 0;" required>
        <button type="submit" style="padding: 8px 16px;">계산</button>
    </form>
    {% if expression %}
    <div style="margin-top: 20px; padding: 15px; background: #f4f4f4; border-radius: 5px;">
        <p><strong>입력값:</strong> {{ expression }}</p>
        <p><strong>결과:</strong> {{ result }}</p>
    </div>
    {% endif %}
</body>
</html>
"""


def evaluate_expression_vulnerable(expr: str):
    """
    [취약점] CWE-94 / CWE-95: Code Injection (Eval Injection)
    사용자 입력값(expr)을 검증 없이 eval() 함수에 직접 전달하여
    임의의 파이썬 코드가 실행(Code Execution)될 수 있습니다.
    """
    # VULNERABLE: eval()을 통한 임의 코드 실행
    return eval(expr)


@app.route("/", methods=["GET"])
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/calculate", methods=["POST"])
def calculate():
    expr = request.form.get("expr", "")
    try:
        result = evaluate_expression_vulnerable(expr)
    except Exception as e:
        result = f"Error: {e}"
    return render_template_string(HTML_TEMPLATE, expression=expr, result=result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
