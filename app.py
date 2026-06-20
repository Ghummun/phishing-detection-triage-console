from flask import Flask, render_template, request
import analyzer

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2MB upload limit


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", result=None)


@app.route("/analyze", methods=["POST"])
def analyze():
    raw_bytes = None

    if "email_file" in request.files and request.files["email_file"].filename:
        raw_bytes = request.files["email_file"].read()
    elif request.form.get("email_text", "").strip():
        raw_bytes = request.form["email_text"].encode("utf-8")

    if not raw_bytes:
        return render_template("index.html", result=None, error="Please upload a .eml file or paste email content.")

    try:
        msg = analyzer.parse_email(raw_bytes)
        result = analyzer.calculate_risk_score(msg)
    except Exception as e:
        return render_template("index.html", result=None, error=f"Could not parse email: {e}")

    return render_template("index.html", result=result, error=None)


if __name__ == "__main__":
    app.run(debug=True, port=5000)