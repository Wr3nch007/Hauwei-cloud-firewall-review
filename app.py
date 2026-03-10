from flask import Flask, render_template, request, send_file
import os
from firewall_analyzer import analyze_firewall

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
OUTPUT_FILE = "firewall_action_tracker.xlsx"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/", methods=["GET", "POST"])
def index():

    findings = None

    if request.method == "POST":

        file = request.files["file"]

        if file:
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)

            df = analyze_firewall(filepath)

            df.to_excel(OUTPUT_FILE, index=False)

            findings = df.to_dict(orient="records")

    return render_template("index.html", findings=findings)


@app.route("/download")
def download():

    return send_file(
        OUTPUT_FILE,
        as_attachment=True
    )


if __name__ == "__main__":
    app.run(debug=True)
