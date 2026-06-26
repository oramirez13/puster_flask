from flask import Flask, render_template, jsonify, request, send_from_directory
import subprocess
import json
import os
import csv
import io

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import pagesizes
from reportlab.lib.units import inch

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BINARY_PATH = os.path.join(BASE_DIR, "puster")
DATA_PATH = os.path.join(BASE_DIR, "monitor_data.json")
PDF_PATH = os.path.join(BASE_DIR, "puster_report.pdf")

app = Flask(__name__)


def cargar_datos():
    if not os.path.exists(DATA_PATH):
        return None
    with open(DATA_PATH, "r") as f:
        return json.load(f)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan")
def scan():
    try:
        result = subprocess.run([BINARY_PATH], capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return jsonify({"status": "error", "message": result.stderr.strip()}), 500
        return jsonify({"status": "completed", "message": result.stdout.strip()})
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "message": "Scan timed out"}), 500
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "Binary not found"}), 500


@app.route("/data")
def data():
    datos = cargar_datos()
    if datos is None:
        return jsonify({"error": "No data found. Run a scan first."}), 404
    return jsonify(datos)


@app.route("/api/alerts")
def api_alerts():
    datos = cargar_datos()
    if datos is None:
        return jsonify({"error": "No data found"}), 404

    alerts = datos.get("alerts", [])
    risk_filter = request.args.get("risk", "").upper()
    process_filter = request.args.get("process", "").lower()
    port_filter = request.args.get("port", "")

    if risk_filter:
        alerts = [a for a in alerts if a.get("risk", "").upper() == risk_filter]
    if process_filter:
        alerts = [a for a in alerts if process_filter in a.get("process", "").lower()]
    if port_filter:
        alerts = [a for a in alerts if a.get("remote_port", "") == port_filter]

    return jsonify({
        "metadata": datos.get("metadata", {}),
        "summary": {
            "total_connections": len(alerts),
            "low": sum(1 for a in alerts if a.get("risk") == "LOW"),
            "medium": sum(1 for a in alerts if a.get("risk") == "MEDIUM"),
            "high": sum(1 for a in alerts if a.get("risk") == "HIGH"),
        },
        "alerts": alerts
    })


@app.route("/export/csv")
def export_csv():
    datos = cargar_datos()
    if datos is None:
        return jsonify({"error": "No data found"}), 404

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Process", "PID", "Protocol", "Remote IP", "Remote Port",
                      "Local IP", "Local Port", "Risk"])

    for alert in datos.get("alerts", []):
        writer.writerow([
            alert.get("process", ""),
            alert.get("pid", ""),
            alert.get("protocol", ""),
            alert.get("remote_ip", ""),
            alert.get("remote_port", ""),
            alert.get("local_ip", ""),
            alert.get("local_port", ""),
            alert.get("risk", ""),
        ])

    csv_content = output.getvalue()
    output.close()

    response = app.make_response(csv_content)
    response.headers["Content-Type"] = "text/csv"
    response.headers["Content-Disposition"] = "attachment; filename=puster_report.csv"
    return response


@app.route("/export/pdf")
def export_pdf():
    datos = cargar_datos()
    if datos is None:
        return jsonify({"error": "No data available"}), 400

    doc = SimpleDocTemplate(PDF_PATH, pagesize=pagesizes.letter)
    elements = []
    styles = getSampleStyleSheet()

    meta = datos.get("metadata", {})
    summary = datos.get("summary", {})

    elements.append(Paragraph("Puster 3.5 - Security Report", styles["Title"]))
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph(f"Host: {meta.get('hostname', 'unknown')}", styles["Normal"]))
    elements.append(Paragraph(f"Timestamp: {meta.get('timestamp', 'N/A')}", styles["Normal"]))
    elements.append(Paragraph(f"Total Connections: {summary.get('total_connections', 0)}", styles["Normal"]))
    elements.append(Paragraph(f"LOW: {summary.get('low', 0)} | MEDIUM: {summary.get('medium', 0)} | HIGH: {summary.get('high', 0)}", styles["Normal"]))
    elements.append(Spacer(1, 0.5 * inch))

    table_data = [["Process", "PID", "Remote IP", "Port", "Protocol", "Risk"]]
    for alert in datos.get("alerts", []):
        table_data.append([
            alert.get("process", ""),
            alert.get("pid", ""),
            alert.get("remote_ip", ""),
            alert.get("remote_port", ""),
            alert.get("protocol", ""),
            alert.get("risk", ""),
        ])

    table = Table(table_data)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))

    elements.append(table)
    doc.build(elements)

    return send_from_directory(BASE_DIR, "puster_report.pdf", as_attachment=True)


if __name__ == "__main__":
    port = int(os.environ.get("PUSTER_PORT", 5000))
    host = os.environ.get("PUSTER_HOST", "127.0.0.1")
    debug = os.environ.get("PUSTER_DEBUG", "false").lower() == "true"
    app.run(host=host, port=port, debug=debug)
