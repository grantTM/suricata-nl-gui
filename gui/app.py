import json
from flask import Flask, render_template, request
import sys
import os

sys.path.append("../scripts")  # So we can import rule logic
from rule_translator import translate_to_suricata, get_next_sid, RULES_FILE, save_rule_to_file

app = Flask(__name__)

EVE_LOG_PATH = os.path.expanduser("~/suricata_nl_gui/logs/eve.json")

@app.route("/", methods=["GET", "POST"])
def index():
    generated_rule = None
    alert = None

    if request.method == "POST":
        user_input = request.form.get("nl_rule")
        sid = get_next_sid(RULES_FILE)
        rule = translate_to_suricata(user_input, sid)

        if rule:
            generated_rule = rule
            if "duplicate" not in rule.lower():  # crude check, refine later
                save_rule_to_file(rule)
        else:
            alert = "⚠️ Could not translate input."

    return render_template("index.html", rule=generated_rule, alert=alert)

@app.route("/logs")
def view_logs():
    alerts = []

    if os.path.exists(EVE_LOG_PATH):
        try:
            with open(EVE_LOG_PATH, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        if entry.get("event_type") == "alert":
                            alerts.append(entry)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            alerts = [{"timestamp": "N/A", "src_ip": "N/A", "dest_ip": "N/A", "proto": "N/A", "alert": {"signature": f"Error reading eve.json: {e}"}}]

    # Show only the most recent 20 alerts
    alerts = alerts[-20:]
    return render_template("logs.html", alerts=alerts)
                        

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
