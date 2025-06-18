import json
from flask import Flask, render_template, request
import sys
import os
from collections import Counter
from datetime import datetime
import pytz

sys.path.append("../scripts")  # So we can import rule logic
from rule_translator import translate_to_suricata, get_next_sid, RULES_FILE, save_rule_to_file

app = Flask(__name__)

EVE_LOG_PATH = "/var/log/suricata/eve.json"

def map_severity(msg):
    msg = msg.lower()
    if "brute force" in msg or "exfiltration" in msg:
        return "High"
    elif "scan" in msg or "dns" in msg:
        return "Medium"
    else:
        return "Low"

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

    # Show only the most recent 20 alerts in descending order
    alerts = alerts[-20:][::-1]

    # Convert UTC to local time (e.g., Central Time)
    local_tz = pytz.timezone("America/Chicago")
    
    for entry in alerts:
        msg = entry.get("alert", {}).get("signature", "")
        entry["severity"] = map_severity(msg)

        ts = entry.get("timestamp")
        if ts:
            try:
                # Try with microseconds first
                utc_time = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z")
                entry["local_time"] = utc_time.astimezone(local_tz).strftime("%Y-%m-%d %I:%M:%S %p %Z")
            except ValueError:
                try:
                    # Fallback: no microseconds
                    utc_time = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
                except ValueError:
                    utc_time = None

            if utc_time:
                entry["local_time"] = utc_time.replace(tzinfo=pytz.utc).astimezone(local_tz).strftime(
                    "%Y-%m-%d %I:%M:%S %p %Z")
            else:
                entry["local_time"] = ts  # fallback

    # Summary statistics
    total_alerts = len(alerts)
    signatures = Counter(entry["alert"]["signature"] for entry in alerts if "alert" in entry)
    top_signatures = signatures.most_common(3)
    sources = Counter(entry["src_ip"] for entry in alerts if "src_ip" in entry)
    top_source = sources.most_common(1)[0][0] if sources else "N/A"
    severities = Counter(entry["severity"] for entry in alerts if "severity" in entry)
    high_count = severities.get("High", 0)
    medium_count = severities.get("Medium", 0)
    low_count = severities.get("Low", 0)

    latest_alert_time = alerts[0]["local_time"] if alerts else "N/A"

    return render_template("logs.html", alerts=alerts,
                        total_alerts=total_alerts,
                        top_signatures=top_signatures,
                        top_source=top_source,
                        high_count=high_count,
                        medium_count=medium_count,
                        low_count=low_count,
                        latest_alert_time=latest_alert_time)
                        

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
