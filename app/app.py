import json
from flask import Flask, render_template, request, make_response, redirect, session, url_for, flash, jsonify
import csv
import io
import sys
import os
from collections import Counter
from datetime import datetime
import pytz
import re
import logging
import tempfile
import subprocess

# Set up logging directory
LOG_DIR = os.path.expanduser("/home/grantfitz/suricata_nl_gui/logs/")
os.makedirs(LOG_DIR, exist_ok=True)

# Main app logger
logging.basicConfig(
    filename=os.path.join(LOG_DIR, "app.log"),
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

# PCAP replay logger
pcap_logger = logging.getLogger("pcap_replay")
pcap_logger.setLevel(logging.INFO)
replay_handler = logging.FileHandler(os.path.join(LOG_DIR, "pcap_replay.log"))
replay_handler.setLevel(logging.INFO)
replay_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
pcap_logger.addHandler(replay_handler)

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))
from rule_translator import translate_to_suricata, get_next_sid, RULES_FILE, save_rule_to_file

app = Flask(__name__)
app.secret_key = "8c22f0fb0d1288c1e99736ff9e104f8b"

EVE_LOG_PATH = "/var/log/suricata/eve.json"
RULES_FILE = os.path.expanduser("/home/grantfitz/suricata_nl_gui/rules/my.rules")

def map_severity(msg):
    msg = msg.lower()

    if any(term in msg for term in [
        "brute force", "sql injection", "xss", "executable", 
        "smb", "telnet", "lateral movement"
    ]):
        return "High"

    elif any(term in msg for term in [
        "port scan", "user-agent", "curl", "dns", "ssh", "external ssh"
    ]):
        return "Medium"

    elif any(term in msg for term in [
        "ICMP"
    ]):
        return "Low"

    return "Low"

    
def get_recent_alerts(limit=20):
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
    alerts = alerts[-limit:][::-1]

    # Convert UTC to local time (e.g., Central Time)
    local_tz = pytz.timezone("America/Chicago")
    
    for entry in alerts:
        msg = entry.get("alert", {}).get("signature", "")
        entry["severity"] = map_severity(msg)

        ts = entry.get("timestamp")
        utc_time = None

        if ts:
            try:
                # Format with microseconds and offset
                utc_time = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z")
            except ValueError:
                try:
                    # Format without microseconds, with offset
                    utc_time = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S%z")
                except ValueError:
                    try:
                        # Format without offset (Z suffix), treat as UTC
                        utc_time = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
                        utc_time = utc_time.replace(tzinfo=pytz.utc)
                    except ValueError:
                        logging.warning(f"Timestamp parsing failed for: {ts}")
                        utc_time = None

        if utc_time:
            entry["local_time"] = utc_time.astimezone(local_tz).strftime("%Y-%m-%d %I:%M:%S %p %Z")
        else:
            entry["local_time"] = ts  # fallback to raw string if all parsing fails

    return alerts

def load_rules():
    """Load Suricata rules as a list of strings."""
    if not os.path.exists(RULES_FILE):
        logging.error(f"Rules file not found: {RULES_FILE}")
        return []
    with open(RULES_FILE, "r") as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        logging.info(f"Loaded {len(lines)} rules from {RULES_FILE}")
        return lines
    
def update_rule(sid, new_rule):
    """Replace the rule with the given SID and increment rev number if valid."""
    rules = load_rules()
    updated = False
    sid_pattern = re.compile(r"sid\s*:\s*" + re.escape(str(sid)) + r"\s*;")

    for i, rule in enumerate(rules):
        if sid_pattern.search(rule):
            # Handle rev increment
            if "rev:" in new_rule:
                new_rule = re.sub(r"rev\s*:\s*(\d+)", lambda m: f"rev:{int(m.group(1)) + 1}", new_rule)
            else:
                new_rule = new_rule.rstrip(";") + "; rev:1;"
            rules[i] = new_rule
            updated = True
            logging.info("Rule with SID %s updated to: %s", sid, new_rule)
            break

    if not updated:
        return False, "Rule with given SID not found."

    # Validate with temp file
    with tempfile.NamedTemporaryFile("w", delete=False) as temp_rules:
        temp_rules.write("\n".join(rules) + "\n")
        temp_rules_path = temp_rules.name

    temp_log_dir = tempfile.mkdtemp()
    # Validate with temp file
    temp_log_dir = tempfile.mkdtemp()

    try:
        subprocess.run(
            ["suricata", "-T", "-c", "/etc/suricata/suricata.yaml",
             "-S", temp_rules_path,
             "--set", f"default-log-dir={temp_log_dir}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
    except subprocess.CalledProcessError as e:
        return False, "Rule validation failed: {}".format(e.stderr.decode() or e.stdout.decode())

    # Save if validated
    try:
        with open(RULES_FILE, "w") as f:
            f.write("\n".join(rules) + "\n")
        return True, "Rule saved successfully."
    except Exception as e:
        return False, f"Failed to save rule: {str(e)}"

@app.route("/", methods=["GET"])
def index_redirect():
    return redirect("/logs")

@app.route("/translate", methods=["GET", "POST"])
def translate():
    generated_rule = None
    alert = None

    if request.method == "POST":
        user_input = request.form.get("nl_rule")
        sid = get_next_sid(RULES_FILE)
        rule = translate_to_suricata(user_input, sid)

        if rule:
            generated_rule = rule
        else:
            alert = "⚠️ Could not translate input."

    return render_template("index.html", 
                           rule=generated_rule, 
                           alert=alert,
                           active_page="translate")

@app.route("/confirm_rule", methods=["POST"])
def confirm_rule():
    action = request.form.get("action")
    if action == "cancel":
        logging.info("User canceled rule creation.")
        return render_template("index.html", alert="Rule creation canceled.")
    
    raw_rule = request.form.get("confirmed_rule")
    sid_override = request.form.get("sid_override")

    if not raw_rule:
        logging.error("No rule content submitted for confirmation.")
        return render_template("index.html", alert="No rule content provided.")

    try:
        if sid_override:
            sid = int(sid_override)
            raw_rule = re.sub(r"sid:\d+;", f"sid:{sid};", raw_rule)
        else:
            # Extract SID from rule if no override
            sid_match = re.search(r"sid:(\d+);", raw_rule)
            sid = int(sid_match.group(1)) if sid_match else None
    except ValueError:
        logging.warning(f"Invalid SID entered: {sid_override}")
        return render_template("index.html", rule=raw_rule, alert="Invalid SID format.")
        
    try:
        # Check if SID already exists
        with open(RULES_FILE, "r") as f:
            if f"sid:{sid};" in f.read():
                logging.warning(f"Duplicate SID attempted: {sid}")
                return render_template("index.html", rule=raw_rule, alert="SID already exists. Choose unique ID to proceed.")
            
        save_rule_to_file(raw_rule)
        logging.info(f"Rule saved successfully: {raw_rule.strip()[:60]}...")
        return render_template("index.html", alert="Rule saved successfully.")
    except Exception as e:
        logging.exception("Failed to save rule")
        return render_template("index.html", rule=raw_rule, alert=f"Failed to save rule: {e}")

@app.route("/logs")
def view_logs():
    sort = request.args.get("sort", "time")
    limit = int(request.args.get("limit", 100))  # Prep for step 2
    alerts = get_recent_alerts(limit)

    if sort == "severity":
        severity_order = {"High": 0, "Medium": 1, "Low": 2}
        alerts.sort(key=lambda a: severity_order.get(a.get("severity", "Low")))

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
                        latest_alert_time=latest_alert_time,
                        active_page="logs",
                        sort=sort,
                        limit=limit)
                        
@app.route("/download_alerts")
def download_alerts():
    alerts = get_recent_alerts()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "Alert", "Severity"])

    for a in alerts:
        writer.writerow([
            a.get("local_time") or a.get("timestamp"),
            a.get("src_ip", "N/A"),
            a.get("dest_ip", "N/A"),
            a.get("proto", "N/A"),
            a.get("alert", {}).get("signature", "N/A"),
            a.get("severity", "N/A")
        ])

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"alerts_{timestamp}.csv"

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route("/rules", methods=["GET", "POST"])
def rules():
    alert = None
    saved_sid = None

    if request.method == "POST":
        sid = request.form.get("original_sid")
        updated_rule = request.form.get("updated_rule")
        if sid and updated_rule:
            success, message = update_rule(sid, updated_rule)
            alert = message
            if success:
                saved_sid = sid

    # Always reload rules from file after save
    parsed_rules = []
    for rule in load_rules():
        sid_match = re.search(r"sid\s*:\s*(\d+)", rule)
        parsed_rules.append({
            "sid": sid_match.group(1) if sid_match else "unknown",
            "rule": rule
        })

    logging.info(f"Parsed {len(parsed_rules)} rules for display")

    return render_template("rules.html", rules=parsed_rules, saved_sid=saved_sid, alert=alert, active_page="rules")

@app.route("/delete_rule", methods=["POST"])
def delete_rule():
    sid = request.form.get("sid")
    if not sid:
        flash("No SID provided for deletion.", "error")
        return redirect(url_for("rules"))

    rules = load_rules()
    updated_rules = [r for r in rules if f"sid:{sid};" not in r]

    if len(rules) == len(updated_rules):
        flash("Rule not found or already deleted.", "error")
    else:
        try:
            with open(RULES_FILE, "w") as f:
                f.write("\n".join(updated_rules) + "\n")
            flash(f"Rule with SID {sid} deleted successfully.", "success")
        except Exception as e:
            flash(f"Failed to delete rule: {e}", "error")

    return redirect(url_for("rules"))

@app.route("/faq")
def faq():
    return render_template("faq.html", active_page="faq")

@app.route("/examples")
def examples():
    return render_template("examples.html", active_page="examples")

@app.route("/glossary")
def glossary():
    return render_template("glossary.html", active_page="glossary")

@app.route("/run-pcap", methods=["POST"])
def run_pcap():
    try:
        ip_address = request.remote_addr
        timestamp = datetime.now().isoformat()

        command = ["sudo", "bash", "/home/grantfitz/suricata_nl_gui/scripts/pcap_generator.pcap.sh"]

        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode == 0:
            message = "PCAP replay succeeded"
            pcap_logger.info(f"{timestamp} - {ip_address} - {message}")
            return jsonify({"status": "success", "message": message})
        else:
            error = f"PCAP replay failed: {result.stderr.strip()}"
            pcap_logger.error(f"{timestamp} - {ip_address} - {error}")
            return jsonify({"status": "error", "message": error}), 500

    except Exception as e:
        fallback_ip = request.remote_addr if "request" in locals() else "unknown"
        fallback_time = datetime.now().isoformat()
        pcap_logger.exception(f"{fallback_time} - {fallback_ip} - Unexpected error during PCAP replay")
        return jsonify({"status": "error", "message": "An unexpected error occurred."}), 500

@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        rating = request.form.get("rating")
        comments = request.form.get("comments", "")
        logging.info(f"User feedback - Rating: {rating}, Comments: {comments}")
        flash("Thanks for your feedback!", "info")
        return redirect(url_for("feedback"))

    return render_template("feedback.html", active_page="feedback")

@app.route("/restart-suricata", methods=["POST"])
def restart_suricata():
    try:
        # Stop existing Suricata (no error if not running)
        subprocess.run(["sudo", "pkill", "-f", "suricata"], check=False)

        # Start Suricata on loopback (or eth1 if configured)
        subprocess.run([
            "sudo", "suricata",
            "-i", "lo",  # Change to "eth1" if needed
            "-c", "/etc/suricata/suricata.yaml",
            "-l", "/var/log/suricata"
        ], check=True)

        flash("✅ Suricata restarted successfully.", "success")
    except subprocess.CalledProcessError as e:
        flash(f"⚠️ Failed to restart Suricata: {e}", "error")

    return redirect(url_for("view_logs"))

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)