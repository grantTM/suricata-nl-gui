from flask import Flask, render_template, request
import sys
sys.path.append("../scripts")  # So we can import rule logic
from rule_translator import translate_to_suricata, get_next_sid, RULES_FILE, save_rule_to_file

app = Flask(__name__)

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

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
