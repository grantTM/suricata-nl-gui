import re
import os

RULES_FILE = os.path.expanduser("~/suricata_nl_gui/rules/my.rules")
SID_START = 1000003 # Starting SID range for custom rules

def get_next_sid(filepath):
    if not os.path.exists(filepath):
        return SID_START

    sid_pattern = re.compile(r"sid:(\d+);")
    max_sid = SID_START - 1

    with open(filepath, "r") as f:
        for line in f:
            match = sid_pattern.search(line)
            if match:
                max_sid = max(max_sid, int(match.group(1)))
    return max_sid + 1

def translate_to_suricata(nl_input, sid):
    nl_input = nl_input.lower().strip()

    if "ssh" in nl_input and "external" in nl_input:
        return f'alert tcp any any -> any 22 (msg:"External SSH attempt detected"; flow:to_server; flags:S; sid:{sid}; rev:1;)'

    elif "icmp" in nl_input:
        return f'alert icmp any any -> any any (msg:"ICMP traffic detected"; sid:{sid}; rev:1;)'

    elif "port scan" in nl_input:
        return f'alert ip any any -> any any (msg:"Potential port scan detected"; threshold:type both, track by_src, count 20, seconds 5; sid:{sid}; rev:1;)'

    else:
        return None

def normalize_rule(rule):
    """
    Strip SID and REV, and normalize spacing and case for duplicate comparison.
    """
    rule = re.sub(r"sid:\d+; *", "", rule)
    rule = re.sub(r"rev:\d+;?", "", rule)
    return rule.strip().lower()

def rule_exists(rule, filepath=RULES_FILE):
    """
    Compare rule logic (ignoring SID/REV) against existing rules.
    """
    if not os.path.exists(filepath):
        return False
    
    new_logic = normalize_rule(rule)

    with open(filepath, "r") as f:
        for line in f:
            if normalize_rule(line) == new_logic:
                return True
    return False

def save_rule_to_file(rule, filepath=RULES_FILE):
    """
    Save rule to file only if it's not a duplicate.
    """
    if rule_exists(rule, filepath):
        print("⚠️ Duplicate rule detected. Rule not saved.")
        return
    
    try:
        with open(filepath, "a") as f:
            f.write(rule + "\n")
        print(f"\n✅ Rule saved to: {filepath}")
    except Exception as e:
        print(f"❌ Failed to save rule: {e}")


if __name__ == "__main__":
    print("🛡️  Natural Language to Suricata Rule Translator\n")
    while True:
        user_input = input("💬 Enter a plain-English detection rule (or type 'exit'): ")
        if user_input.lower() == 'exit':
            break
        sid = get_next_sid(RULES_FILE)
        rule = translate_to_suricata(user_input, sid)
        if rule:
            print("\n🧾 Generated Suricata Rule:")
            print(rule)
            save_rule_to_file(rule)
        else:
            print("⚠️ Unable to translate input to Suricata rule.")
        print("-" * 60)