import re
import os

RULES_FILE = os.path.expanduser("~/suricata_nl_gui/rules/my.rules")
SID_START = 1000001 # Starting SID range for custom rules

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

    elif "brute force" in nl_input and "ssh" in nl_input:
        return f'alert tcp any any -> any 22 (msg:"Possible SSH brute force attempt"; flags:S; threshold:type both, track by_src, count 2, seconds 30; sid:{sid}; rev:1;)'

    elif "sql injection" in nl_input:
        return f'alert http any any -> any any (msg:"Possible SQL injection Attempt"; content:"select"; nocase; http_uri; pcre:"/select.+from/i"; classtype:web-application-attack; sid:{sid}; rev:1;)'

    # Suspicious User-Agent (Phishing/Malware)
    elif "suspicious user agent" in nl_input:
        return f'alert http any any -> any any (msg:"Suspicious User-Agent Detected"; content:"User-Agent|3A|"; http_header; content:"curl"; nocase; distance:0; classtype:trojan-activity; sid:{sid}; rev:1;)'
    
    # Malicious File Download (Executable)
    elif "exe download" in nl_input or ".exex file download" in nl_input:
        return f'alert http any any -> any any (msg:"Executable File Download Detected"; flow:established,to_client; content:".exe"; http_uri; classtype:bad-unknown; sid:{sid}; rev:1;)'
    
    # XSS Attack (Web App)
    elif "cross-site scripting" in nl_input or "xss attack" in nl_input:
        return f'alert http any any -> any any (msg:"Potential XSS Attempt"; content:"<script>"; nocase; http_client_body; classtype:web-application-attack; sid:{sid}; rev:1;)'
    
    # Internal Lateral Movement
    elif "internal smb connection" in nl_input or "lateral movement" in nl_input:
        return f'alert tcp [10.0.0.0/8] any -> [10.0.0.0/8] 445 (msg:"Internal SMB Traffic - Potential Lateral Movement"; flow:to_server, established; content:"SMB"; nocase; classtype:policy-violation; sid:{sid}; rev:1;)'

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