
# Rule Examples

This page shows how plain-English input gets translated into Suricata rules using the SME Suricata IDS tool. These examples are designed to help new users understand what can be accomplished with the tool and how to phrase detection requests

---

## Anatomy of a Suricata Rule

A Suricata rule generally looks like this:

```suricata
alert tcp any any -> $HOME_NET 22 (msg:"SSH Connection"; sid:1000001; rev:1;)
```

| Component			| Meaning								|
|-------------------------------|-----------------------------------------------------------------------|
| `alert`			| The action to take (e.g., `alert`, `drop`, `pass`			|
| `tcp`				| The protocol to inspect (`tcp` ,`udp` ,`icmp`, etc.			|
| `any any -> $HOME_NET 22`	| Traffic from anywhere to port 22 in your network			|
| `msg`				| A human-readable message attached to the alert			|
| `sid`				| Unique signature ID (you assign these; best to start > 1,000,000)	|
| `rev`				| Revision number of the rule (for versioning)				|

Additional options like `flow`, `threshold`, `dsize`, `content`, and `itype` refine what traffic matches.
You will see these components reused in the examples below.

---
### 1. External SSH Attempt

**Input:**
`alert on external ssh attempt`

**Generated Rule:**
```suricata
alert tcp any any -> any 22 (msg:"External SSH attempt detected"; flow:to_server; flags:S; sid 1000001; rev:1;)
```

**Explanation:**
Triggers on external TCP SYN packets sent to port 22 (SSH), alerting to unwanted connection attempts

### 2. ICMP Traffic

**Input:**
`alert on icmp traffic`

**Generated Rule:**
```suricata
alert icmp any any -> any any (msg:"ICMP traffic detected"; sid:1000002; rev:1;)
```

**Explanation:**
Flags any ICMP activity (e.g., ping scans), often used in network reconnaissance

### 3. Port Scan Detection

**Input:**
`alert on port scan`

**Generated Rule:**
```suricata
alert ip any any -> any any (msg:"Potential port scan detected"; threshold:type both, track by_src, count 20, seconds 5; sid:1000003; rev:1;)
```

**Explanation**
Detects possible scanning behavior by monitoring for 20 connection attempts in 5 seconds from the same source

### 4. SSH Brute Force

**Input:**
`alert on ssh brute force`

**Generated Rule:**
```suricata
alert tcp any any -> any 22 (msg:"Possible SSH brute force attempt"; flags:S; threshold:type both, track by_src, count 2, seconds 30; sid:1000004; rev:1;)
```

**Explanation:**
Flags repeated connection attempts to SSH within a short time frame, indicating brute force attempts

### 5. SQL Injection Attempt

**Input:**
`alert on SQL injection`

**Generated Rule:**
```suricata
alert http any any -> any any (msg:"Possible SQL injection Attempt"; content:"select"; nocase; http_uri: pcre:"/select.+from/i"; classtype:web-application-attack; sid:1000005; rev:1;)
```

**Explanation:**
Matches suspicious SQL keywords and patterns in HTTP URI traffic, signaling possible injection attacks

### 6. Suspicious User-Agent

**Input:**
`alert on suspicious user agent`

**Generated Rule:**
```suricata
alert http any any -> any any (msg:"Suspicious User-Agent Detected"; content:"User-Agent|3A|"; http_header; content:"curl"; nocase; distance:0; classtype:trojan-activity; sid:1000006; rev:1;)
```

**Explanation:**
Flags HTTP requests using automated tools like `curl`, often linked to scanning or exploitation.

### 7. Executable File Download

**Input:**
`alert on exe download`

**Generated Rule:**
```suricata
alert http any any -> any any (msg:"Executable File Download Detected"; flow:established,to_client; content:".exe"; http_uri; claddtype:bad-unknown; sid:1000007; rev:1;)
```

**Explanation:**
Detects HTTP downloads of `.exe` files, commonly associated with malware delivery

### 8. Cross-Site Scripting (XSS)

**Input:**
`alert on xss attack`

**Generated Rule:**
```suricata
alert http any any -> any any (msg:"Potential XSS Attempt"; content:"<script>"; nocase; http_client_body; classtype:web-application-attack; sid:1000008; rev:1;)
```

**Explanation:**
Triggers on `script` tags in HTTP client data, an obvious indicator of XSS

### 9. Internal SMB Lateral Movement

**Input:**
`alert on lateral movement with smb`

**Generated Rule:**
```suricata
alert tcp [10.0.0.0/8] any -> [10.0.0.0/8] 445 (msg:"Internal SMB Traffic - Potential Lateral Movement"; flow:to_server, established; content:"SMB"; nocase; classtype:policy-violations; sid:1000009; rev:1;)

---

# Tips

- Grammar doesn't have to be perfect - the rule translator is looking for the existence of certain keywords to build rules (`SSH`, `alert`, `DNS`, `brute force`, etc.)
- All generated rules are stored in `rules/my.rules`
- Advanced users can manually edit the file for fine-tuning/implementation of [flowbit logic](https://docs.suricata.io/en/latest/rules/flow-keywords.html)

---

# Want to Contribute?

Send suggestions or rule ideas to the project maintainer or open an issue on GitHub
