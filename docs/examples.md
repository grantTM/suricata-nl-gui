
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
| `sid`				| Unique signature ID (you addign these; best to start > 1,000,000)	|
| `rev`				| Revision number of the rule (for versioning)				|

Additional options like `flow`, `threshold`, `dsize`, `content`, and `itype` refine what traffic matches.
You will see these components reused in the examples below.


### 1. SSH Brute Force Attempt

**Input:**
alert on brute force login attempts over SSH

**Generated Rule:**
```suricata
alert tcp any any -> any 22 (msg:"Potential SSH brute force login attempt"; flow:to_server,established; threshold: type both, track by_src, count 5, seconds 60; sid 1000001; rev:1;)
```

**Explanation:**
Triggers if 5 or more login attempts are made over SSH (port 22) to a server within 60 seconds

---

### 2. SSH from External IP

**Input:**
alert me on SSH from outside IP

**Generated Rule:**
```suricata
alert tcp !$HOME_NET any -> $HOME_NET 22 (msg:"External SSH connection attempt"; flow:to_server,established; sid:1000002; rev:1;)
```

**Explanation:**
Detects incoming SSH traffic from outside your network

---

### 3. Suspicious DNS Lookup

**Input:**
`detect DNS lookups to strange domains`

**Generated Rule:**
```alert udp any any -> any 53 (msg:"Suspicious DNS Query"; content:".xyz"; nocase; sid:1000003; rev:1;)```

**Explanation**
Flags DNS requests that include ".xyz" --- often used in malicious domains. Content can be modified by editing the rule after generation

---

### 4. Web Server Access Flood

**Input:**
`alert on more than 10 requests to web server in 30 seconds`

**Generated Rule:**
```alert tcp any any -> $HOME_NET 80 (msg:"Web server access flood"; flow:to_server,established; threshold:type both, track_by_src, count 10, seconds 30; sid:1000004; rev:1;)```

**Explanation:**
Helps detect early signs of a DDoS attack or aggressive scanning behavior

---

### 5. File Exfiltration Attempt

**Input:**
`alert on large outbound file transfers`

**Generated Rule:**
```alert tcp $HOME_NET any -> !$HOME_NET any (msg:"Possible file exfiltration"; flow:to_server,established; dsize:>1000; sid:1000005; rev:1;)```

**Explanation:**
Detects large data transfers originating from hosts to external destinations

---

### 6. ICMP Ping Sweep

**Input:**
`detect ping sweep`

**Generated Rule:**
```alert icmp any any -> any any (msg:"Ping sweep detected"; itype:8; sid:1000006; rev:1;)```

**Explanation:**
Flags basic ICMP echo request commonly used to map active hosts.

---

# Tips

- Grammar doesn't have to be perfect - the rule translator is looking for the existence of certain keywords to build rules (`SSH`, `alert`, `DNS`, `brute force`, etc.)
- All generated rules are stored in `rules/my.rules`
- Advanced users can manually edit the file for fine-tuning/implementation of [flowbit logic](https://docs.suricata.io/en/latest/rules/flow-keywords.html)

# Want to Contribute?

Send suggestions or rule ideas to the project maintainer or open an issue on GitHub

