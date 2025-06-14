
# Frequently Asked Questions (FAQ)

This FAQ covers common questions from users deploying the SME IDS tool.

---

### Do I need to be a cybersecurity expert to use this?

No! The goal of this project was to help solve a couple problems small and medium-sized enterprises face every day, but specific to the question, with lack of experienced personnel. The GUI allows you to enter plain English that gets translated into a Suricata rule. Remember that time you were able to code something and didn't have to know the precise syntax? Wait...me either.

---

### I'm getting alerted, but don't think I'm being attacked. What gives?

Some alerts like ICMP pings and DNS requests are most often a part of normal system activity, BUT...attackers know this is a vector that might get overlooked. If they get a successful response from your system, they've found some low-hanging fruit. Better safe than sorry.

---

### Where are the alerts coming from?

I've given you a baseline of alerts to give you a head start in bad guy detection. You might've already created a couple yourself. If you did and see it on the log page of the GUI, congrats! You caught some traffic and are well on your way to becomming a cyber supersleuth.

---

### Do I need to test this on a real network?

Nope! You can try detecting traffic by:
- Using `sample-eve.json` in the `logs/` folder
- Generating controlled traffic (like `ping` or `nmap`, but be careful with that one...your place of work might frown on the existence of nmap anywhere near their networks) between two devices

---

### Can I view or edit the Suricata rules directly?

You betcha! All of the rules are written to the `rules/my.rules` file. You can open and modify them manually using any text editor. If you do edit a rule, please ensure that you have not introduced a duplicate SID to the ruleset. Each rule should have a unique `sid` and should pass Suricata's validation check (`suricata -T`).

---

### Is this tool secure?

Are you sure you're not a cyber pro? By default, the web interface only runs locally at `localhost:5000`. If you expose it to other machines or use `ngrok`, consider the following:
- Adding basic authentication/password protection
- Keeping the rule editor behind a firewall or VPN. Remember, HTTP, your ISP (and therefore, a bad actor that's gained access to your system) can see everything you're looking at on a web page. HTTPS, your ISP can see that you're on a page, but nothing else. If you're behind a VPN, they can see that you're online, but your traffic is fully encrypted.

---

### Can I share this with others?

Yes! The more, the merrier. You can do the following:
- Share the GitHub link
- Package it with Docker (coming soon)
- Point others to the documentation in `docs/`

---

### How do I update my instance to make sure I have the most up-to-date version of rules and documentation?

```bash
git pull origin main
```
