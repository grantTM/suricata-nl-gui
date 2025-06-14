
# SME IDS: Lightweight Intrusion Detection for Small Business using Suricata

This project provides a user-friendly intrusion detection system (IDS) for small and midsized enterprises that often lack full-time cybersecurity staff or access to enterprise grade tools.

The tool uses [Suricata](https://suricata.io) as the detection engine and includes:
- A lightweight, browser-based GUI for writing plain-English rules
- Real-time alert viewing from Suricata's `eve.json` log
- A natural language rule translator that turns basic descriptions into working threat detection logic
- Optional Docker support for easy deployment

**Built for usability** - no SIEMs, threat intel feeds, or full-time SOC analyst required

---

## Features

---

- Alert viewer (auto-refresh, top IP summary, local timestamps)
- Natural language rule creation (e.g. "alert on SSH from outside IP")
- Editable rule thresholds and preview before saving
- Dark/light mode support with persistence
- Minimal system requirements to run (Kali Linux or Docker)

---

## Target Audience

This tool is intended for:
- IT generalists at a small business without a cyber-focused background
- Students or hobbyists learning IDS concepts
- Security teams that may want to prototype alert logic in a GUI

Common feedback from small businesses or those familiar with them is that *"We don't have time or budget for enterprise-grade security"*. If that's you, this project is for you!

---

## Getting Started

See [`docs/quickstart.md`](./quickstart.md) to launch the tool on your system or try it with Docker
