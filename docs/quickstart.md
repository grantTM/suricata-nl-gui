
# Quick Start Guide: Running the SME IDS App

This guide will teach you how to launch the natural-language Suricata GUI tool.

---

## Option 1: Run with Python (local)

### Setup Instructions

#### Linux (Debian-based like Kali or Ubuntu)

```bash
sudo apt update
sudo apt install python3 python3-pip suricata
pip3 install -r requirements.txt
cd app
python3 app.py
```

#### macOS (using Homebrew)

```bash
brew install python3 suricata
pip3 install -r requirements.txt
cd app
python3 app.py
```
Note: You may need to allow Python network access under System Prefereces > Security & Privacy

#### Windows (using PowerShell)

1. Install [Python 3](https://www.python.org/downloads) and ensure it's added to your PATH.
2. Install [Suricata for Windows](https://suricata.io/download/)
3. Open PowerShell and run:
```powershell

pip install -r requirements.txt
cd app
python app.py
```
### Access the Web App

Once running, open your browser and go to:
```arduino

http://localhost:5000
```
This is your local interface to add rules, view logs, and manage alerts.

## Option 2: Run with Docker (Coming Soon)

A Docker container version of the app will be released to simplify deployment across:
- Windows (via Docker Desktop + WSL2)
- macOS (Intel or M1/M2)
- Linux (local)

When ready, you'll run:
```bash

docker run -p 5000:5000 grantfitz/sme-ids:latest
```
Stay tuned for the full Dockerfile and image publishing instructions.

## Project Folder Overview

| Path			| Purpose					|
|-----------------------|-----------------------------------------------|
|`app/`			| Flask app files and HTML templates		|
|`rules/my.rules`	| Suricata rules written from GUI		|
|`logs/eve.json`	| Alert log (auto-parsed by GUI)		|
|`scripts/`		| Natural language rule translator		|
|`docs/`		| Documentation files (README, examples, etc,)	|

## Verifying Suricata Alerts

To manually check that Suricata is generating alerts:

```bash

tail -f /var/log/suricata/eve.json
```
This will help to verify the engine is runing and parsing live traffic (or test payloads).
The GUI auto-refreshes every 10 seconds on the "View Logs" tab.

## Help and Support
- `docs/examples.md`: Sample rule input and resulting Suricata syntax
- `docs/glossary.md`: Plain-language explanations of common IDS terms
- Still in a rut? Contact the dev or file an issue on GitHub.



