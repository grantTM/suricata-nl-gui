
TARGET="127.0.0.1"
INTERFACE="lo"
PCAP_FILE="suricata_rules_test.pcap"
WEB_DIR="./web_root"

# Set up a dummy HTTP server root
mkdir -p $WEB_DIR/downloads
echo "This is a fake .exe payload" > $WEB_DIR/downloads/malware.exe
echo "<html><body>SQL Result: admin</body></html>" > $WEB_DIR/index.php
echo "<html><body>Agent Check</body></html>" > $WEB_DIR/agent-check
echo "<html><body>Login Page</body></html>" > $WEB_DIR/login

# Start Python HTTP server in background
cd $WEB_DIR || exit
python3 -m http.server 80 >/dev/null 2>&1 &
HTTP_PID=$!
cd ..

# Give server time to start
sleep 2

echo "Starting traffic capture..."
sudo tcpdump -i $INTERFACE -w $PCAP_FILE &
TCPDUMP_PID=$!
sleep 2

# 1. ICMP (Ping)
ping -c 3 $TARGET

# 2. External SSH Attempt
nc -zv $TARGET 22

# 3. SSH Brute Force (6 Attempts)
for port in 10001 10002 10003 10004 10005 10006; do
  sudo hping3 -S -p 22 -s $port -c 1 127.0.0.1 >/dev/null 2>&1
done

# 4. Port Scan
nmap -p 21-25 $TARGET

# 5. SQL Injection in HTTP GET
curl "http://$TARGET/index.php?user=admin&query=select+password+from+users"

# 6. Suspicious User-Agent
curl -A "curl/7.79.1" "http://$TARGET/agent-check"

# 7. Executable File Download
curl -O "http://$TARGET/downloads/malware.exe"

# 8. XSS Payload via POST
curl -X POST -d "<script>alert('xss')</script>" "http://$TARGET/login"

#9. Internal SMB Connection (to Port 445)
nc -zv $TARGET 445

# Finish
sleep 2
if ps -p $TCPDUMP_PID > /dev/null; then
  sudo kill -INT $TCPDUMP_PID
fi
kill $HTTP_PID
sleep 1
echo "PCAP created: $PCAP_FILE"
rm -rf $WEB_DIR
