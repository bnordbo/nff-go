#!/usr/bin/env bash

SGW_IP=10.37.52.163
INTF_NAME="eth1"
INTF_ADDR="00:06.0"

echo -n "[+] Unbind network interface..."
./dpdk/dpdk/usertools/dpdk-devbind.py --bind=ena $INTF_ADDR > /dev/null
sleep 5
echo "ok"

echo -n "[+] Creating Bearer..."
export $(python3 scripts/create_bearer.py 999990000000001 1234567890 loltel | grep -v "Session" | xargs -d '\n')
echo "ok"

echo -n "[+] Binding interface to DPDK..."
ifdown eth1
./dpdk/dpdk/usertools/dpdk-devbind.py --bind=igb_uio $INTF_ADDR > /dev/null
echo "ok"

echo "[+] Starting GTP-U packets injection..."
./wg2/gtp-u-boom/gtp-u-boom -port 0 -dst-ip 45.8.8.45 -src-ip $SGW_IP -teid $PGWU_TEID -data $GTPU_PAYLOAD

echo -n "[+] Unbind network interface..."
./dpdk/dpdk/usertools/dpdk-devbind.py --bind=ena $INTF_ADDR > /dev/null
sleep 5
echo "ok"

