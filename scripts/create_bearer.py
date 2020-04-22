#!/usr/bin/env python3

from scapy.all import rdpcap, IP, ICMP
from scapy.contrib import gtp, gtp_v2
from optparse import OptionParser
import socket
import sys

PGW_IP="45.8.8.45"
IMCP_DST_IP="185.76.9.133"

def parse_opt():
    usage = "usage: %prog [options] IMSI MSISDN APN"
    parser = OptionParser(usage)
    (options, args) = parser.parse_args()
    if len(args) != 3:
        parser.error("incorrect number of arguments")
        parser.print_usage()
        sys.exit(255)
    return sys.argv[1:]

def create_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 10000))
    sock.connect(('45.8.8.45', 2123))
    return sock

def get_gtp_packet(imsi, msisdn, apn):
    gtpc = rdpcap('traces/gtpv2-create-session-request.pcap')[0]["GTP v2 Header"]
    gtpc["GTPv2 Create Session Request"]["IE IMSI"].IMSI=imsi
    gtpc["GTPv2 Create Session Request"]["IE APN"].APN='{}.mnc099.mcc999.gprs'.format(apn)
    gtpc["GTPv2 Create Session Request"]['IE MSISDN'].digits=msisdn
    #gtpc.show()
    return gtpc.build()


if "__main__" == __name__:
    imsi, msisdn, apn = parse_opt()
    gtpc = get_gtp_packet(imsi, msisdn, apn)
    sock = create_socket()
    sock.send(gtpc)
    data = sock.recv(256)
    sock.close()
    resp = gtp.GTPHeader(data)
    if (resp["GTPv2 Create Session Response"]["IE Cause"].Cause == 16):
        # request aceptec
        pgwu_teid = resp["GTPv2 Create Session Response"]["IE F-TEID"].GRE_Key
        allocated_ip = resp["GTPv2 Create Session Response"]["IE PAA"].ipv4
        icmp_packet = IP(src=allocated_ip, dst=ICMP_DST_IP)/ICMP()
        print("Session created.\nIP={}\nPGWU_TEID={}\nGTPU_PAYLOAD={}".format(allocated_ip, pgwu_teid, icmp_packet.build().hex()))
    else:
        print("Failed to create session")
        resp.show()
        sys.exit(1)

