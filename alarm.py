# !/usr/bin/python3

from scapy.all import *
import argparse
import base64
# print(base64.b64decode("YnJvZGdlcnM6VGhleVBsYXllZFdpdGhHcmVhdENoYXJhY3Rlcg=="))
def ip_proto(pkt):
    proto_field = pkt.get_field('proto')
    return proto_field.i2s[pkt.proto]

# x = IP() / TCP()
# print(ip_proto(x))

flags = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08, "URG": 0x20}
incidents_detected = 0
# usernameIndicators = {F}
TCP_REVERSE = dict((k, TCP_SERVICES[k]) for k in TCP_SERVICES.keys())
def packetcallback(packet):
    check_NULL_scan(packet)
    check_xmas_scan(packet)
    check_fin_scan(packet)
    check_nikto_scan(packet)
    # check_smb_scan(packet)
    check_credentials_ftp(packet)
    check_credentials_imap(packet)
    check_credentials_HTTP(packet)

def check_NULL_scan(packet):
    global incidents_detected
    try:    
        if packet[TCP].flags == 0:
            incidents_detected += 1
            src_ip = packet[IP].src
            protocol = ip_proto(packet[IP])
            print('ALERT #{}: {} is detected from {} ({})!'.format( \
                                                        incidents_detected,  \
                                                        "NULL scan", src_ip, \
                                                        protocol))
    except: 
        pass

#FIN, PSH, and URG flags
def check_fin_scan(packet):
    global incidents_detected   
    try:    
        if packet[TCP].flags == flags["FIN"]:
            incidents_detected += 1
            src_ip = packet[IP].src
            protocol = ip_proto(packet[IP])
            print('ALERT #{}: {} is detected from {} ({})!'.format( \
                                                        incidents_detected,  \
                                                        "FIN scan", src_ip, \
                                                        protocol))
    except: 
        pass

def check_xmas_scan(packet):
    global incidents_detected   
    try:    
        if packet[TCP].flags == (flags["FIN"] + flags["PSH"] + flags["URG"]):
            incidents_detected += 1
            src_ip = packet[IP].src
            protocol = ip_proto(packet[IP])
            print('ALERT #{}: {} is detected from {} ({})!'.format( \
                                                        incidents_detected,  \
                                                        "Xmas scan", src_ip, \
                                                        protocol))
    except: 
        pass

def check_nikto_scan(packet):  
    global incidents_detected 
    try:    
        loadData = str(packet[TCP].load)
        if "Nikto" in loadData or "nikto" in loadData or "NIKTO" in loadData:
            incidents_detected += 1
            src_ip = packet[IP].src
            protocol = ip_proto(packet[IP])
            print('ALERT #{}: {} is detected from {} ({})!'.format( \
                                                        incidents_detected,  \
                                                        "NIKTO scan", src_ip, \
                                                        protocol))
    except: 
        pass

x = 0
def check_smb_scan(packet):   
    global x
    x += 1
    if x < 100: 
        try:    
            print(ls(packet))
        except: 
            pass
usernames = []
passwords = []
x = 0
def check_credentials_ftp(packet):  
    global incidents_detected  
    try: 
        data = str(raw(packet))
        if "USER " in data:
            usernames.append(data.split("USER ")[1].split("\\")[0])
        if "PASS " in data:
            passwords.append(data.split("PASS ")[1].split("\\")[0])
            if len(usernames) == len(passwords):
                incidents_detected += 1
                src_ip = packet[IP].src
                payload = "username:{}, password:{}".format(usernames[-1], passwords[-1])
                print('ALERT #{}: Usernames and passwords sent in-the-clear ({}) from {} ({})!'.format( \
                                            incidents_detected,  \
                                            "ftp", \
                                            src_ip, payload))

    except:
        pass

def check_credentials_imap(packet):  
    global incidents_detected 
    try: 
        if packet[TCP].sport == 143 or packet[TCP].dport == 143:
            data = str(raw(packet))
            if " LOGIN " in data:
                incidents_detected += 1
                parsedData = data.split(" LOGIN ")[1].split(" ")
                usernames.append(parsedData[0])
                passwords.append(parsedData[1].replace('\"', "").split("\\")[0])
                src_ip = packet[IP].src
                payload = "username:{}, password:{}".format(usernames[-1], passwords[-1])
                print('ALERT #{}: Usernames and passwords sent in-the-clear ({}) from {} ({})!'.format( \
                                            incidents_detected,  \
                                            "imap", \
                                            src_ip, payload))
    except:
        pass

def check_credentials_HTTP(packet):   
    global incidents_detected
    try: 
        if packet[TCP].sport == 80 or packet[TCP].dport == 80:
            data = str(raw(packet))
            if "Authorization: Basic " in data:
                incidents_detected += 1
                parsedData = data.split("Authorization: Basic ")[1].split("\\")
                pair = str(base64.b64decode(parsedData[0]))
                pair = pair[2:len(pair)-1]
                u_pass = pair.split(":")
                usernames.append(u_pass[0])
                passwords.append(u_pass[1])
                src_ip = packet[IP].src
                payload = "username:{}, password:{}".format(usernames[-1], passwords[-1])
                print('ALERT #{}: Usernames and passwords sent in-the-clear ({}) from {} ({})!'.format( \
                                            incidents_detected,  \
                                            "HTTP", \
                                            src_ip, payload))
    except:
        pass



parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
    try:
        print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
        sniff(offline=args.pcapfile, prn=packetcallback)              
    except:
        print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
    print("Sniffing on %(interface)s... " % {"interface" : args.interface})
    try:
        sniff(iface=args.interface, prn=packetcallback)
    except:
        print("Sorry, can\'t read network traffic. Are you root?")
