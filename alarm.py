# !/usr/bin/python3

from scapy.all import *
import argparse
import base64

flags = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08, "URG": 0x20}
usernames = []
passwords = []
incidents_detected = 0

def ip_proto(pkt):
    """ returns the protcol used by a packet

    Args:
        pkt (Scapy Packet): packet from which the protocol is pulled

    Returns:
        String: the protocol used by the packet
    """
    proto_field = pkt[IP].get_field('proto')
    return proto_field.i2s[pkt[IP].proto]

def print_scan_incident(packet, incident, incidents_detected):
    """ Prints an alert corresponding with the detected incident from the packet

    Args:
        packet (Scapy Packet): packet from which the incident was detected
        incident (String): the scan detected as a string
        incidents_detected (int): number of incidents detected
    """
    src_ip = packet[IP].src
    protocol = ip_proto(packet)
    print('ALERT #{}: {} is detected from {} ({})!'.format(          \
                                                incidents_detected,  \
                                                incident, src_ip,    \
                                                protocol))


def packetcallback(packet):
    """ Sniffs for various incidents in packet

    Args:
        packet (Scapy Packet): the packet to be sniffed
    """
    check_NULL_scan(packet)
    check_xmas_scan(packet)
    check_fin_scan(packet)
    check_nikto_scan(packet)
    check_smb_scan(packet)
    check_credentials_ftp(packet)
    check_credentials_imap(packet)
    check_credentials_HTTP(packet)

def check_NULL_scan(packet):
    """ Detects NULL scans in a packet

    Args:
        packet (Scapy Packet): the packet to be sniffed
    """
    global incidents_detected
    try:    
        if packet[TCP].flags == 0:
            incidents_detected += 1
            print_scan_incident(packet, "NULL scan", incidents_detected)
    except: 
        pass

def check_fin_scan(packet):
    """ Detects FIN scans in a packet

    Args:
        packet (Scapy Packet): the packet to be sniffed
    """
    global incidents_detected   
    try:    
        if packet[TCP].flags == flags["FIN"]:
            incidents_detected += 1
            print_scan_incident(packet, "FIN scan", incidents_detected)
    except: 
        pass

def check_xmas_scan(packet):
    """ Detects Xmas scans in a packet

    Args:
        packet (Scapy Packet): the packet to be sniffed
    """
    global incidents_detected   
    try:    
        if packet[TCP].flags == (flags["FIN"] + flags["PSH"] + flags["URG"]):
            incidents_detected += 1
            print_scan_incident(packet, "Xmas scan", incidents_detected)

    except: 
        pass

def check_nikto_scan(packet):  
    """ Detects Nikto scans in a packet

    Args:
        packet (Scapy Packet): the packet to be sniffed
    """
    global incidents_detected 
    try:    
        loadData = str(packet[TCP].load)
        if "Nikto" in loadData or "nikto" in loadData or "NIKTO" in loadData:
            incidents_detected += 1
            print_scan_incident(packet, "NIKTO scan", incidents_detected)

    except: 
        pass

def check_smb_scan(packet):   
    """ Detects SMB scans in a packet

    Args:
        packet (Scapy Packet): the packet to be sniffed
    """
    global incidents_detected
    try:    
        data = str(raw(packet))
        if "SMB" in data:
            incidents_detected += 1
            print_scan_incident(packet, "SMB scan", incidents_detected)
    except: 
        pass

def check_credentials_ftp(packet):  
    """ Detects credentials sent via FTP

    Args:
        packet (Scapy Packet): the packet to be sniffed
    """
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
    """ Detects credentials sent via imap

    Args:
        packet (Scapy Packet): the packet to be sniffed
    """
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
    """ Detects credentials sent via HTTP

    Args:
        packet (Scapy Packet): the packet to be sniffed
    """

    global incidents_detected
    try: 
        if packet[TCP].sport == 80 or packet[TCP].dport == 80:
            data = str(raw(packet))
            if "Authorization: Basic " in data:
                incidents_detected += 1
                parsedData = data.split("Authorization: Basic ")[1].split("\\")
                u_pass_pair = str(base64.b64decode(parsedData[0]))
                u_pass_pair = u_pass_pair[2:len(u_pass_pair)-1]
                parsed_pair = u_pass_pair.split(":")
                usernames.append(parsed_pair[0])
                passwords.append(parsed_pair[1])
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
