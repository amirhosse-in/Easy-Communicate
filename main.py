from scapy.all import *
from randmac import RandMac
import psutil
import secrets
import string
import re

conf.verb = 0 # Disable Scapy logging

def generate_unique_pattern(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    unique_pattern = ''.join(secrets.choice(characters) for _ in range(length))
    return unique_pattern

def list_ifaces():
    addrs = psutil.net_if_addrs()
    ifaces = []
    mac_addresses = []
    for i, key in enumerate(addrs.keys()):
        addresses = addrs[key]
        for addr in addresses:
            if addr.family == psutil.AF_LINK:  # Check for MAC address
                mac_address = addr.address
                print(f"{i}- ({key}): {mac_address}")
                ifaces.append(key)
                mac_addresses.append(mac_address)
                break
    return ifaces, mac_addresses

regex_pattern = r'^(.*?):(.*?):(.*)$'

def packet_handler(packet, title, unique_pattern):
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        title_bytes = f"{title}:".encode('utf-8')
        if payload.startswith(title_bytes):
            payload = payload.decode('utf-8')
            matches = re.match(regex_pattern, payload)
            if matches:
                header = matches.group(1)
                message = matches.group(2)
                unique_ptrn = matches.group(3)
                if unique_pattern == unique_ptrn:
                    return
                print(message)

def start_sniffing(title, interface, unique_pattern):
    sniff(iface=interface, prn=lambda pkt: packet_handler(pkt, title, unique_pattern), store=0)

def send_packet(header, data, interface, mac_address, unique_pattern):
    ether_source = mac_address
    eth = Ether(src = ether_source, dst = 'ff:ff:ff:ff:ff:ff')
    r = Raw(load=f"{header}:{data}:{unique_pattern}")
    x = sendp(eth/r, iface=interface)

def get_interface():
    ifaces, mac_addresses = list_ifaces()
    while True:
        index = int(input("Please select the interface number you wish to chat with: "))
        if index > 0 and index <= len(ifaces):
            index -= 1
            break
        else:
            print("Invalid command!")
    return ifaces[index], mac_addresses[index]

def get_header_and_password():
    while True:
        header = input("Input your chatroom's name: ")
        if len(header) != 0:
            break
    while True:
        password = input("Input chatroom's password: ")
        if len(password) != 0:
            break
    return header, password

def get_name():
    name = input("Please provide your name (press enter to remain anonymous): ")
    return name, len(name) == 0 # To check if user want to remain anonymous

def receive_messages(header, iface, unique_pattern):
    sniff_thread = threading.Thread(target=start_sniffing, args=(header,iface,unique_pattern,), daemon = True)
    sniff_thread.start()

def send_messages(iface, mac_address, header, unique_pattern, name, anonymous):
    while(True):
        message = input()
        send_packet(header, message, iface, mac_address, unique_pattern)

packet_title = 'ECV1' # For first version of Easy Communicate
packet_data = 'This is the content of the broadcast packet.'

if __name__ == "__main__":
    print("Welcome to Easy Communicate V1.0.0")
    unique_pattern = generate_unique_pattern(16)
    iface, mac_address = get_interface()
    header, password = get_header_and_password()
    name, anonymous = get_name()
    receive_messages(header, iface, unique_pattern) # It just starts a daemon thread to receive messages
    send_messages(iface, mac_address, header, unique_pattern, name, anonymous)


