from scapy.all import *
from randmac import RandMac
import psutil
import secrets
import string
import re
import faker

conf.verb = 0 # Disable Scapy logging
last_message_pattern = ''
fake = faker.Faker()

def encrypt(plain_text, key):
    encrypted_text = ""
    key_index = 0
    
    for char in plain_text:
        key_char = key[key_index % len(key)]
        encrypted_char = chr((ord(char) + ord(key_char)) % 256)
        encrypted_text += encrypted_char
        key_index += 1
    
    return encrypted_text

def decrypt(encrypted_text, key):
    decrypted_text = ""
    key_index = 0
    
    for char in encrypted_text:
        key_char = key[key_index % len(key)]
        decrypted_char = chr((ord(char) - ord(key_char)) % 256)
        decrypted_text += decrypted_char
        key_index += 1
    
    return decrypted_text


def generate_unique_pattern(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    unique_pattern = ''.join(secrets.choice(characters) for _ in range(length))
    return unique_pattern

def list_ifaces(): # List of network interfaces along with their names and MAC addresses.
    addrs = psutil.net_if_addrs()
    ifaces = []
    mac_addresses = []
    i = 1
    for key in addrs.keys(): # Avoid using 'enumerate' since it exhibits different behaviors on various operating systems.
        addresses = addrs[key]
        for addr in addresses:
            if addr.family == psutil.AF_LINK:  # Check for MAC address
                mac_address = addr.address
                print(f"{i}- ({key}): {mac_address}")
                ifaces.append(key)
                mac_addresses.append(mac_address)
                i += 1
                break
    return ifaces, mac_addresses

regex_pattern = r'^(.*?):(.*?):(.*)$'

# Packets consist of two layers. The first layer is Ethernet, which includes a destination address of ff:ff:ff:ff:ff:ff (Broadcast) and a source address that can either be the user's MAC address or a randomly generated MAC address.
# The second layer is RAW, comprising three parts: the chatroom name (not encrypted), the encrypted message (encrypted with the password), and a unique pattern designed to prevent clients from receiving their own messages. (A new unique pattern is generated for each message.)

def packet_handler(packet, title, key): 
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        title_bytes = f"{title}:".encode('utf-8')
        if payload.startswith(title_bytes):
            payload = payload.decode('utf-8')
            matches = re.match(regex_pattern, payload)
            if matches:
                message = matches.group(2)
                pattern = matches.group(3)
                if last_message_pattern == pattern:
                    return
                print(decrypt(message, key))

def start_sniffing(title, interface, key):
    sniff(iface=interface, prn=lambda pkt: packet_handler(pkt, title, key), store=0)

def send_packet(header, data, interface, mac_address, key, name, anonymous):
    global last_message_pattern
    last_message_pattern = generate_unique_pattern(16) # This is used to prevent clients from receiving their own messages
    ether_source = mac_address
    message = name + ": " + data
    if anonymous:
        ether_source = fake.hexify('^^:^^:^^:^^:^^:^^')
        message = "Anonymous: " + data
    ethernet = Ether(src = ether_source, dst = 'ff:ff:ff:ff:ff:ff')
    raw = Raw(load=f"{header}:{encrypt(message, key)}:{last_message_pattern}")
    sendp(ethernet/raw, iface=interface)

def get_interface():
    ifaces, mac_addresses = list_ifaces()
    regex_pattern = r'\d+$'
    while True:
        index = input("Please select the interface number you wish to chat with: ")
        if not re.match(regex_pattern, index):
            print("Invalid command!")
            continue
        index = int(index)
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
    return name, len(name) == 0 # To check if the user wants to remain anonymous or not

def receive_messages(header, iface, password):
    sniff_thread = threading.Thread(target=start_sniffing, args=(header, iface, password,), daemon = True)
    sniff_thread.start()

def send_messages(iface, mac_address, header, name, anonymous, password):
    print("Send '\\' to exit")
    single_back_slash = r'^\\$'
    multiple_back_slash = r'^\\{2,}$'
    while(True):
        message = input()
        if re.match(single_back_slash, message):
            break
        elif re.match(multiple_back_slash, message):
            message = message[1:]
        send_packet(header, message, iface, mac_address, password, name, anonymous)

if __name__ == "__main__":
    print("Welcome to Easy Communicate V1.0.0")
    iface, mac_address = get_interface()
    header, password = get_header_and_password()
    name, anonymous = get_name()
    receive_messages(header, iface, password) # This code begins a daemon thread that waits for messages.
    send_messages(iface, mac_address, header, name, anonymous, password)
    print("Goodbye :)")


