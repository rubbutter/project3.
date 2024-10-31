from scapy.all import *
import sys

# Complete this function!
def process_pcap(pcap_fname):
    for pkt in PcapReader(pcap_fname):
        # Your code here
        pass

if __name__=='__main__':
    if len(sys.argv) != 2:
        print('Use: python3 detector.py file.pcap')
        sys.exit(-1)
    process_pcap(sys.argv[1])
