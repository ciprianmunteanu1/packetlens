from scapy.all import conf 
from sniffer import start_sniffer
from concurrent.futures import ThreadPoolExecutor

# Get all interfaces on the current machine
interfaces = list(conf.ifaces)

# Merge results from all threads sniffing on interfaces
with ThreadPoolExecutor() as executor:
    results = list(executor.map(start_sniffer, interfaces))
