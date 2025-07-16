from scapy.all import conf 
from backend.app.core.sniffer import start_sniffer, PacketData
from concurrent.futures import ThreadPoolExecutor


# Retrieve all network interfaces available on the current machine using Scapy
interfaces = list(conf.ifaces)


def collect_packets() -> list[PacketData]:
    """
    Runs packet sniffing in parallel threads on all network interfaces
    Returns a list of all captured PacketData objects
    """
    
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(start_sniffer, interfaces))

    return results
