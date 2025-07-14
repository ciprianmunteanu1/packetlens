from scapy.all import (
    sniff,
    Ether,
    IP,
    TCP,
    UDP,
    ARP,
    IPv6,
    Raw,
    ICMP,
)
from scapy.layers.inet6 import (
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    ICMPv6ND_NS,
    ICMPv6ND_NA,
    ICMPv6Unknown,
)
from scapy.layers.inet import icmptypes
from datetime import datetime
from dataclasses import dataclass
from typing import Optional

@dataclass
class PacketData:
    """Class for storing sniffed packets info"""
    timestamp: str

    # Ether
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    eth_type: Optional[str] = None
    interface: Optional[str] = None

    # IP
    protocol: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None

    # TCP / UDP
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    flags: Optional[str] = None
    payload: Optional[str] = None

    # ICMP
    icmp_type: Optional[str] = None
    code: Optional[int] = None


icmpv6_types = {
    1: "destination-unreachable",
    2: "packet-too-big",
    3: "time-exceeded",
    4: "parameter-problem",
    128: "echo-request",
    129: "echo-reply",
    133: "router-solicitation",
    134: "router-advertisement",
    135: "neighbor-solicitation",
    136: "neighbor-advertisement",
    137: "redirect",
    141: "inverse-nd-solicitation",
    142: "inverse-nd-advertisement",
    148: "certification-path-solicitation",
    149: "certification-path-advertisement",
    151: "multicast-listener-query",
    152: "multicast-listener-report",
    153: "multicast-listener-done",
}


def dissect_packet(packet, interface: str) -> PacketData:
    # PacketData object fields
    obj_timestamp = datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S")

    obj_src_mac = None
    obj_dst_mac = None
    obj_eth_type = None
    obj_interface = interface

    obj_protocol = None
    obj_src_ip = None
    obj_dst_ip = None

    obj_src_port = None
    obj_dst_port = None
    obj_flags = None

    obj_icmp_type = None
    obj_code = None

    obj_payload = None

    # Ethernet Layer
    if Ether in packet:
        obj_src_mac = packet[Ether].src
        obj_dst_mac = packet[Ether].dst
        obj_eth_type = packet[Ether].sprintf("%Ether.type%").lower()

        if ARP in packet:
            obj_src_ip = packet[ARP].psrc
            obj_dst_ip = packet[ARP].pdst

    has_ip_layer = False
    if IP in packet:
        obj_src_ip = packet[IP].src
        obj_dst_ip = packet[IP].dst
        obj_protocol = packet[IP].sprintf("%IP.proto%").lower()
        has_ip_layer = True

    elif IPv6 in packet:
        obj_src_ip = packet[IPv6].src
        obj_dst_ip = packet[IPv6].dst
        obj_protocol = packet[IPv6].sprintf("%IPv6.nh%").lower()
        has_ip_layer = True

    if has_ip_layer:
        if TCP in packet:
            obj_src_port = packet[TCP].sport
            obj_dst_port = packet[TCP].dport
            obj_flags = str(packet[TCP].flags)
        elif UDP in packet:
            obj_src_port = packet[UDP].sport
            obj_dst_port = packet[UDP].dport
        elif ICMP in packet:
            obj_icmp_type = icmptypes.get(packet[ICMP].type, str(packet[ICMP].type))
            obj_code = packet[ICMP].code
        else:
            # Check for ICMPv6 layers
            icmpv6_layer = None
            for icmpv6_cls in [
                ICMPv6EchoRequest,
                ICMPv6EchoReply,
                ICMPv6ND_NS,
                ICMPv6ND_NA,
                ICMPv6Unknown,
            ]:
                if packet.haslayer(icmpv6_cls):
                    icmpv6_layer = packet.getlayer(icmpv6_cls)
                    break

            if icmpv6_layer:
                icmp_type_num = icmpv6_layer.type
                obj_icmp_type = icmpv6_types.get(
                    icmp_type_num, str(icmp_type_num)
                )
                obj_code = icmpv6_layer.code
                obj_protocol = "icmpv6"

    if Raw in packet:
        obj_payload = packet[Raw].load

    return PacketData(
        timestamp=obj_timestamp,
        src_mac=obj_src_mac,
        dst_mac=obj_dst_mac,
        eth_type=obj_eth_type,
        interface=obj_interface,
        protocol=obj_protocol,
        src_ip=obj_src_ip,
        dst_ip=obj_dst_ip,
        src_port=obj_src_port,
        dst_port=obj_dst_port,
        flags=obj_flags,
        payload=obj_payload,
        icmp_type=obj_icmp_type,
        code=obj_code,
    )


packet_lst = []


def handle_packet(packet, interface: str):
    dissected_packet = dissect_packet(packet, interface)

    protocol_str = dissected_packet.protocol

    # Selecting only protocols from this list or ARP
    if ARP in packet or protocol_str in ["udp", "tcp", "icmp", "icmpv6"]:
        packet_lst.append(dissected_packet)
        print(dissected_packet)


def start_sniffer(interface: str):
    sniff(
        count=20,
        iface=interface,
        prn=lambda pkt: handle_packet(pkt, interface),
        store=False,
        timeout = 10,
        stop_filter=lambda x: len(packet_lst) == 20,
    )


if __name__ == "__main__":
    start_sniffer("lo0")
