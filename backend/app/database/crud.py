from sqlalchemy.orm import Session
from backend.app.database.models import Packet
from sqlalchemy import func, and_, or_
from backend.app.core.sniffer import start_sniffer
from backend.app.core.threading_manager import collect_packets
from datetime import datetime
from typing import Optional, List


# Inserts packets captured from a specific network interface into the database and returns their count
def add_iface_packets_to_db(session: Session, interface: str) -> int:
    # Add packets to database
    packet_list = start_sniffer(interface)
    count = 0
    for packet in packet_list:
        count += 1
        session.add(
            Packet(
                timestamp=datetime.strptime(packet.timestamp, "%Y-%m-%d %H:%M:%S") if packet.timestamp else None,
                src_mac=packet.src_mac,
                dst_mac=packet.dst_mac,
                eth_type=packet.eth_type,
                interface=packet.interface,
                protocol=packet.protocol,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                flags=packet.flags,
                payload=str(packet.payload) if packet.payload else None,
                icmp_type=packet.icmp_type,
                code=packet.code
            )
        )

    session.commit()
    return count


# Inserts packets captured concurrently from all interfaces into the database and returns the total count
def add_all_packets_to_db(session: Session) -> int:
     # Add packets to database
    packet_lists = collect_packets()
    count = 0
    for sublist in packet_lists:
        for packet in sublist:
            count += 1
            session.add(
                Packet(
                    timestamp=datetime.strptime(packet.timestamp, "%Y-%m-%d %H:%M:%S") if packet.timestamp else None,
                    src_mac=packet.src_mac,
                    dst_mac=packet.dst_mac,
                    eth_type=packet.eth_type,
                    interface=packet.interface,
                    protocol=packet.protocol,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    flags=packet.flags,
                    payload=str(packet.payload) if packet.payload else None,
                    icmp_type=packet.icmp_type,
                    code=packet.code
                )
            )

    session.commit()
    return count
    

# Functions for querying packets based on various filters
def get_all_packets(session: Session) -> List[Packet]:
    results = session.query(Packet).all()
    return results


def filter_by_protocol(session: Session, protocol: Optional[str]) -> List[Packet]:
    if protocol is None:
        return []

    results = session.query(Packet).filter(Packet.protocol == protocol).all()
    return results


def filter_by_interface(session: Session, interface: Optional[str]) -> List[Packet]:
    if interface is None:
        return []

    results = session.query(Packet).filter(Packet.interface == interface).all()
    return results


def filter_by_ip(session: Session, src_ip: Optional[str] = None, dst_ip: Optional[str] = None) -> List[Packet]:
    if src_ip is None and dst_ip is None:
        return []
    
    query = session.query(Packet)
    if src_ip:
        query = query.filter(Packet.src_ip == src_ip)
    if dst_ip:
        query = query.filter(Packet.dst_ip == dst_ip)

    results = query.all()
    return results


def filter_by_icmp_type(session: Session, icmp_type: Optional[str]) -> List[Packet]:
    if icmp_type is None:
        return []

    results = session.query(Packet).filter(Packet.icmp_type == icmp_type).all()
    return results


def filter_by_ether_type(session: Session, eth_type: Optional[str]) -> List[Packet]:
    if eth_type is None:
        return []

    results = session.query(Packet).filter(Packet.eth_type == eth_type).all()
    return results


def filter_by_time_range(session: Session, start_ts_str: Optional[str] = None, end_ts_str: Optional[str] = None) -> List[Packet]:
    start_ts = datetime.strptime(start_ts_str, "%Y-%m-%d %H:%M:%S") if start_ts_str else None
    end_ts = datetime.strptime(end_ts_str, "%Y-%m-%d %H:%M:%S") if end_ts_str else None

    query = session.query(Packet)
    if start_ts:
        query = query.filter(Packet.timestamp >= start_ts)
    if end_ts:
        query = query.filter(Packet.timestamp <= end_ts)

    results = query.all()
    return results


def filter_packets(
    session: Session,
    protocol: Optional[str] = None,
    interface: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    icmp_type: Optional[str] = None,
    eth_type: Optional[str] = None,
    start_ts_str: Optional[str] = None,
    end_ts_str: Optional[str] = None
) -> List[Packet]:
    start_ts = datetime.strptime(start_ts_str, "%Y-%m-%d %H:%M:%S") if start_ts_str else None
    end_ts = datetime.strptime(end_ts_str, "%Y-%m-%d %H:%M:%S") if end_ts_str else None

    query = session.query(Packet)
    if protocol:
        query = query.filter(Packet.protocol == protocol)
    if interface:
        query = query.filter(Packet.interface == interface)
    if src_ip:
        query = query.filter(Packet.src_ip == src_ip)
    if dst_ip:
        query = query.filter(Packet.dst_ip == dst_ip)
    if src_port:
        query = query.filter(Packet.src_port == src_port)
    if dst_port:
        query = query.filter(Packet.dst_port == dst_port)
    if icmp_type:
        query = query.filter(Packet.icmp_type == icmp_type)
    if eth_type:
        query = query.filter(Packet.eth_type == eth_type)
    if start_ts:
        query = query.filter(Packet.timestamp >= start_ts)
    if end_ts:
        query = query.filter(Packet.timestamp <= end_ts)

    results = query.all()
    return results


# Mapping from human-readable TCP flag names to Scapy single-letter codes
FLAG_MAP = {
    "SYN": "S",
    "ACK": "A",
    "FIN": "F",
    "RST": "R",
    "PSH": "P",
    "URG": "U",
    "ECE": "E",
    "CWR": "C",
}


def filter_by_tcp_flags(session: Session, flags: Optional[List[str]]) -> List[Packet]:
    if not flags:
        return []

    converted_flags = []
    for flag in flags:
        converted_flags.append(FLAG_MAP.get(flag.upper(), flag))

    query = session.query(Packet).filter(Packet.protocol == "tcp")
    flag_conditions = [Packet.flags.like(f"%{f}%") for f in converted_flags]
    if flag_conditions:
        query = query.filter(or_(*flag_conditions))

    results = query.all()
    return results


def filter_by_payload_size(session: Session, min_size: int) -> List[Packet]:
    results = session.query(Packet).filter(Packet.payload.isnot(None),
                                           func.length(Packet.payload) >= min_size).all()
    return results


def filter_by_mac(session: Session, src_mac: Optional[str] = None, dst_mac: Optional[str] = None) -> List[Packet]:
    if src_mac is None and dst_mac is None:
        return []
    
    query = session.query(Packet)
    if src_mac:
        query = query.filter(Packet.src_mac == src_mac)
    if dst_mac:
        query = query.filter(Packet.dst_mac == dst_mac)

    results = query.all()
    return results


def filter_by_port_range(session: Session, start_port: int, end_port: int) -> List[Packet]:
    if end_port <= start_port:
        return []
    
    results = session.query(Packet).filter(
        or_(
            and_(Packet.src_port >= start_port, Packet.src_port <= end_port),
            and_(Packet.dst_port >= start_port, Packet.dst_port <= end_port)
        )
    ).all()
    return results


def count_packets_by_protocol(session: Session, protocol: Optional[str]) -> int:
    if protocol is None:
        return 0
    
    count = session.query(Packet).filter(Packet.protocol == protocol).count()
    return count


def delete_all_packets(session: Session) -> int:
    rows_deleted = session.query(Packet).delete()
    session.commit()
    return rows_deleted
    