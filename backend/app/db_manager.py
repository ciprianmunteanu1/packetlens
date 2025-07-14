from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import create_engine, Column, DateTime, Integer, String, func, and_, or_
from threading_manager import collect_packets
from datetime import datetime
import json
from typing import Optional, List

# Create database engine and Base class
engine = create_engine("sqlite:///packets.db", echo=True)
Base = declarative_base()


class Packet(Base):
    __tablename__ = "packets"

    # Added primary key id to avoid SQLAlchemy errors
    id = Column(Integer, primary_key=True, autoincrement=True)

    timestamp = Column(DateTime)

    src_mac = Column(String)
    dst_mac = Column(String)
    eth_type = Column(String)
    interface = Column(String)

    protocol = Column(String)
    src_ip = Column(String)
    dst_ip = Column(String)

    src_port = Column(Integer)
    dst_port = Column(Integer)
    flags = Column(String)
    payload = Column(String)

    icmp_type = Column(String)
    code = Column(Integer)

    # Represent Packet object as dictionary
    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": str(self.timestamp) if self.timestamp else None,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "eth_type": self.eth_type,
            "interface": self.interface,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "flags": self.flags,
            "payload": self.payload,
            "icmp_type": self.icmp_type,
            "code": self.code,
        }


# Create table in database and session maker
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)


# Function to add packets returned by all threads to database
def add_packets_to_db():
    # Create session
    session = Session()

    # Add packets to database
    packet_lists = collect_packets()
    for sublist in packet_lists:
        for packet in sublist:
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
    session.close()
    

# Filtering functions
def get_all_packets() -> List[Packet]:
    session = Session()
    results = session.query(Packet).all()
    session.close()
    return results


def filter_by_protocol(protocol: Optional[str]) -> List[Packet]:
    if protocol is None:
        return []

    session = Session()
    results = session.query(Packet).filter(Packet.protocol == protocol).all()
    session.close()
    return results


def filter_by_interface(interface: Optional[str]) -> List[Packet]:
    if interface is None:
        return []

    session = Session()
    results = session.query(Packet).filter(Packet.interface == interface).all()
    session.close()
    return results


def filter_by_ip(src_ip: Optional[str] = None, dst_ip: Optional[str] = None) -> List[Packet]:
    if src_ip is None and dst_ip is None:
        return []
    
    session = Session()
    query = session.query(Packet)

    if src_ip:
        query = query.filter(Packet.src_ip == src_ip)
    if dst_ip:
        query = query.filter(Packet.dst_ip == dst_ip)

    results = query.all()
    session.close()
    return results


def filter_by_icmp_type(icmp_type: Optional[str]) -> List[Packet]:
    if icmp_type is None:
        return []

    session = Session()
    results = session.query(Packet).filter(Packet.icmp_type == icmp_type).all()
    session.close()
    return results


def filter_by_ether_type(eth_type: Optional[str]) -> List[Packet]:
    if eth_type is None:
        return []

    session = Session()
    results = session.query(Packet).filter(Packet.eth_type == eth_type).all()
    session.close()
    return results


def filter_by_time_range(start_ts_str: Optional[str] = None, end_ts_str: Optional[str] = None) -> List[Packet]:
    start_ts = datetime.strptime(start_ts_str, "%Y-%m-%d %H:%M:%S") if start_ts_str else None
    end_ts = datetime.strptime(end_ts_str, "%Y-%m-%d %H:%M:%S") if end_ts_str else None

    session = Session()
    query = session.query(Packet)

    if start_ts:
        query = query.filter(Packet.timestamp >= start_ts)
    if end_ts:
        query = query.filter(Packet.timestamp <= end_ts)

    results = query.all()
    session.close()
    return results


def filter_packets(
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

    session = Session()
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
    session.close()
    return results


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


def filter_by_tcp_flags(flags: Optional[List[str]]) -> List[Packet]:
    if not flags:
        return []

    converted_flags = []
    for flag in flags:
        converted_flags.append(FLAG_MAP.get(flag.upper(), flag))

    session = Session()
    query = session.query(Packet).filter(Packet.protocol == "tcp")

    flag_conditions = [Packet.flags.like(f"%{f}%") for f in converted_flags]
    if flag_conditions:
        query = query.filter(or_(*flag_conditions))

    results = query.all()
    session.close()
    return results


def filter_by_payload_size(min_size: int) -> List[Packet]:
    session = Session()
    results = session.query(Packet).filter(Packet.payload.isnot(None),
                                           func.length(Packet.payload) >= min_size).all()
    session.close()
    return results


def filter_by_mac(src_mac: Optional[str] = None, dst_mac: Optional[str] = None) -> List[Packet]:
    if src_mac is None and dst_mac is None:
        return []
    
    session = Session()
    query = session.query(Packet)

    if src_mac:
        query = query.filter(Packet.src_mac == src_mac)
    if dst_mac:
        query = query.filter(Packet.dst_mac == dst_mac)

    results = query.all()
    session.close()
    return results


def filter_by_port_range(start_port: int, end_port: int) -> List[Packet]:
    if end_port <= start_port:
        return []
    
    session = Session()
    results = session.query(Packet).filter(
        or_(
            and_(Packet.src_port >= start_port, Packet.src_port <= end_port),
            and_(Packet.dst_port >= start_port, Packet.dst_port <= end_port)
        )
    ).all()
    session.close()
    return results


def count_packets_by_protocol(protocol: Optional[str]) -> int:
    if protocol is None:
        return 0
    
    session = Session()
    count = session.query(Packet).filter(Packet.protocol == protocol).count()
    session.close()
    return count

def delete_all_packets():
    session = Session()
    session.query(Packet).delete()
    session.commit()
    session.close()
