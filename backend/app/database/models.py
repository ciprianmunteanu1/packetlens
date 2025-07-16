from sqlalchemy import Column, DateTime, Integer, String
from backend.app.database.db_manager import Base


class Packet(Base):
    """
    SQLAlchemy model for storing network packet data
    Represents a row in the 'packets' table
    """
    
    __tablename__ = "packets"

    # Primary key for the packets table
    id = Column(Integer, primary_key=True, autoincrement=True)

    timestamp = Column(DateTime)

    # Ethernet fields
    src_mac = Column(String)
    dst_mac = Column(String)
    eth_type = Column(String)
    interface = Column(String)

    # IP fields
    protocol = Column(String)
    src_ip = Column(String)
    dst_ip = Column(String)

    # TCP/UDP fields
    src_port = Column(Integer)
    dst_port = Column(Integer)
    flags = Column(String)
    payload = Column(String)

    # ICMP fields
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
