from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class PacketOut(BaseModel):
    """
    Represents the output schema for a captured network packet
    """
    
    id: int
    
    timestamp: Optional[datetime] = None

    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    eth_type: Optional[str] = None
    interface: Optional[str] = None

    protocol: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None

    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    flags: Optional[str] = None
    payload: Optional[str] = None

    icmp_type: Optional[str] = None
    code: Optional[int] = None
    
    class Config:
        from_attributes = True
        

class AddPacketsResponse(BaseModel):
    """
    Schema for response after adding packets to the database.
    """
    
    message: str
    packets_added: int
    
    
class CountResponse(BaseModel):
    """
    Schema for returning the count of packets by protocol
    """
    
    protocol: str
    count: int
    
    
class DeleteResponse(BaseModel):
    """
    Schema for response after deleting all packets
    """
    
    message: str
    rows_deleted: int
