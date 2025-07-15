from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class PacketOut(BaseModel):
    """To validate and serialize data"""
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
    message: str
    packets_added: int
    
    
class CountResponse(BaseModel):
    protocol: str
    count: int
    
    
class DeleteResponse(BaseModel):
    message: str
    rows_deleted: int
