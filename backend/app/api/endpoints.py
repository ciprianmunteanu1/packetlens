from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from backend.app.database.db_manager import engine, get_session
from backend.app.database import crud, models
from schemas import PacketOut, AddPacketsResponse, CountResponse, DeleteResponse
from typing import Optional

# Add models to database
models.Base.metadata.create_all(bind=engine)


# Create server
app = FastAPI()


# Endpoints
@app.post("/packets/all", response_model=AddPacketsResponse)
def add_all_packets_req(session: Session = Depends(get_session)):
    number_of_packets = crud.add_all_packets_to_db(session)
    return AddPacketsResponse(
        message="Packets captured and saved successfully.",
        packets_added=number_of_packets
    )
    
    
@app.post("/packets/interface/{interface_name}", response_model= AddPacketsResponse)
def add_packets_iface_req(interface_name: str, session: Session = Depends(get_session)):
    number_of_packets = crud.add_iface_packets_to_db(session, interface_name)
    return AddPacketsResponse(
        message=f"Packets captured on interface {interface_name} and saved successfully.",
        packets_added=number_of_packets
    )
    

@app.get("/packets", response_model=list[PacketOut])
def get_all_packets_req(session: Session = Depends(get_session)):
    packets = crud.get_all_packets(session)
    return [PacketOut.model_validate(packet) for packet in packets]


@app.get("/packets/by_protocol", response_model=list[PacketOut])
def filter_by_protocol_req(protocol: Optional[str] = None, session: Session = Depends(get_session)):
    packets = crud.filter_by_protocol(session, protocol)
    return [PacketOut.model_validate(packet) for packet in packets]


@app.get("/packets/by_interface", response_model=list[PacketOut])
def filter_by_interface_req(interface: Optional[str] = None, session: Session = Depends(get_session)):
    packets = crud.filter_by_interface(session, interface)
    return [PacketOut.model_validate(packet) for packet in packets]


@app.get("/packets/by_ip", response_model=list[PacketOut])
def filter_by_ip_req(src_ip: Optional[str] = None, dst_ip: Optional[str] = None, session: Session = Depends(get_session)):
    packets = crud.filter_by_ip(session, src_ip, dst_ip)
    return [PacketOut.model_validate(packet) for packet in packets]

@app.get("/packets/by_icmp_type", response_model=list[PacketOut])
def filter_by_icmp_type_req(icmp_type: Optional[str] = None, session: Session = Depends(get_session)):
    packets = crud.filter_by_icmp_type(session, icmp_type)
    return [PacketOut.model_validate(packet) for packet in packets]


@app.get("/packets/by_eth_type", response_model=list[PacketOut])
def filter_by_ether_type_req(eth_type: Optional[str] = None, session: Session = Depends(get_session)):
    packets = crud.filter_by_ether_type(session, eth_type)
    return [PacketOut.model_validate(packet) for packet in packets]


@app.get("/packets/by_time_range", response_model=list[PacketOut])
def filter_by_time_range_req(
    start_ts: Optional[str] = None,
    end_ts: Optional[str] = None,
    session: Session = Depends(get_session)
):
    packets = crud.filter_by_time_range(session, start_ts, end_ts)
    return [PacketOut.model_validate(packet) for packet in packets]


@app.get("/packets/by_payload_size", response_model=list[PacketOut])
def filter_by_payload_size_req(
    min_size: int,
    session: Session = Depends(get_session)
):
    packets = crud.filter_by_payload_size(session, min_size)
    return [PacketOut.model_validate(packet) for packet in packets]


@app.get("/packets/by_mac", response_model=list[PacketOut])
def filter_by_mac_req(
    src_mac: Optional[str] = None,
    dst_mac: Optional[str] = None,
    session: Session = Depends(get_session)
):
    packets = crud.filter_by_mac(session, src_mac, dst_mac)
    return [PacketOut.model_validate(packet) for packet in packets]


@app.get("/packets/by_port_range", response_model=list[PacketOut])
def filter_by_port_range_req(
    start_port: int,
    end_port: int,
    session: Session = Depends(get_session)
):
    packets = crud.filter_by_port_range(session, start_port, end_port)
    return [PacketOut.model_validate(packet) for packet in packets]


@app.get("/packets/by_flags", response_model=list[PacketOut])
def filter_by_flags_req(
    flags: Optional[list[str]] = None,
    session: Session = Depends(get_session)
):
    packets = crud.filter_by_tcp_flags(session, flags)
    return [PacketOut.model_validate(packet) for packet in packets]


@app.get("/packets/filter", response_model=list[PacketOut])
def filter_packets_req(
    protocol: Optional[str] = None,
    interface: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    icmp_type: Optional[str] = None,
    eth_type: Optional[str] = None,
    start_ts: Optional[str] = None,
    end_ts: Optional[str] = None,
    session: Session = Depends(get_session)
):
    packets = crud.filter_packets(
        session,
        protocol,
        interface,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        icmp_type,
        eth_type,
        start_ts,
        end_ts
    )
    return [PacketOut.model_validate(packet) for packet in packets]


@app.get("/packets/count_by_protocol", response_model=CountResponse)
def count_by_protocol_req(
    protocol: str,
    session: Session = Depends(get_session)
):
    count = crud.count_packets_by_protocol(session, protocol)
    return CountResponse(protocol=protocol, count=count)



@app.delete("/packets", response_model=DeleteResponse)
def delete_all_packets_req(session: Session = Depends(get_session)):
    rows_deleted = crud.delete_all_packets(session)
    return DeleteResponse(
        message="All packets deleted successfully.",
        rows_deleted=rows_deleted
    )

