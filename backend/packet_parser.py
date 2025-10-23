import asyncio
import pyshark
from db_config import get_db_connection
from datetime import datetime

def parse_pcap(file_path, file_id):
    """
    Parse a PCAP file, insert packet data into MySQL,
    and tag each record with a unique file_id for separation.
    """
    # Fix asyncio issue on Python 3.11+
    asyncio.set_event_loop(asyncio.new_event_loop())

    cap = pyshark.FileCapture(file_path, only_summaries=False)
    connection = get_db_connection()
    cursor = connection.cursor()

    packet_count = 0

    for packet in cap:
        try:
            frame_number = int(packet.number) if hasattr(packet, 'number') else None
            timestamp = datetime.now()

            # Ethernet Layer
            src_mac = getattr(packet.eth, 'src', None) if hasattr(packet, 'eth') else None
            dst_mac = getattr(packet.eth, 'dst', None) if hasattr(packet, 'eth') else None

            # IP Layer
            src_ip = getattr(packet.ip, 'src', None) if hasattr(packet, 'ip') else None
            dst_ip = getattr(packet.ip, 'dst', None) if hasattr(packet, 'ip') else None
            ttl = int(getattr(packet.ip, 'ttl', 0)) if hasattr(packet, 'ip') else None
            ip_version = getattr(packet.ip, 'version', None) if hasattr(packet, 'ip') else None
            ip_header_len = int(getattr(packet.ip, 'hdr_len', 0)) if hasattr(packet, 'ip') else None
            ip_total_len = int(getattr(packet.ip, 'len', 0)) if hasattr(packet, 'ip') else None

            # TCP/UDP Layer
            src_port = getattr(packet.tcp, 'srcport', None) if hasattr(packet, 'tcp') else (
                getattr(packet.udp, 'srcport', None) if hasattr(packet, 'udp') else None)
            dst_port = getattr(packet.tcp, 'dstport', None) if hasattr(packet, 'tcp') else (
                getattr(packet.udp, 'dstport', None) if hasattr(packet, 'udp') else None)
            tcp_flags = getattr(packet.tcp, 'flags', None) if hasattr(packet, 'tcp') else None
            tcp_seq = int(getattr(packet.tcp, 'seq', 0)) if hasattr(packet, 'tcp') else None
            tcp_ack = int(getattr(packet.tcp, 'ack', 0)) if hasattr(packet, 'tcp') else None

            # General Info
            protocol = getattr(packet, 'highest_layer', 'Unknown')
            length = int(getattr(packet, 'length', 0))
            info = str(getattr(packet, 'info', ''))
            interface = getattr(packet, 'interface_id', None)
            flow_id = f"{src_ip}_{dst_ip}_{src_port}_{dst_port}"
            packet_summary = str(packet)

            # Insert into DB with file_id
            cursor.execute("""
                INSERT INTO packets (
                    timestamp, frame_number, src_mac, dst_mac, src_ip, dst_ip,
                    src_port, dst_port, protocol, length, ttl, tcp_flags,
                    tcp_seq, tcp_ack, ip_version, ip_header_len, ip_total_len,
                    info, interface, flow_id, packet_summary, file_id
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                timestamp, frame_number, src_mac, dst_mac, src_ip, dst_ip,
                src_port, dst_port, protocol, length, ttl, tcp_flags,
                tcp_seq, tcp_ack, ip_version, ip_header_len, ip_total_len,
                info, interface, flow_id, packet_summary, file_id
            ))

            packet_count += 1

        except Exception as e:
            print(f"[!] Error parsing packet: {e}")
            continue

    connection.commit()
    cursor.close()
    connection.close()

    return {"packets_parsed": packet_count, "file_id": file_id}
