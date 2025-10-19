import pyshark
import pandas as pd
from db_config import get_db_connection
from datetime import datetime

def parse_pcap(file_path):
    cap = pyshark.FileCapture(file_path)
    connection = get_db_connection()
    cursor = connection.cursor()

    packet_count = 0

    for packet in cap:
        try:
            src_ip = packet.ip.src if hasattr(packet, 'ip') else None
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else None
            protocol = packet.highest_layer
            length = int(packet.length)
            info = str(packet.info if hasattr(packet, 'info') else "")
            timestamp = datetime.now()

            if src_ip and dst_ip:
                cursor.execute("""
                    INSERT INTO packets (src_ip, dst_ip, protocol, length, info, timestamp)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (src_ip, dst_ip, protocol, length, info, timestamp))
                packet_count += 1
        except Exception as e:
            print(f"Error parsing packet: {e}")
            continue

    connection.commit()
    cursor.close()
    connection.close()

    return {"packets_parsed": packet_count}
