from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
from packet_parser import parse_pcap
from db_config import get_db_connection

# --- Initialize Flask app ---
app = Flask(__name__)
CORS(app)

# --- Upload folder ---
UPLOAD_FOLDER = os.path.join("backend", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Home page ---
@app.route('/')
def home():
    return render_template('index.html')

# --- Upload route ---
@app.route('/upload', methods=['POST'])
def upload_pcap():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Empty filename'}), 400

        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        # Parse PCAP and store into MySQL
        result = parse_pcap(filepath)

        return jsonify({
            'message': 'File processed successfully',
            'summary': result
        })

    except Exception as e:
        print(f"[!] Error in /upload route: {e}")
        return jsonify({'error': str(e)}), 500

# --- Results route ---
@app.route('/results', methods=['GET'])
def get_results():
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Total packets
        cursor.execute("SELECT COUNT(*) as total_packets FROM packets")
        total_packets = cursor.fetchone()['total_packets']

        # Total bytes
        cursor.execute("SELECT SUM(length) as total_bytes FROM packets")
        total_bytes = cursor.fetchone()['total_bytes'] or 0

        # Protocol distribution
        cursor.execute("SELECT protocol, COUNT(*) as count FROM packets GROUP BY protocol")
        protocols = cursor.fetchall()

        # Top 10 Source IPs
        cursor.execute("""
            SELECT src_ip, COUNT(*) as count 
            FROM packets 
            WHERE src_ip IS NOT NULL 
            GROUP BY src_ip 
            ORDER BY count DESC LIMIT 10
        """)
        top_src_ips = cursor.fetchall()

        # Top 10 Destination IPs
        cursor.execute("""
            SELECT dst_ip, COUNT(*) as count 
            FROM packets 
            WHERE dst_ip IS NOT NULL 
            GROUP BY dst_ip 
            ORDER BY count DESC LIMIT 10
        """)
        top_dst_ips = cursor.fetchall()

        # Top 10 Ports (src or dst)
        cursor.execute("""
            SELECT COALESCE(src_port,dst_port) as port, COUNT(*) as count
            FROM packets
            WHERE src_port IS NOT NULL OR dst_port IS NOT NULL
            GROUP BY port
            ORDER BY count DESC LIMIT 10
        """)
        top_ports = cursor.fetchall()

        # Top 10 Source-Destination pairs
        cursor.execute("""
            SELECT CONCAT(src_ip,' -> ',dst_ip) as pair, COUNT(*) as count
            FROM packets
            WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL
            GROUP BY pair
            ORDER BY count DESC LIMIT 10
        """)
        top_pairs = cursor.fetchall()

        cursor.close()
        connection.close()

        return jsonify({
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "protocols": protocols,
            "top_src_ips": top_src_ips,
            "top_dst_ips": top_dst_ips,
            "top_ports": top_ports,
            "top_pairs": top_pairs
        })

    except Exception as e:
        print(f"[!] Error in /results route: {e}")
        return jsonify({"error": str(e)}), 500

# --- Run Flask ---
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
