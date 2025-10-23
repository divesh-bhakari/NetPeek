from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import uuid
from packet_parser import parse_pcap
from db_config import get_db_connection

# --- Initialize Flask app ---
app = Flask(__name__, template_folder='templates')
CORS(app)
app.config['TEMPLATES_AUTO_RELOAD'] = True  # Force Flask to reload templates

# --- Upload folder ---
UPLOAD_FOLDER = os.path.join("backend", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Serve Home page ---
@app.route('/')
def home():
    return render_template('index.html')

# --- Serve Results page ---
@app.route('/result.html')
def result_page():
    return render_template('result.html')

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

        # Step 2: Generate a unique file_id for this upload
        file_id = str(uuid.uuid4())

        # Step 3: Parse PCAP and store into MySQL with file_id
        result = parse_pcap(filepath, file_id=file_id)

        # Return success + file_id for frontend to remember
        return jsonify({
            'message': 'File processed successfully',
            'summary': result,
            'file_id': file_id
        })

    except Exception as e:
        print(f"[!] Error in /upload route: {e}")
        return jsonify({'error': str(e)}), 500


# --- Results Data API (Step 4: Filter by file_id) ---
@app.route('/results', methods=['GET'])
def get_results():
    try:
        file_id = request.args.get("file_id")
        if not file_id:
            return jsonify({"error": "Missing file_id parameter"}), 400

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Filter all queries by file_id
        cursor.execute("SELECT COUNT(*) as total_packets FROM packets WHERE file_id=%s", (file_id,))
        total_packets = cursor.fetchone()['total_packets']

        cursor.execute("SELECT SUM(length) as total_bytes FROM packets WHERE file_id=%s", (file_id,))
        total_bytes = cursor.fetchone()['total_bytes'] or 0

        cursor.execute("SELECT protocol, COUNT(*) as count FROM packets WHERE file_id=%s GROUP BY protocol", (file_id,))
        protocols = cursor.fetchall()

        cursor.execute("""
            SELECT src_ip, COUNT(*) as count 
            FROM packets 
            WHERE file_id=%s AND src_ip IS NOT NULL 
            GROUP BY src_ip 
            ORDER BY count DESC LIMIT 10
        """, (file_id,))
        top_src_ips = cursor.fetchall()

        cursor.execute("""
            SELECT dst_ip, COUNT(*) as count 
            FROM packets 
            WHERE file_id=%s AND dst_ip IS NOT NULL 
            GROUP BY dst_ip 
            ORDER BY count DESC LIMIT 10
        """, (file_id,))
        top_dst_ips = cursor.fetchall()

        cursor.execute("""
            SELECT COALESCE(src_port, dst_port) as port, COUNT(*) as count
            FROM packets
            WHERE file_id=%s AND (src_port IS NOT NULL OR dst_port IS NOT NULL)
            GROUP BY port
            ORDER BY count DESC LIMIT 10
        """, (file_id,))
        top_ports = cursor.fetchall()

        cursor.execute("""
            SELECT CONCAT(src_ip,' -> ',dst_ip) as pair, COUNT(*) as count
            FROM packets
            WHERE file_id=%s AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
            GROUP BY pair
            ORDER BY count DESC LIMIT 10
        """, (file_id,))
        top_pairs = cursor.fetchall()

        cursor.execute("""
            SELECT src_ip, dst_ip, protocol, length, timestamp
            FROM packets
            WHERE file_id=%s
            ORDER BY id ASC
        """, (file_id,))
        all_packets = cursor.fetchall()

        cursor.close()
        connection.close()

        return jsonify({
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "protocols": protocols,
            "top_src_ips": top_src_ips,
            "top_dst_ips": top_dst_ips,
            "top_ports": top_ports,
            "top_pairs": top_pairs,
            "all_packets": all_packets
        })

    except Exception as e:
        print(f"[!] Error in /results route: {e}")
        return jsonify({"error": str(e)}), 500


# --- Run Flask ---
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
