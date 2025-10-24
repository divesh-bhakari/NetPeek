from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import uuid
from dotenv import load_dotenv
from packet_parser import parse_pcap
from db_config import get_db_connection
import google.generativeai as genai

# --- Load API keys ---
load_dotenv("api.env")
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# --- Initialize Flask app ---
app = Flask(__name__, template_folder='templates')
CORS(app)
app.config['TEMPLATES_AUTO_RELOAD'] = True

# --- Upload folder ---
UPLOAD_FOLDER = os.path.join("backend", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/result.html')
def result_page():
    return render_template('result.html')


@app.route('/descriptive_result.html')
def descriptive_result_page():
    return render_template('descriptive_result.html')


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
        file_id = str(uuid.uuid4())
        result = parse_pcap(filepath, file_id=file_id)

        return jsonify({
            'message': 'File processed successfully',
            'summary': result,
            'file_id': file_id
        })
    except Exception as e:
        print(f"[!] Error in /upload route: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/results', methods=['GET'])
def get_results():
    try:
        file_id = request.args.get("file_id")
        if not file_id:
            return jsonify({"error": "Missing file_id parameter"}), 400

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

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


@app.route('/results_descriptive_ai', methods=['GET'])
def get_descriptive_results_ai():
    """
    Returns descriptive PCAP analysis for the latest upload along with AI insights.
    Works even if no file_id is provided.
    """
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # ✅ Get the latest uploaded file (based on timestamp)
        cursor.execute("""
            SELECT file_id, file_name
            FROM packets
            WHERE file_id IS NOT NULL
            ORDER BY id DESC LIMIT 1
        """)
        latest_file = cursor.fetchone()

        if not latest_file:
            return jsonify({"error": "No PCAP data found in database."}), 404

        file_id = latest_file['file_id']
        file_name = latest_file.get('file_name', 'Unknown')

        # --- Fetch summary metrics ---
        cursor.execute("SELECT COUNT(*) as total_packets FROM packets WHERE file_id=%s", (file_id,))
        total_packets = cursor.fetchone()['total_packets']

        cursor.execute("SELECT SUM(length) as total_bytes FROM packets WHERE file_id=%s", (file_id,))
        total_bytes = cursor.fetchone()['total_bytes'] or 0

        cursor.execute("SELECT MIN(timestamp) as start_time, MAX(timestamp) as end_time FROM packets WHERE file_id=%s", (file_id,))
        times = cursor.fetchone()
        start_time, end_time = times['start_time'], times['end_time']
        capture_duration = str(end_time - start_time) if start_time and end_time else "Unknown"

        cursor.execute("SELECT src_ip, COUNT(*) as count FROM packets WHERE file_id=%s AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY count DESC LIMIT 1", (file_id,))
        top_src_ip = cursor.fetchone()
        top_src_ip_val = top_src_ip['src_ip'] if top_src_ip else 'N/A'

        cursor.execute("SELECT dst_ip, COUNT(*) as count FROM packets WHERE file_id=%s AND dst_ip IS NOT NULL GROUP BY dst_ip ORDER BY count DESC LIMIT 1", (file_id,))
        top_dst_ip = cursor.fetchone()
        top_dst_ip_val = top_dst_ip['dst_ip'] if top_dst_ip else 'N/A'

        cursor.execute("SELECT protocol, COUNT(*) as count FROM packets WHERE file_id=%s GROUP BY protocol ORDER BY count DESC LIMIT 1", (file_id,))
        protocol = cursor.fetchone()
        top_protocol_val = protocol['protocol'] if protocol else 'N/A'

        cursor.execute("SELECT COALESCE(src_port,dst_port) as port, COUNT(*) as count FROM packets WHERE file_id=%s AND (src_port IS NOT NULL OR dst_port IS NOT NULL) GROUP BY port ORDER BY count DESC LIMIT 5", (file_id,))
        top_ports = cursor.fetchall() or []

        avg_packet_size = round(total_bytes / total_packets) if total_packets else 0

        cursor.close()
        connection.close()

        # --- Generate AI insights using Gemini ---
        model = genai.GenerativeModel("gemini-1.5-pro")  # ✅ use a supported model
        prompt = f"""
        You are a network traffic analysis expert.
        Analyze the following PCAP summary and provide 4-5 bullet points with meaningful observations and possible anomalies:

        File Name: {file_name}
        Total Packets: {total_packets}
        Capture Duration: {capture_duration}
        Top Source IP: {top_src_ip_val}
        Top Destination IP: {top_dst_ip_val}
        Most Used Protocol: {top_protocol_val}
        Top Ports: {[p['port'] for p in top_ports]}
        Average Packet Size: {avg_packet_size} bytes
        """

        response = model.generate_content(prompt)
        ai_insight = response.text.strip() if response and hasattr(response, "text") else "No insights generated."

        return jsonify({
            "summary": {
                "file_name": file_name,
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "capture_duration": capture_duration,
                "top_src_ip": top_src_ip_val,
                "top_dst_ip": top_dst_ip_val,
                "top_protocol": top_protocol_val,
                "top_ports": top_ports,
                "avg_packet_size": avg_packet_size
            },
            "ai_insight": ai_insight
        })

    except Exception as e:
        print(f"[!] Error in /results_descriptive_ai route: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
