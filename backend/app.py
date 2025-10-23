from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import uuid
import openai
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

# --- Serve Descriptive Results page ---
@app.route('/descriptive_result.html')
def descriptive_result_page():
    return render_template('descriptive_result.html')

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

# --- API route to provide descriptive data ---
@app.route('/results_descriptive', methods=['GET'])
def get_descriptive_results():
    try:
        file_id = request.args.get("file_id")  # optional, for specific PCAP
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # --- Basic PCAP info ---
        query_total = "SELECT COUNT(*) as total_packets FROM packets"
        query_total_bytes = "SELECT SUM(length) as total_bytes FROM packets"
        query_times = "SELECT MIN(timestamp) as start_time, MAX(timestamp) as end_time FROM packets"
        filters = ()
        if file_id:
            query_total += " WHERE file_id=%s"
            query_total_bytes += " WHERE file_id=%s"
            query_times += " WHERE file_id=%s"
            filters = (file_id,)

        cursor.execute(query_total, filters)
        total_packets = cursor.fetchone()['total_packets']

        cursor.execute(query_total_bytes, filters)
        total_bytes = cursor.fetchone()['total_bytes'] or 0

        cursor.execute(query_times, filters)
        times = cursor.fetchone()
        start_time = times['start_time']
        end_time = times['end_time']
        capture_duration = str(end_time - start_time) if start_time and end_time else "Unknown"

        # Top source IP
        query_top_src = "SELECT src_ip, COUNT(*) as count FROM packets WHERE src_ip IS NOT NULL"
        if file_id: query_top_src += " AND file_id=%s"
        query_top_src += " GROUP BY src_ip ORDER BY count DESC LIMIT 1"
        cursor.execute(query_top_src, (file_id,) if file_id else ())
        top_src_ip = cursor.fetchone()
        top_src_ip_val = top_src_ip['src_ip'] if top_src_ip else 'N/A'

        # Top destination IP
        query_top_dst = "SELECT dst_ip, COUNT(*) as count FROM packets WHERE dst_ip IS NOT NULL"
        if file_id: query_top_dst += " AND file_id=%s"
        query_top_dst += " GROUP BY dst_ip ORDER BY count DESC LIMIT 1"
        cursor.execute(query_top_dst, (file_id,) if file_id else ())
        top_dst_ip = cursor.fetchone()
        top_dst_ip_val = top_dst_ip['dst_ip'] if top_dst_ip else 'N/A'

        # Most used protocol
        query_protocol = "SELECT protocol, COUNT(*) as count FROM packets"
        if file_id: query_protocol += " WHERE file_id=%s"
        query_protocol += " GROUP BY protocol ORDER BY count DESC LIMIT 1"
        cursor.execute(query_protocol, (file_id,) if file_id else ())
        protocol = cursor.fetchone()
        protocol_val = protocol['protocol'] if protocol else 'N/A'

        # Average packet size
        avg_packet_size = round(total_bytes / total_packets) if total_packets else 0

        # Optional: file name
        query_file_name = "SELECT file_name FROM packets"
        if file_id: query_file_name += " WHERE file_id=%s"
        query_file_name += " ORDER BY id ASC LIMIT 1"
        cursor.execute(query_file_name, (file_id,) if file_id else ())
        file_row = cursor.fetchone()
        file_name = file_row['file_name'] if file_row else 'Unknown'

        cursor.close()
        connection.close()

        return jsonify({
            "file_name": file_name,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "capture_duration": capture_duration,
            "top_src_ip": top_src_ip_val,
            "top_dst_ip": top_dst_ip_val,
            "top_protocol": protocol_val,
            "avg_packet_size": avg_packet_size
        })

    except Exception as e:
        print(f"[!] Error in /results_descriptive route: {e}")
        return jsonify({"error": str(e)}), 500


# --- API route to provide descriptive data with AI insights ---
@app.route('/results_descriptive_ai', methods=['GET'])
def get_descriptive_results_ai():
    try:
        file_id = request.args.get("file_id")
        if not file_id:
            return jsonify({"error": "Missing file_id parameter"}), 400

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # --- Basic PCAP info ---
        cursor.execute("SELECT COUNT(*) as total_packets FROM packets WHERE file_id=%s", (file_id,))
        total_packets = cursor.fetchone()['total_packets']

        cursor.execute("SELECT SUM(length) as total_bytes FROM packets WHERE file_id=%s", (file_id,))
        total_bytes = cursor.fetchone()['total_bytes'] or 0

        cursor.execute("SELECT MIN(timestamp) as start_time, MAX(timestamp) as end_time FROM packets WHERE file_id=%s", (file_id,))
        times = cursor.fetchone()
        start_time = times['start_time']
        end_time = times['end_time']
        capture_duration = str(end_time - start_time) if start_time and end_time else "Unknown"

        # Top source IP
        cursor.execute("SELECT src_ip, COUNT(*) as count FROM packets WHERE file_id=%s AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY count DESC LIMIT 1", (file_id,))
        top_src_ip = cursor.fetchone()
        top_src_ip_val = top_src_ip['src_ip'] if top_src_ip else 'N/A'

        # Top destination IP
        cursor.execute("SELECT dst_ip, COUNT(*) as count FROM packets WHERE file_id=%s AND dst_ip IS NOT NULL GROUP BY dst_ip ORDER BY count DESC LIMIT 1", (file_id,))
        top_dst_ip = cursor.fetchone()
        top_dst_ip_val = top_dst_ip['dst_ip'] if top_dst_ip else 'N/A'

        # Most used protocol
        cursor.execute("SELECT protocol, COUNT(*) as count FROM packets WHERE file_id=%s GROUP BY protocol ORDER BY count DESC LIMIT 1", (file_id,))
        top_protocol = cursor.fetchone()
        top_protocol_val = top_protocol['protocol'] if top_protocol else 'N/A'

        # Top ports
        cursor.execute("SELECT COALESCE(src_port,dst_port) as port, COUNT(*) as count FROM packets WHERE file_id=%s AND (src_port IS NOT NULL OR dst_port IS NOT NULL) GROUP BY port ORDER BY count DESC LIMIT 5", (file_id,))
        top_ports = cursor.fetchall()

        # Average packet size
        avg_packet_size = round(total_bytes / total_packets) if total_packets else 0

        # File name
        cursor.execute("SELECT file_name FROM packets WHERE file_id=%s ORDER BY id ASC LIMIT 1", (file_id,))
        file_row = cursor.fetchone()
        file_name = file_row['file_name'] if file_row else 'Unknown'

        cursor.close()
        connection.close()

        # --- Generate AI insights using OpenAI ---
        import os
        import openai
        openai.api_key = os.getenv("sk-...NyUA")  # store in environment variable

        prompt = f"""
        You are a network analyst AI. 
        Given the following PCAP summary, provide concise, insightful observations and potential anomalies:
        File Name: {file_name}
        Total Packets: {total_packets}
        Capture Duration: {capture_duration}
        Top Source IP: {top_src_ip_val}
        Top Destination IP: {top_dst_ip_val}
        Most Used Protocol: {top_protocol_val}
        Top Ports: {[p['port'] for p in top_ports]}
        Average Packet Size: {avg_packet_size} bytes

        Provide 4-5 bullet points of insights, including potential suspicious activity or patterns.
        """

        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7,
            max_tokens=300
        )

        ai_insight = response.choices[0].message.content.strip()

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

# --- Run Flask ---
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
