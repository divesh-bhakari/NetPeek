from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
from packet_parser import parse_pcap

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = os.path.join("backend", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def home():
    # Serve the HTML frontend
    return render_template('index.html')

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

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
