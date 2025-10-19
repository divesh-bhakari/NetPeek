from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from packet_parser import parse_pcap

app = Flask(__name__)
CORS(app)

# Folder to store uploaded files
UPLOAD_FOLDER = os.path.join("backend", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# Home route to confirm backend is running
@app.route('/')
def home():
    return jsonify({"message": "NetPeek backend is running! Use /upload to send a PCAP or PCAPNG file."})


# File upload and processing route
@app.route('/upload', methods=['POST'])
def upload_pcap():
    try:
        # Check if file part exists in request
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({'error': 'Empty filename'}), 400

        # Save uploaded file
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        # Parse and store data into MySQL using updated parser
        result = parse_pcap(filepath)

        return jsonify({
            'message': 'File processed successfully',
            'summary': result
        })

    except Exception as e:
        print(f"[!] Error in /upload route: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    # Run backend server
    app.run(host='127.0.0.1', port=5000, debug=True)
