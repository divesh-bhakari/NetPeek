from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from packet_parser import parse_pcap

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = "backend/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/upload', methods=['POST'])
def upload_pcap():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    # Parse and store data
    result = parse_pcap(filepath)

    return jsonify({'message': 'File processed successfully', 'summary': result})

if __name__ == '__main__':
    app.run(debug=True)
