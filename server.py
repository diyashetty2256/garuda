"""
ScamShield — Python Backend Server
Flask server serving the static frontend and /api/analyze endpoint.
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os

from detector import analyze_message, lookup_contact, get_heatmap_data, get_report_stats, submit_report

app = Flask(__name__, static_folder='public', static_url_path='')
CORS(app)


@app.route('/')
def index():
    return send_from_directory('public', 'index.html')


@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('public', path)


@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()

        if not data or 'message' not in data:
            return jsonify({"error": "Please provide a message to analyze."}), 400

        message = data['message']

        if not isinstance(message, str) or len(message.strip()) == 0:
            return jsonify({"error": "The message cannot be empty."}), 400

        if len(message) > 10000:
            return jsonify({"error": "Message is too long. Please keep it under 10,000 characters."}), 400

        result = analyze_message(message)
        return jsonify(result)

    except Exception as e:
        print(f"Analysis error: {e}")
        return jsonify({"error": "An error occurred while analyzing the message."}), 500


@app.route('/api/lookup', methods=['POST'])
def lookup():
    try:
        data = request.get_json()

        if not data or 'query' not in data:
            return jsonify({"error": "Please provide a phone number or email to look up."}), 400

        query = data['query']

        if not isinstance(query, str) or len(query.strip()) == 0:
            return jsonify({"error": "The query cannot be empty."}), 400

        result = lookup_contact(query)
        return jsonify(result)

    except Exception as e:
        print(f"Lookup error: {e}")
        return jsonify({"error": "An error occurred during the lookup."}), 500


@app.route('/api/heatmap', methods=['GET'])
def heatmap():
    try:
        data = get_heatmap_data()
        return jsonify(data)
    except Exception as e:
        print(f"Heatmap error: {e}")
        return jsonify({"error": "Failed to load heatmap data."}), 500


@app.route('/api/reports/stats', methods=['GET'])
def report_stats():
    try:
        stats = get_report_stats()
        return jsonify(stats)
    except Exception as e:
        print(f"Stats error: {e}")
        return jsonify({"error": "Failed to load stats."}), 500


@app.route('/api/report', methods=['POST'])
def report_scam():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Please provide report data."}), 400

        result = submit_report(data)
        if not result.get("success"):
            return jsonify(result), 400
        return jsonify(result)
    except Exception as e:
        print(f"Report error: {e}")
        return jsonify({"error": "An error occurred while submitting the report."}), 500


if __name__ == '__main__':
    print("Scam Language Detector running at http://localhost:3000")
    app.run(host='0.0.0.0', port=3000, debug=True)
