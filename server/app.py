import atexit
import signal
import time
from flask import Flask, request, jsonify
from flask_cors import CORS
import psutil
import ip_link_analyser
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
CORS(app)

@app.route('/start_capture', methods=['POST'])
def start_capture():
    try:
        data = request.json
        device = data['device']
        filter_expr = data['filter_expr']
        packet_count = data['packet_count']
        timeout = data['timeout']
        country_pairs = data['country_pairs']
        ip_link_analyser.start_packet_capture(device, filter_expr, packet_count, timeout, country_pairs)
        return jsonify({"status": "capture started"})
    except Exception as e:
        logging.error(f"Error starting capture: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    try:
        data = request.json
        ip_link_analyser.stop_packet_capture()
        return jsonify({"status": "capture stopped"})
    except Exception as e:
        logging.error(f"Error stopping capture: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/get_data', methods=['GET'])
def get_data():
    try:
        data = ip_link_analyser.get_classified_data()
        return jsonify(data)
    except Exception as e:
        logging.error(f"Error getting classified data: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/network-interfaces', methods=['GET'])
def get_network_interfaces():
    try:
        interfaces = []
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == 2:  # AF_INET (IPv4)
                    interfaces.append({
                        'name': interface,
                        'address': addr.address
                    })
        return jsonify(interfaces)
    except Exception as e:
        logging.error(f"Error getting network interfaces: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# def shutdown_server():
#     logging.info("Shutting down gracefully...")
#     ip_link_analyser.stop_packet_capture()
#     ip_link_analyser.close_packet_capture()
#     logging.info("Server shutdown complete.")

# def signal_handler(signum, frame):
#     shutdown_server()
#     # Delay to ensure shutdown messages are logged
#     time.sleep(1)
#     raise SystemExit

# signal.signal(signal.SIGINT, signal_handler)
# signal.signal(signal.SIGTERM, signal_handler)
# # atexit.register(shutdown_server)

if __name__ == '__main__':
    app.run(debug=True)
