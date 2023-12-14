from flask import Flask, request, jsonify
from threading import Thread
import monitor_ip

app = Flask(__name__)

@app.route('/get_ips', methods=['GET'])
def get_ips():
    ip_address = request.remote_addr
    if ip_address in monitor_ip.ip_requests:
        print("request", monitor_ip.ip_requests[ip_address])
    # Check if the IP has been captured by Tshark and its request count
    if ip_address in monitor_ip.ip_requests and monitor_ip.ip_requests[ip_address] > 4:
        return "Too many requests", 429
    else:
        return jsonify(list(monitor_ip.ip_requests.keys()))

if __name__ == '__main__':
    # Start the IP monitor in a separate thread
    ip_monitor_thread = Thread(target=monitor_ip.monitor_ips)
    ip_monitor_thread.daemon = True
    ip_monitor_thread.start()

    app.run(debug=True)