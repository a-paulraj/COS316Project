from flask import Flask, jsonify
import subprocess
import threading
import pickle
import pandas as pd
from collections import defaultdict
from training import calculate_attack_features 

app = Flask(__name__)

# Function to load the trained model
def load_model(filename):
    with open(filename, 'rb') as file:
        return pickle.load(file)

# Load the trained model
model = load_model('DTC.pkl')

def block_ip_address(ip_address):
    pass

# Shared dictionary to store data for each IP address
ip_data = defaultdict(list)

# Function to preprocess and predict traffic data
def preprocess_and_predict(data):
    # Preprocess the data
    data_df = pd.DataFrame(data)
    processed_data = calculate_attack_features(data_df)

    # Predict using the model
    prediction = model.predict(processed_data)
    return prediction

def extract_data_from_line(line):
    data = {}
    if 'TCP' in line:
        parts = line.strip().split()
        data['timestamp'] = float(parts[1])
        data['source_ip'] = parts[2]
        data['length'] = int(parts[6])

        start_ind = 7
        end_ind = len(parts)
        for j in range(7, len(parts)):
            if parts[j][-4:] == 'ACK]' or parts[j][-4:] == 'SYN]':
                start_ind = j+1
                break
        for j in range(start_ind, len(parts)):
            if parts[j][0] == '[':
                end_ind = j
                break

        flags = {}
        for i in range(start_ind, end_ind):
            flag_parts = parts[i].split('=')
            if len(flag_parts) == 2:
                flags[flag_parts[0]] = int(flag_parts[1])

        data['window'] = flags.get('Win', 0)
        data['end_length'] = flags.get('Len', 0)
        data['seq'] = flags.get('Seq', 0)
        data['ack'] = flags.get('Ack', 0)

    return data

# Function to monitor and process network traffic
def monitor_network_traffic():
    process = subprocess.Popen(['tshark', '-i', 'lo'],
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.DEVNULL)
    
    all_requests = []  # List to store all incoming requests

    while True:
        line = process.stdout.readline()
        if line:
            data = extract_data_from_line(line.decode().strip())
            
            # Check if the necessary data is present
            if 'source_ip' in data:
                all_requests.append(data)
                # Check if we have collected 10 requests
                if len(all_requests) == 10:
                    # Convert the collected data to a DataFrame
                    data_df = pd.DataFrame(all_requests)
                    prediction = preprocess_and_predict(data_df)

                    # Check for an attack and print all involved IPs
                    if any(prediction == 1):  # If any request in the batch is an attack
                        print("Potential Attack detected in the following IPs:")
                        for request in all_requests:
                            print(request['source_ip'])
                    
                    # Clear the list for the next set of requests
                    all_requests.clear()

def retrieve_status_information():
    total_packets_analyzed = sum(len(packets) for packets in ip_data.values())
    unique_ips_monitored = len(ip_data)

    status = {
        "total_packets_analyzed": total_packets_analyzed,
        "unique_ips_monitored": unique_ips_monitored
    }
    return status
    
# HTTP endpoint to get the status or list of blocked IPs
@app.route('/status', methods=['GET'])
def get_status():
    # Retrieve and return status information
    status = retrieve_status_information()
    return jsonify(status)

# Start network monitoring in a separate thread
threading.Thread(target=monitor_network_traffic, daemon=True).start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
