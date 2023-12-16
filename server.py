from flask import Flask, jsonify
import subprocess
import threading
import pickle
import pandas as pd
from collections import defaultdict
from training import calculate_attack_features 

app = Flask(__name__)

# loads the trained model
def load_model(filename):
    with open(filename, 'rb') as file:
        return pickle.load(file)

model = load_model('DTC.pkl')

def block_ip_address(ip_address):
    pass

def cont_cred(unnec):
    pass

# stores data for each IP address
ip_data = defaultdict(list)

# preprocesses and predicts traffic data
def preprocess_and_predict(data):
    # preprocess
    data_df = pd.DataFrame(data)
    processed_data = calculate_attack_features(data_df)

    # predict
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

# monitors and processes network traffic
def monitor_network_traffic():
    process = subprocess.Popen(['tshark', '-i', 'lo'],
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.DEVNULL)
    
    all_requests = []  # stores incoming requests

    while True:
        line = process.stdout.readline()
        if line:
            data = extract_data_from_line(line.decode().strip())
            
            # checks that necessary data is present
            if 'source_ip' in data:
                all_requests.append(data)
                # checks we have collected 10 requests
                if len(all_requests) == 10:
                    # converts collected data to a dataframe object
                    data_df = pd.DataFrame(all_requests)
                    prediction = preprocess_and_predict(data_df)

                    # checks for an attack and print all involved IPs
                    if any(prediction == 1):  # if any request in batch is attack
                        print("Potential Attack detected in the following IPs:")
                        for request in all_requests:
                            print(request['source_ip'])
                    
                    # clears list for next set of requests
                    all_requests.clear()

def retrieve_status_information():
    total_packets_analyzed = sum(len(packets) for packets in ip_data.values())
    unique_ips_monitored = len(ip_data)

    status = {
        "total_packets_analyzed": total_packets_analyzed,
        "unique_ips_monitored": unique_ips_monitored
    }
    return status
    
# HTTP endpoint to get status or list of blocked IPs
@app.route('/status', methods=['GET'])
def get_status():
    # retrieve and return status information
    status = retrieve_status_information()
    return jsonify(status)

# start network monitoring in a separate thread
threading.Thread(target=monitor_network_traffic, daemon=True).start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
