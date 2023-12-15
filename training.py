import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pickle
from sklearn.metrics import accuracy_score


def read_data(file_paths):
    all_data = []
    for file_path in file_paths:
        with open(file_path, 'r') as file:
            lines = file.readlines()

        for line in lines:
            if 'TCP' in line:
                parts = line.strip().split()
                # print(parts)
                timestamp = float(parts[1])
                source_ip = parts[2]
                length = int(parts[6])
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
                # print(start_ind, end_ind)
                for i in range(start_ind, end_ind):
                    flags[parts[i].split('=')[0]] = int(parts[i].split('=')[1])
                
                # print(flags)
                win = flags['Win']
                end_len = flags['Len']
                seq = flags['Seq']
                if 'Ack' in flags:
                    ack = flags['Ack']
                else:
                    ack = 0

                all_data.append((timestamp, source_ip, length, seq, ack, win, end_len))


    # print(all_data)
    d = np.array(all_data)
    # print(d)
    # print(d.shape)
    return pd.DataFrame(all_data, columns=['timestamp', 'source_ip', 'length', 'seq', 'ack', 'window', 'end_length'])

# Read the data
n1 = '/Users/akhilpaulraj/Downloads/basic_output.txt'
n2 = '/Users/akhilpaulraj/Downloads/largePacket_output.txt'
n3 = '/Users/akhilpaulraj/Downloads/fast_output.txt'
a1 = '/Users/akhilpaulraj/Downloads/random_output.txt'
a2 = '/Users/akhilpaulraj/Downloads/fixed_output.txt'
normal_traffic = read_data([n1, n2, n3])
# print(normal_traffic.head())
attack_traffic = read_data([a1, a2])
# print(attack_traffic.head())

# print(normal_traffic)

# # Extract features
# features_normal = extract_features(normal_traffic)
# features_attack = extract_features(attack_traffic)

# # Combine and label the data
normal_traffic['isattack'] = 0
attack_traffic['isattack'] = 1
combined_data = pd.concat([normal_traffic, attack_traffic])

normsorted = normal_traffic.sort_values(by='timestamp')
attacksorted = attack_traffic.sort_values(by='timestamp')
truncatedattack = attacksorted.loc[2000000:2500000]
combined_data = pd.concat([normal_traffic, truncatedattack])

# feature selection
combined_data = combined_data.sort_values(by='timestamp')
X = combined_data.drop('isattack', axis=1)
y = combined_data['isattack']
X = X.drop('source_ip', axis=1)
print(X.head())
print(y.head())

import pandas as pd

def calculate_attack_features(dataframe, window_size=10):
#     dataframe = dataframe.sort_values(by='timestamp')

    timestamps = []
    seq_ack_ratio = []
    window_size_ack_ratio = []
    end_length_avg = []
    packet_rate = []

    for i in range(len(dataframe) - window_size + 1):
        window = dataframe.iloc[i:i + window_size]
        timestamps.append(window['timestamp'].max())

        # Feature 1: Sequence to ACK ratio
        seq_ack_ratio.append(window['seq'].sum() / window['ack'].sum() if window['ack'].sum() != 0 else 0)

        # Feature 2: ACK ratio within the window
        window_size_ack_ratio.append(window['ack'].sum() / window_size)

        # Feature 3: Average end_length
        end_length_avg.append(window['end_length'].mean())

        # Feature 4: Packet rate
        packet_rate.append(len(window) / (window['timestamp'].max() - window['timestamp'].min()))

    features = pd.DataFrame({
        'seq_ack_ratio': seq_ack_ratio,
        'window_size_ack_ratio': window_size_ack_ratio,
        'end_length_avg': end_length_avg,
        'packet_rate': packet_rate
    })

    return features

X_features = calculate_attack_features(X)
print(X_features.head())

from sklearn.tree import DecisionTreeClassifier, plot_tree
import matplotlib.pyplot as plt
y = y[0:len(X_features)] # NECESSARY BECAUSE OF WINDOW
X_train, X_test, y_train, y_test = train_test_split(X_features, y, test_size=0.3, random_state=42)
X.head()
# Initialize and train the model
model = DecisionTreeClassifier(max_depth = 2)
model.fit(X_train, y_train)

print('Training Accuracy', accuracy_score(y_train, model.predict(X_train)))
print('Test Accuracy', accuracy_score(y_test, model.predict(X_test)))
with open('DTC.pkl', 'wb') as file:
    pickle.dump(model, file)
print(X_features.columns.to_list())
plt.figure(figsize=(12, 8))
plot_tree(model, feature_names=X_features.columns.to_list())
plt.savefig('DT.jpg', format='jpg')
plt.show()