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
normal_traffic = read_data(['basic_output.txt', 'largePacket_output.txt', 'fast_output.txt'])
# print(normal_traffic.head())
attack_traffic = read_data(['random_output.txt', 'fixed_output.txt'])
# print(attack_traffic.head())

# print(normal_traffic)

# # Extract features
# features_normal = extract_features(normal_traffic)
# features_attack = extract_features(attack_traffic)

# # Combine and label the data
normal_traffic['isattack'] = 0
attack_traffic['isattack'] = 1
combined_data = pd.concat([normal_traffic, attack_traffic])

# Split the data into features and labels
X = combined_data.drop('isattack', axis=1)
y = combined_data['isattack']
X = combined_data.drop('source_ip', axis=1)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
X.head()
# Initialize and train the model
model = RandomForestClassifier()
model.fit(X_train, y_train)

print('Training Accuracy', accuracy_score(y_train, model.predict(X_train)))
print('Test Accuracy', accuracy_score(y_test, model.predict(X_test)))
with open('RF.pkl', 'wb') as file:
    pickle.dump(model, file)

print("Model trained and saved as RF.pkl")
