The file DTC.pkl contains the pickled decision tree classifier that has already been trained. If the reader is interested in re-training the model, reach out to us directly and we can provide the training data (there is insufficient space to include data on GitHub). RF.pkl is an older random forest model that was trained on different features.

1. Compile and run the server application with 'python3 server.py'
2. Generate normal traffic requests using 'curl http://127.0.0.1:8080/status' in a separate terminal window
3. Generate SYN Flood attack traffic requests using 'sudo hping3 -c 15000 -d 120 -S -w 64 -p 80 --flood --rand-source 127.0.0.1' 
