import subprocess

# shared dictionary to store IP addresses and their request counts
ip_requests = {}

def monitor_ips():
    process = subprocess.Popen(['tshark', '-i', 'lo'],
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.DEVNULL)

    while True:
        line = process.stdout.readline()
        if line:
            ip = line.decode().strip()
            if ip in ip_requests:
                ip_requests[ip] += 1
            else:
                ip_requests[ip] = 1