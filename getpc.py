'''
Issues:
    1. Cannot find OS version/name properly, inserts IP instead.

'''

import socket
import threading
import queue

network = "192.168.1."
responsive_ips = []

def scan_ip(ip):
    # Check if the IP is responsive by attempting to connect to port 80
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.connect((ip, 80))
        s.close()
        # Add the IP to the list of responsive IPs
        responsive_ips.append(ip)
    except:
        pass

def scan_network():
    # Create a queue containing all IP addresses in the network
    q = queue.Queue()
    for i in range(1, 256):
        ip = network + str(i)
        q.put(ip)

    # Create multiple threads to process the queue
    threads = []
    for i in range(100):
        t = threading.Thread(target=worker, args=(q,))
        t.start()
        threads.append(t)

    # Wait for all threads to complete
    for t in threads:
        t.join()

def worker(q):
    # Process the queue of IP addresses
    while True:
        try:
            ip = q.get_nowait()
        except queue.Empty:
            break
        scan_ip(ip)

def get_device_info(ip):
    # Retrieve device name, OS version, and open ports for the specified IP
    try:
        # Use the socket library to connect to the IP address and retrieve information
        # Note that this information may be different depending on the operating system of the device
        device_name = socket.gethostbyaddr(ip)[0]
        os_version = socket.gethostbyaddr(ip)[2][0]
        open_ports = []
        for port in range(1, 1025):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        return (device_name, os_version, open_ports)
    except:
        return None

def main():
    scan_network()

    # Iterate over the list of responsive IPs and retrieve information for each device
    for ip in responsive_ips:
        print("Scanning " + ip)
        device_info = get_device_info(ip)
        if device_info:
            print("Device name:", device_info[0])
            print("OS version:", device_info[1])
            print("Open ports:", device_info[2])
        else:
            print("Could not retrieve information for", ip)

if __name__ == "__main__":
    # Call the main function
    main()
