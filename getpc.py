'''
Issues:
    1. Cannot find OS version/name properly, inserts IP instead.

'''

import socket
import threading
import queue

# Passing arguments
import sys, getopt
import re

def debug(message):
    if debugBool:
        print("debug | " + str(message))

responsive_ips = []

devices = [] # [[IP, Device name, OS, Open ports], [IP2, Device name2, OS2, Open ports2]]
# Working
def scan_ip(ip):
    # Check if the IP is responsive by attempting to connect to port 80
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.connect((ip, 80))
        s.close()
        # Add the IP to the list of responsive IPs
        responsive_ips.append(ip)
        print(str(ip) + " is responsive")
    except:
        pass

# Threading
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
    debug("All threads completed for scan_network")

# Queueing
def worker(q):
    # Process the queue of IP addresses
    while True:
        try:
            ip = q.get_nowait()
        except queue.Empty:
            break
        scan_ip(ip)

# Working
def get_device_info(ip):
    this_list = []
    this_list.append(ip)
    # Retrieve device name, OS version, and open ports for the specified IP
    try:
        # Use the socket library to connect to the IP address and retrieve information
        # Note that this information may be different depending on the operating system of the device
        device_name = socket.gethostbyaddr(ip)[0]
        debug("Got device name for " + str(ip) + ": " + device_name)
    except socket.herror:
        device_name = "No device name found"
    this_list.append(device_name)

    try:
        os_version = socket.gethostbyaddr(ip)[2][0]
        debug("Got os_version for " + str(ip) + ": " + os_version)
    except socket.herror:
        os_version = "No OS version found"
    this_list.append(os_version)

    open_ports = []
    for port in range(1, 1025):
        debug("Scanning port: " + str(port))
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
                debug("Port: " + str(port) + " is open for " + str(ip))
            s.close()
        except Exception as e:
            print(type(e))
            print(e.args)
            print(e)
            print()
    this_list.append(open_ports)
    debug("Got open_ports for " + str(ip) + ": " + str(open_ports))

    devices.append(this_list) # [ip, device_name, os_version, open_ports]

# Threading
def get_infos():
    # Create a queue containing all responsive IP addresses in the network
    qu = queue.Queue()

    # Iterate over the list of responsive IPs and retrieve information for each device
    for ip in responsive_ips:
        qu.put(ip)

    # Create multiple threads to process the queue
    threads = []
    for i in range(len(responsive_ips)):
        t = threading.Thread(target=device_worker, args=(qu,))
        t.start()
        debug("Started thread: " + str(t))
        threads.append(t)

    # Wait for all threads to complete
    for t in threads:
        t.join()
    debug("All threads completed for get_infos")

# Queueing
def device_worker(qu):
    while True:
        try:
            ip = qu.get_nowait()
        except queue.Empty:
            break
        print("Getting info for: " + str(ip))
        get_device_info(ip)

def main(argv):
    # Default arguments
    global network 
    network = "192.168.1."

    global debugBool
    debugBool = False
    

    global outputfile
    outputfile = ''

    try:
        opts, args = getopt.getopt(argv, "hi:do:")
    except getopt.GetoptError:
        print('Invalid option(s). Usage: getpcsV2.py [-i <x.x.x.>] [-d] [-o <output_file>]')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print("This program allows you to scan and identify a network using the Python library: Socket.")
            print("All parameters are optional.", end="\n\n")
            print("Parameters:")
            print("[-i <x.x.x.>] The x's are numbers with amount of digits 1-3. The format must be followed exactly. If argument is ignored, the input will default to '192.168.1.'.")
            print("[-d] Enables debug mode, which also provides extra information when scanning.")
            print("[-o <output_file>] Allows you to output all the PC-information to a text-file.")
            sys.exit(2)
        elif opt == '-i':
            # Define the regular expression pattern
            pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.$'
            if re.match(pattern, arg.strip()):
                network = arg.strip()
        elif opt == '-d':
            debugBool = True
        elif opt == "-o":
            if arg.strip():
                outputfile = arg
            else:
                print('No output file specified. Usage: getpcsV2.py [-d] [-o <output_file>]')
                sys.exit(2)
        
    scan_network()
    debug("Found " + str(len(responsive_ips)) + " responsive ips")

    get_infos()

    if outputfile:
        f = open(outputfile, "a")

    output = ""
    for device in devices:
        if device:
            output += "IP: " + str(device[0]) + "\n"
            output += "Device name: " + str(device[1]) + "\n"
            output += "OS version: " + str(device[2]) + "\n"
            output += "Open ports: " + str(device[3]) + "\n\n"

    print(output)

    if outputfile:
        f.write(output)
        f.close()

if __name__ == "__main__":
    # Call the main function
    main(sys.argv[1:])