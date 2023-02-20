# Networking
import socket
import nmap

# Threading
import threading
import queue


# Passing arguments
import sys, getopt
import re

def debug(message):
    if debugBool:
        print("debug | " + str(message))

def debugException(e):
    debug(type(e))
    debug(e.args)
    debug(e)
    debug("")
    sys.exit(2)

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
    # Retrieve device name, OS version, and open ports for the specified IP
    try:
        # Use the socket library to connect to the IP address and retrieve information
        # Note that this information may be different depending on the operating system of the device
        device_name = socket.gethostbyaddr(ip)[0]
        debug("Got device name for " + str(ip) + ": " + device_name)
    except socket.herror:
        device_name = None

    nm = nmap.PortScanner()
    nm.scan(ip, arguments="-O")
    nmap_result = nm[ip]

    # Get uptime information
    try:
        uptime = [nmap_result['uptime']['lastboot'], int(nmap_result['uptime']['seconds'])]
    except KeyError:
        uptime = [None, None]
    except Exception as e:
        debugException(e)

    # Get open TCP ports
    try:
        tcp_ports = [port for port, port_data in nmap_result['tcp'].items() if port_data['state'] == 'open']
    except Exception as e:
        tcp_ports = None
        debugException(e)

    # Get port usage information
    portused = {}
    try:
        for port_data in nmap_result['portused']:
            portused[int(port_data['portid'])] = port_data['state']
    except Exception as e:
        portused = None
        debugException(e)

    # Get operating system names
    try:
        os_names = [os_match['name'] for os_match in nmap_result['osmatch']]
        if not os_names:
            os_names = None
        if len(os_names) == 1:
            os_names = os_names[0]
    except Exception as e:
        os_names = None
        debugException(e)

    devices.append({
        "name": device_name,
        "ip": ip,
        "uptime": uptime,
        "tcp": tcp_ports,
        "portused": portused,
        "os": os_names
    })
    debug({
        "name": device_name,
        "ip": ip,
        "uptime": uptime,
        "tcp": tcp_ports,
        "portused": portused,
        "os": os_names
    })

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

def output_device_info(listofdevices):
    _output = ""
    for device in listofdevices:
        devicename = device['name'] if device['name'] else None
        _output += f"Device name: {devicename}\n"

        ip = device['ip'] if device['ip'] else None
        _output += f"IP: {ip}\n"

        os = device['os'] if device['os'] else None
        if isinstance(device['os'], list):
            os = " | ".join(os)
        _output += f"OS: {os}\n"

        if device['tcp']:
            tcp_ports = ", ".join(str(port) for port in device['tcp'])
        else:
            tcp_ports = None
        _output += f"Open TCP ports: {tcp_ports}\n"

        if device['portused']:
            port_used = ", ".join(f"{port} ({device['portused'][port].upper()})" for port in device['portused'])
        else:
            port_used = None
        _output += f"Currently used ports: {port_used}\n"

        if device['uptime'][1]:
            uptime_seconds = device['uptime'][1]
            uptime = f"{uptime_seconds // 86400} d {uptime_seconds // 3600 % 24} h {uptime_seconds // 60 % 60} min {uptime_seconds % 60} s ({uptime_seconds}s) since {device['uptime'][0]}"
        else:
            uptime = None
        _output += f"Uptime: {uptime}\n\n"

    return _output


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
            print("This program allows you to scan and identify devices within a network using the Python libraries: nmap and socket.")
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
            else:
                print("Wrong '-i' argument format. Use <x.x.x.>")
                sys.exit(2)
        elif opt == '-d':
            debugBool = True
        elif opt == "-o":
            if arg.strip():
                outputfile = arg.strip()
            else:
                print('No output file specified. Usage: getpcsV2.py [-d] [-o <output_file>]')
                sys.exit(2)
        
    scan_network()
    debug("Found " + str(len(responsive_ips)) + " responsive ips")

    get_infos()

    if outputfile:
        f = open(outputfile, "a")

    output = output_device_info(devices)

    print(output)

    if outputfile:
        f.write(output)
        f.close()

if __name__ == "__main__":
    # Call the main function
    main(sys.argv[1:])