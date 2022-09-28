import sys
import threading
import socket
from datetime import datetime

ports_available = []

def scan_for_ports(name, first_port, max_port):
    try:
        for port in range(first_port, max_port):
            if (port - 1) == max_port - 1:
                print(name, "Finishing...")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((targeted_ip, port))
            if result == 0:
                ports_available.append(port)
            s.close()
    except socket.error:
        print("Socker error - could not connect")
        sys.exit()


if __name__ == '__main__':
    first_port = int(input('First port -> '))
    last_port = int(input('Last port -> '))
    targeted_ip = input('IP target -> ')
    threads_count = int(input('Threads -> '))
    threads = []

    i = 0
    next_max = first_port
    min_port = first_port
    while i < threads_count:
        i += 1
        next_max += ((last_port - first_port) // threads_count)
        if i == threads_count:
            next_max = last_port
        print("Thread{} starts: {} ends: {}".format(i, min_port, next_max))
        threads.append(threading.Thread(target=scan_for_ports, args=("thread{}".format(i), min_port, next_max)))
        min_port = next_max

    print("~" * 50)
    print("Scanning for open ports in the range {}-{} . . .".format(first_port, last_port))
    print("Started -> " + str(datetime.now()))
    print("~" * 50)

    for e in threads:
        e.start()

    for e in threads:
        e.join()

    print("Ended -> " + str(datetime.now()))

    if len(ports_available) == 0:
        print("No open ports found {}-{}".format(first_port, last_port))
    else:
        print("Found the following open ports:")
        print("~" * 50)
        for port in ports_available:
            print(port)
        print("~" * 50)

    input("Exit")
