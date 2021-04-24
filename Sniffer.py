import logging, sys, ctypes, os
from datetime import datetime

# Trying to import scapy module if installed if not printing instructions and exiting the program
try:
    from scapy.all import *
except ModuleNotFoundError as exception:
    module_name = str(exception).split()[3]
    print(f'{exception}\nUse "pip3 install {module_name}" to install {module_name} module')
    sys.exit()

try:
    # Checking if the prgram run as a root or sudo user on linux
    is_admin = (os.getuid() == 0)
except AttributeError:
    # Checking if the program run with administrator privileges in windows
    is_admin = (ctypes.windll.shell32.IsUserAnAdmin() != 0)

# Priniting message and exiting the program if the user is not a admin or sudo user
if not is_admin:
    print('Program needs to be run with admin/sudo privileges!')
    sys.exit()

user_stop, capture_started = False, False
try:
    # Checking to see if scapy in promiscuos mode for packets capture 
    # If not trying to change its value to promiscuos mode and check again
    # if failing in one of the times exiting the program
    try:
        conf.sniff_promisc = 1
    except:
        print('Failed to configure promiscuos mode in scapy')
        sys.exit()
    else:
        if conf.sniff_promisc != 1:
            print('Failed to configure promiscuos mode in scapy')
            sys.exit()

    # Prompting the user for an interface name
    network_interface = input("Enter the name of the interface you want to use the sniffer on: ")

    # Getting all network interfaces in windows or linux
    interfaces_list =  [inter['name'] for inter in get_windows_if_list()] if os.name == 'nt' else get_if_list()

    # Checking if the interface the user entered exist in the computer if not exiting the program
    for inter in interfaces_list:
        # Making the check case insensetive and overiding with the real interface name
        if network_interface.casefold() == inter.casefold():
            network_interface = inter
            break
    else:
        print(f'No interface was found with name: {network_interface}')
        sys.exit()

    # Prompting the user for the number of packets to sniff
    packet_sniff_number = input("Enter the number of packets to sniff (0 is infinity): ")

    # Checking if the number entered by the user is a positive integer if so exiting the program
    if not packet_sniff_number.isdigit(): 
        print(f"The entered value {packet_sniff_number} is invalid for packet capture")
        sys.exit()
    
    # Checking if the number is greater than zero
    elif int(packet_sniff_number) > 0:
        packet_sniff_number = int(packet_sniff_number)
        print(f'The program will capture {packet_sniff_number} packets')
    
    # Checking if the number is equal to zero
    elif int(packet_sniff_number) == 0:
        packet_sniff_number = int(packet_sniff_number)
        print("The program will capture until the timeout expire.")
    
    # Prompting the user for the time the sniffer should continue to sniff
    sniff_time = input('Enter the number of seconds to run the capture: ')

    # Checking if the number entered by the user is a positive integer if so exiting the program
    if sniff_time.isdigit():
        sniff_time = int(sniff_time)
        print(f'The program will capture packets for {sniff_time} seconds.')
    else:
        print(f'The entered time {sniff_time} is invalid')
        sys.exit()

    # List of protocols for the user to choose to sniff
    protocols = ['arp','bootp','icmp','tcp','udp']
    nl='\n'
    # Prompting the user to choose which protocol to sniff from the list above or to sniff all protocols
    print(f'Choose the protocol the sniffer will filter by:{nl}{nl.join([f"{proto+1}. {protocols[proto]}" for proto in range(len(protocols))])}{nl}{len(protocols)+1}. all')
    sniff_protocol = input('Enter your choice: ')

    # Checking if the input entered by the user is a positive integer or if it's greater than the list length if so exiting the program
    if not sniff_protocol.isdigit() or int(sniff_protocol)-1 > len(protocols):
        print(f'The entered value for protocol is not defiend in the program or invalid')
        sys.exit()
    # Checking of the user entered the value for sniffing all protocols
    elif int(sniff_protocol)-1 == len(protocols):
        sniff_protocol = int(sniff_protocol)-1
        print(f'The program will capture packets of all protocols')
    # Checking if the user entered a value for one of the defiend protocols in the program
    elif 0 < int(sniff_protocol) < len(protocols):
        sniff_protocol = protocols[int(sniff_protocol)-1]
        print(f'The program will capture packets of {sniff_protocol} protocol')

    # Initializing Logger object to log packets from sniffer
    sniffer_log = logging.getLogger('sniffer_log')

    # Creating the custom logging message format
    formatter = logging.Formatter('Time: %(asctime)s.%(msecs)03d %(message)s', '%d-%m-%Y %H:%M:%S')
    
    # Setting the log level by getting the attribute value form the log level name
    sniffer_log.setLevel(getattr(logging, 'INFO'))
    
    # Creating the a stream handler for the log to print on the console
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    
    # Creating a file handler to write the log to a file with specified format
    log_file = f"sniffer_log_{datetime.now():%d-%m-%Y_%H-%M-%S}-protocol_{'ALL' if sniff_protocol == len(protocols) else sniff_protocol.upper()}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    
    # Adding the stream and file handlers to the logger object
    sniffer_log.addHandler(file_handler)
    sniffer_log.addHandler(stream_handler)  

    # Defiening a function that will be called for each captured packet and will log each packet relevant parameters to terminal and log file
    def log_packets(packet):
        # Checking if a packet contains on of the protocols that contain source ip and destination ip
        # If saving the packet protocol, source mac, destination mac, source ip and destination ip to a variable
        if packet[0][1].summary().split()[2].lower() in protocols:
            data = f'Protocol: {packet[0][1].summary().split()[2]} Source MAC: {packet[0].src} Destination MAC: {packet[0].dst} Source IP: {packet[0][1].src} Destination IP: {packet[0][1].dst}'
        # Else saving only the packet protocol, source mac and destination mac to a variable
        else:
            data = f'Protocol: {packet[0].summary().split()[2]} Source MAC: {packet[0].src} Destination MAC: {packet[0].dst}'

        # Logging the packet extracted data to the logger object.
        sniffer_log.info(data)
    
    # Starting the packets capture
    # in this stage the program will stop and wait for pakcets to arrive and print on the terminal or wait till it finishes or the user will manually stop it. 
    print('Starting the packet capture:\n')
    capture_started = True

    try:
        # If the user chose to sniff all protocols the scapy sniff function will be called without the filter paramter to capture everything
        if sniff_protocol == len(protocols):
            sniff(iface = network_interface, count = int(packet_sniff_number), timeout = int(sniff_time), prn = log_packets)
        # Else the sniff function will capture only the packets of the protocol defined in the 'filter' parameter in the function
        else:
            sniff(iface = network_interface, filter = sniff_protocol, count = int(packet_sniff_number), timeout = int(sniff_time), prn = log_packets)
    
    except Exception as exception:
        print(exception)

    # Informing the user that the timeout for the capturing has ended and the name of the log file created
    print(f'\Packet capture stopped, sniffing time ended\nLogged captured packets can be found in file {log_file}')

except KeyboardInterrupt:
    print('\nProgram was stopped by user')
    # Checking if the user stopped manually the program during the capturing process
    user_stop = True if capture_started else False
finally:
    # if the user manually stopped the program during the capturing process
    # Priniting to the user the name of the log file created
    if user_stop:
        print(f'\Packet capture stopped by user\nLogged captured packets can be found in file {log_file}')





