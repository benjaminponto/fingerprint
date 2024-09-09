from scapy.all import *

def send_syn_packet(target_ip, target_port):
    # Create an IP layer
    ip = IP(dst=target_ip)
    
    # Create a TCP layer with SYN flag set
    tcp = TCP(dport=target_port, flags='S')
    
    # Construct the packet
    packet = ip/tcp
    
    # Send the packet and capture the response
    response = sr1(packet, timeout=1)
    
    return response

def analyze_response(response):
    #in this function we can determin the OS of the packet that is recieved
    if response is None:
        print("No response received. The target might be down or firewalled.")
        return

    # Analyze response and extract information
    if response.haslayer(TCP):

        tcp_layer = response.getlayer(TCP)
        ip_layer = response.getlayer(IP)

        ttl = ip_layer.ttl
        window_size = tcp_layer.window
        flags = tcp_layer.flags
        options = tcp_layer.options 

        print(f"TTL: {ttl}")
        print(f"Window Size: {window_size}")
        print(f"Flags: {flags}")
        print(f"Options: {options}") 

        #Based on certain charecterisitics like ttl, window size, flags and options we can determine the OS of the target
        if ttl == 64:
            print("Likely a Linux system.")
        elif ttl == 128:
            print("Likely a Windows system.")
        elif window_size == 65535:
            print("Likely a macOS system.")
        else:
            print("not able to determin the operating system.")


        if tcp_layer.flags & 0x12:  # SYN-ACK flag
            print("Received SYN-ACK from target.")
            print("Potential OS fingerprint information:")
            # Further analysis can be done based on TCP flags and options
        elif tcp_layer.flags & 0x14:  # RST-ACK flag
            print("Received RST-ACK from target. Port might be closed.")
    else:
        print("Response does not contain TCP layer.")

def main():
    target_ip = input("Enter the target IP address:")
    target_port = 80  # Common HTTP port for testing

    print(f"Sending SYN packet to {target_ip}:{target_port}")
    response = send_syn_packet(target_ip, target_port)
    analyze_response(response)

if __name__ == "__main__":
    main()