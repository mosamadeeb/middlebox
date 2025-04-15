import socket
import os
from scapy.all import sniff, IP, TCP, Raw, send
from scapy.utils import checksum
import struct

from packet_order_code import K, PERM_TO_SYMBOL_MAP, get_byte_from_bit_string

# Get the host IP from environment
sec_host = os.getenv('SECURENET_HOST_IP')
insec_host = os.getenv('INSECURENET_HOST_IP')

def calculate_tcp_checksum(ip_packet, tcp_segment):
    """
    Calculate TCP checksum with pseudo-header.
    
    Args:
        ip_packet: IP layer of the packet
        tcp_segment: TCP layer of the packet
        
    Returns:
        int: Calculated TCP checksum
    """
    # Create pseudo-header for TCP checksum calculation
    tcp_pseudo_header = struct.pack(
        '!4s4sBBH',
        socket.inet_aton(ip_packet.src),
        socket.inet_aton(ip_packet.dst),
        0,  # reserved (must be zero)
        socket.IPPROTO_TCP,
        len(bytes(tcp_segment))
    )
    
    # Calculate TCP checksum including pseudo-header
    tcp_checksum_data = tcp_pseudo_header + bytes(tcp_segment)
    return checksum(tcp_checksum_data)

codeword_buffer = []
channel_data_buffer = ''
overall_channel_data_buffer = ''

def update_covert_channel(seq):
    """
    Update the covert channel with the current sequence number.
    
    Args:
        seq: The sequence number of the packet
    """
    global codeword_buffer, channel_data_buffer, overall_channel_data_buffer
    codeword_buffer.append(seq)
    
    # Check if we have reached the limit of K packets
    if len(codeword_buffer) >= K:
        # Create the permutation based on the ordering of the original sequence numbers
        sorted_seq_nums = sorted(range(len(codeword_buffer)), key=lambda i: codeword_buffer[i])
        codeword_perm = [sorted_seq_nums.index(i) for i in range(len(codeword_buffer))]

        print(f"Received permutation: {codeword_perm}")

        print(tuple(codeword_perm))
        symbol = PERM_TO_SYMBOL_MAP.get(tuple(codeword_perm))
        if not symbol:
            print(f"Received INVALID permutation: {codeword_perm}")
        else:
            print(f"Received symbol: {symbol} from permutation: {codeword_perm}")
            channel_data_buffer += symbol

            if len(channel_data_buffer) >= 8:
                byte = get_byte_from_bit_string(channel_data_buffer[:8])
                print(f"Gathered byte: {byte} from buffer")
                channel_data_buffer = channel_data_buffer[8:]

                overall_channel_data_buffer += byte.decode('utf-8')
                print(f"Overall message: {overall_channel_data_buffer}")

        codeword_buffer.clear()

def handle_packet(packet):
    """Handle incoming packets"""
    # Check if packet is a valid TCP packet with IP layer
    if not (IP in packet and TCP in packet):
        return
    
    # Filter packets: only process those from the secure host
    if packet[IP].src != sec_host:
        return
    
    # Get source and destination info
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport

    # Only process packets destined for our service
    if dst_port != 8888:
        return
    
    # Handle SYN packet (connection establishment)
    if packet[TCP].flags & 0x02:  # SYN flag
        print(f"Received SYN from {src_ip}:{src_port}")
        
        # Create SYN-ACK response
        seq = 10000  # Our initial seq number
        ack = packet[TCP].seq + 1
        
        syn_ack = IP(src=dst_ip, dst=src_ip) / \
                 TCP(sport=dst_port, dport=src_port, flags='SA', 
                     seq=seq, ack=ack)
        
        # Calculate checksums
        del syn_ack[TCP].chksum
        del syn_ack[IP].chksum
        syn_ack[IP].chksum = checksum(bytes(syn_ack[IP]))
        syn_ack[TCP].chksum = calculate_tcp_checksum(syn_ack[IP], syn_ack[TCP])
        
        # Send SYN-ACK response
        send(syn_ack, verbose=0)
        print(f"Sent SYN-ACK to {src_ip}:{src_port}")
        
    # Handle ACK packet (part of three-way handshake)
    elif packet[TCP].flags & 0x10 and not packet[TCP].flags & 0x08:  # ACK flag without PSH
        print(f"Received ACK from {src_ip}:{src_port}")
        
    # Handle data packet (PSH-ACK)
    elif packet[TCP].flags & 0x18:  # PSH-ACK flags
        if Raw in packet:
            # NOTE: Only packets with payload can carry covert channel data
            update_covert_channel(packet[TCP].seq)
            
            payload = packet[Raw].load
            try:
                decoded_payload = payload.decode('utf-8')
                print(f"Received data from {src_ip}:{src_port}")
                print(f"SEQ: {packet[TCP].seq}, Payload: {decoded_payload}")
            except UnicodeDecodeError:
                print(f"Received binary data from {src_ip}:{src_port}")
            
            # Send ACK for the received data
            ack_packet = IP(src=dst_ip, dst=src_ip) / \
                         TCP(sport=dst_port, dport=src_port, flags='A',
                             seq=packet[TCP].ack, ack=packet[TCP].seq + len(payload))
            
            # Calculate checksums
            del ack_packet[TCP].chksum
            del ack_packet[IP].chksum
            ack_packet[IP].chksum = checksum(bytes(ack_packet[IP]))
            ack_packet[TCP].chksum = calculate_tcp_checksum(ack_packet[IP], ack_packet[TCP])
            
            # Send ACK
            send(ack_packet, verbose=0)
            # print(f"Sent ACK to {src_ip}:{src_port}")

def start_listener():
    if not sec_host:
        print("SECURENET_HOST_IP environment variable is not set.")
        return
        
    if not insec_host:
        print("INSECURENET_HOST_IP environment variable is not set.")
        return
        
    print(f"Starting TCP listener on port 8888, filtering for packets from {sec_host}")
    print("Waiting for packets...")
    
    # Use a BPF filter to only capture TCP packets to port 8888 from the secure host
    # This is more efficient than filtering in Python
    filter_str = f"tcp and port 8888 and src host {sec_host}"
    sniff(filter=filter_str, prn=handle_packet, store=0)

if __name__ == "__main__":
    start_listener()
