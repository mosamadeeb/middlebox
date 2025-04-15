import os
import socket
import time
import struct
from scapy.all import IP, TCP, Raw, send, sr1
from scapy.utils import checksum
import itertools

from packet_order_code import K, BPS, SYMBOL_TO_PERM_MAP, get_bit_string

TRANSMISSION_RATE = 0.005  # seconds

NUMBER_OF_PACKETS = 3000

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

def sender():
    host = os.getenv('SECURENET_HOST_IP')
    dst_ip = os.getenv('INSECURENET_HOST_IP')
    dst_port = 8888

    # Create a cyclic iterator over capital alphabets (A-Z)
    # This has the nice side effect of the payload being 1 byte long
    message_cycle = itertools.cycle('ABCDEFGHIJKLMNOPQRSTUVWXYZ')

    covert_message = 'The quick brown fox jumps over the lazy dog.'
    covert_message_symbols = get_bit_string(covert_message.encode('utf-8'))
    covert_message_symbols = [covert_message_symbols[i:i+BPS] for i in range(0, len(covert_message_symbols), BPS)]
    covert_message_cycle = itertools.cycle(covert_message_symbols)

    if not host:
        print("SECURENET_HOST_IP environment variable is not set.")
        return

    if not dst_ip:
        print("SECURENET_HOST_IP environment variable is not set.")
        return

    try:
        # Source IP and port
        src_ip = host
        src_port = dst_port
        
        # Initial sequence number
        seq_num = 1000
        
        # Step 1: Establish a connection with three-way handshake
        print("Establishing TCP connection...")
        
        # SYN packet
        syn_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='S', seq=seq_num)
        syn_ack_packet = sr1(syn_packet, timeout=2, verbose=0)
        
        if not syn_ack_packet:
            print("No SYN-ACK response received. Connection failed.")
            return
        
        # Extract acknowledgment number from SYN-ACK
        ack_num = syn_ack_packet[TCP].seq + 1
        seq_num = syn_ack_packet[TCP].ack
        
        # Send ACK to complete three-way handshake
        ack_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='A', seq=seq_num, ack=ack_num)
        send(ack_packet, verbose=0)
        
        print("TCP connection established")

        counter = 0
        
        # Step 2: Send data packets
        while True:
            def send_packet(payload, seq_num, ack_num):
                # Create data packet with PSH and ACK flags (for established connection)
                # PSH flag ensures data is pushed to the application layer immediately
                data_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, 
                                                            flags='PA', seq=seq_num, ack=ack_num)/Raw(load=payload)
                
                # Remove auto-calculated checksums
                del data_packet[TCP].chksum
                del data_packet[IP].chksum
                
                # Calculate IP checksum manually
                ip_checksum = checksum(bytes(data_packet[IP]))
                data_packet[IP].chksum = ip_checksum

                # Calculate TCP checksum manually
                tcp_checksum = calculate_tcp_checksum(data_packet[IP], data_packet[TCP])
                data_packet[TCP].chksum = tcp_checksum
                
                # Send the data packet
                ack_response = sr1(data_packet, timeout=2, verbose=0)
                
                if ack_response:
                    # Update acknowledgment numbers
                    ack_num = ack_response[TCP].seq + len(ack_response[Raw].load) if Raw in ack_response else ack_response[TCP].seq
                    print(f"Data packet (SEQ={seq_num}) sent to {dst_ip}:{dst_port}, received acknowledgment")
                else:
                    print(f"Data packet (SEQ={seq_num}) sent to {dst_ip}:{dst_port}, no acknowledgment received")
                
                time.sleep(TRANSMISSION_RATE)

                return ack_num
            
            payloads = [next(message_cycle) for _ in range(K)]

            symbol = next(covert_message_cycle)
            symbol_order = SYMBOL_TO_PERM_MAP[symbol]
            for i in symbol_order:
                # TODO: This doesn't account for ack number
                ack_num = send_packet(payloads[i], seq_num + i, ack_num)
            
            print(f"Sent symbol: {symbol} in frame: [{seq_num}, ..., {seq_num + K - 1}]")
            seq_num += K

            counter += K
            if counter >= NUMBER_OF_PACKETS:
                break
        
        print("All packets sent..")


    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    sender()
