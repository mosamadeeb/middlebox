import argparse
import os
import socket
import struct

from packet_order_code import (
    PermutationConfig,
    gen_permutation_to_bit_string_map,
    get_byte_from_bit_string,
)
from scapy.all import IP, TCP, Raw, send, sniff
from scapy.utils import checksum

# Get the host IP from environment
sec_host = os.getenv("SECURENET_HOST_IP")
insec_host = os.getenv("INSECURENET_HOST_IP")

# Initialization (these are not used)
NUMBER_OF_PACKETS = 0
PERM_CONFIG = PermutationConfig()
PERM_TO_SYMBOL_MAP = dict()

USE_COVERT_CHANNEL = False


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
        "!4s4sBBH",
        socket.inet_aton(ip_packet.src),
        socket.inet_aton(ip_packet.dst),
        0,  # reserved (must be zero)
        socket.IPPROTO_TCP,
        len(bytes(tcp_segment)),
    )

    # Calculate TCP checksum including pseudo-header
    tcp_checksum_data = tcp_pseudo_header + bytes(tcp_segment)
    return checksum(tcp_checksum_data)


codeword_buffer = []
channel_data_buffer = ""
overall_channel_data_buffer = ""

# Updated during initialization
covert_message = ""

counter = 0

total_bit_errors = 0


def check_bit_errors(original_msg, received_msg):
    # Make sure we compare the minimum length of both messages
    min_length = min(len(received_msg), len(original_msg))
    received_msg = received_msg[:min_length]
    original_msg = original_msg[:min_length]

    # Convert messages to bits and count differences
    bit_errors = 0
    for r_char, o_char in zip(received_msg, original_msg):
        r_bits = format(ord(r_char), "08b")
        o_bits = format(ord(o_char), "08b")
        for r_bit, o_bit in zip(r_bits, o_bits):
            if r_bit != o_bit:
                bit_errors += 1

    print(f"Bit differences: {bit_errors}")

    global total_bit_errors
    total_bit_errors += bit_errors


def update_covert_channel(seq):
    """
    Update the covert channel with the current sequence number.

    Args:
        seq: The sequence number of the packet
    """
    global codeword_buffer, channel_data_buffer, overall_channel_data_buffer
    codeword_buffer.append(seq)

    # Check if we have reached the limit of K packets
    if len(codeword_buffer) >= PERM_CONFIG.K:
        # Create the permutation based on the ordering of the original sequence numbers
        sorted_seq_nums = sorted(
            range(len(codeword_buffer)), key=lambda i: codeword_buffer[i]
        )
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

                overall_channel_data_buffer += byte.decode("utf-8", "backslashreplace")
                # print(f"Overall message: {overall_channel_data_buffer}")

                if len(overall_channel_data_buffer) >= len(covert_message):
                    print("Full message received. Resetting buffer.")

                    # Calculate bit differences between received message and original message
                    check_bit_errors(covert_message, overall_channel_data_buffer)

                    overall_channel_data_buffer = ""

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

        syn_ack = IP(src=dst_ip, dst=src_ip) / TCP(
            sport=dst_port, dport=src_port, flags="SA", seq=seq, ack=ack
        )

        # Calculate checksums
        del syn_ack[TCP].chksum
        del syn_ack[IP].chksum
        syn_ack[IP].chksum = checksum(bytes(syn_ack[IP]))
        syn_ack[TCP].chksum = calculate_tcp_checksum(syn_ack[IP], syn_ack[TCP])

        # Send SYN-ACK response
        send(syn_ack, verbose=0)
        print(f"Sent SYN-ACK to {src_ip}:{src_port}")

    # Handle ACK packet (part of three-way handshake)
    elif (
        packet[TCP].flags & 0x10 and not packet[TCP].flags & 0x08
    ):  # ACK flag without PSH
        print(f"Received ACK from {src_ip}:{src_port}")

    # Handle data packet (PSH-ACK)
    elif packet[TCP].flags & 0x18:  # PSH-ACK flags
        if Raw in packet:
            payload = packet[Raw].load

            print(f"Received binary data from {src_ip}:{src_port} with SEQ: {packet[TCP].seq}")

            # Send ACK for the received data
            ack_packet = IP(src=dst_ip, dst=src_ip) / TCP(
                sport=dst_port,
                dport=src_port,
                flags="A",
                seq=packet[TCP].ack,
                ack=packet[TCP].seq + len(payload),
            )

            # Calculate checksums
            del ack_packet[TCP].chksum
            del ack_packet[IP].chksum
            ack_packet[IP].chksum = checksum(bytes(ack_packet[IP]))
            ack_packet[TCP].chksum = calculate_tcp_checksum(
                ack_packet[IP], ack_packet[TCP]
            )

            # Send ACK
            send(ack_packet, verbose=0)
            # print(f"Sent ACK to {src_ip}:{src_port}")

            if USE_COVERT_CHANNEL:
                # NOTE: Only packets with payload can carry covert channel data
                update_covert_channel(packet[TCP].seq)

            global counter
            counter += 1
            if counter >= NUMBER_OF_PACKETS:
                print("Received enough packets, stopping listener.")

                if USE_COVERT_CHANNEL:
                    # Check the last set of bit errors
                    check_bit_errors(
                        covert_message[: len(overall_channel_data_buffer)],
                        overall_channel_data_buffer,
                    )
                    print("Total bit errors:", total_bit_errors)

                # Exit the program
                os._exit(0)


def start_listener():
    parser = argparse.ArgumentParser(
        description="Receiver script with configurable parameters."
    )
    parser.add_argument(
        "--message_offset",
        type=int,
        default=0,
        help="Start offset for the covert message data (default: 0)",
    )
    parser.add_argument(
        "--number_of_packets",
        type=int,
        default=3000,
        help="Number of packets to send (default: 3000)",
    )
    parser.add_argument(
        "--k", type=int, default=4, help="Length of codeword (default: 4)"
    )
    parser.add_argument(
        "--bps", type=int, default=4, help="Bits per symbol (default: 4)"
    )

    args = parser.parse_args()

    global NUMBER_OF_PACKETS, PERM_CONFIG, PERM_TO_SYMBOL_MAP

    NUMBER_OF_PACKETS = args.number_of_packets

    if args.k > 0:
        global USE_COVERT_CHANNEL, covert_message
        USE_COVERT_CHANNEL = True

        with open("covert_message.txt", "r") as f:
            covert_message = f.read().strip()
        if args.message_offset > 0:
            covert_message = covert_message[args.message_offset :]

        PERM_CONFIG = PermutationConfig(K=args.k, BPS=args.bps)
        PERM_TO_SYMBOL_MAP = gen_permutation_to_bit_string_map(PERM_CONFIG)

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
