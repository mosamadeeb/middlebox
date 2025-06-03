import argparse
import itertools
import os
import random
import socket
import struct
import time

from packet_order_code import (
    PermutationConfig,
    gen_bit_string_to_permutation_map,
    get_bit_string,
)
from scapy.all import IP, TCP, Raw, send, sr1
from scapy.utils import checksum


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


def sender():
    parser = argparse.ArgumentParser(
        description="Sender script with configurable parameters."
    )
    parser.add_argument(
        "--transmission_rate",
        type=float,
        default=0.005,
        help="Transmission rate in seconds (default: 0.005)",
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

    TRANSMISSION_RATE = args.transmission_rate
    NUMBER_OF_PACKETS = args.number_of_packets

    # Function to generate random payloads
    def generate_random_payload(length):
        return os.urandom(length)

    def payload_generator():
        while True:
            payload_length = random.randint(4, 256)
            yield generate_random_payload(payload_length)

    message_cycle = payload_generator()

    if args.k > 0:
        PERM_CONFIG = PermutationConfig(K=args.k, BPS=args.bps)
        SYMBOL_TO_PERM_MAP = gen_bit_string_to_permutation_map(PERM_CONFIG)

        covert_message = "The quick brown fox jumps over the lazy dog."
        covert_message_symbols = get_bit_string(
            covert_message.encode("utf-8"), PERM_CONFIG.BPS
        )
        covert_message_symbols = [
            covert_message_symbols[i : i + PERM_CONFIG.BPS]
            for i in range(0, len(covert_message_symbols), PERM_CONFIG.BPS)
        ]
        covert_message_cycle = itertools.cycle(covert_message_symbols)

    host = os.getenv("SECURENET_HOST_IP")
    dst_ip = os.getenv("INSECURENET_HOST_IP")
    dst_port = 8888

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
        syn_packet = IP(src=src_ip, dst=dst_ip) / TCP(
            sport=src_port, dport=dst_port, flags="S", seq=seq_num
        )
        syn_ack_packet = sr1(syn_packet, timeout=2, verbose=0)

        if not syn_ack_packet:
            print("No SYN-ACK response received. Connection failed.")
            return

        # Extract acknowledgment number from SYN-ACK
        ack_num = syn_ack_packet[TCP].seq + 1
        seq_num = syn_ack_packet[TCP].ack

        # Send ACK to complete three-way handshake
        ack_packet = IP(src=src_ip, dst=dst_ip) / TCP(
            sport=src_port, dport=dst_port, flags="A", seq=seq_num, ack=ack_num
        )
        send(ack_packet, verbose=0)

        print("TCP connection established")

        def send_packet(payload, seq_num, ack_num):
            # Create data packet with PSH and ACK flags (for established connection)
            # PSH flag ensures data is pushed to the application layer immediately
            data_packet = (
                IP(src=src_ip, dst=dst_ip)
                / TCP(
                    sport=src_port, dport=dst_port, flags="PA", seq=seq_num, ack=ack_num
                )
                / Raw(load=payload)
            )

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
                ack_num = (
                    ack_response[TCP].seq + len(ack_response[Raw].load)
                    if Raw in ack_response
                    else ack_response[TCP].seq
                )
                print(
                    f"Data packet (SEQ={seq_num}) sent to {dst_ip}:{dst_port}, received acknowledgment"
                )
            else:
                print(
                    f"Data packet (SEQ={seq_num}) sent to {dst_ip}:{dst_port}, no acknowledgment received"
                )

            time.sleep(TRANSMISSION_RATE)

            return ack_num

        counter = 0

        # Step 2: Send data packets
        if args.k <= 0:
            # If K is not set, send single packets
            while True:
                payload = next(message_cycle)
                ack_num = send_packet(payload, seq_num, ack_num)
                print(f"Sent payload: {payload} in frame: [{seq_num}]")
                seq_num += 1
                counter += 1
                if counter >= NUMBER_OF_PACKETS:
                    break
        else:
            while True:
                payloads = [next(message_cycle) for _ in range(PERM_CONFIG.K)]

                symbol = next(covert_message_cycle)
                symbol_order = SYMBOL_TO_PERM_MAP[symbol]
                for i in symbol_order:
                    # TODO: This doesn't account for ack number
                    ack_num = send_packet(payloads[i], seq_num + i, ack_num)

                print(
                    f"Sent symbol: {symbol} in frame: [{seq_num}, ..., {seq_num + PERM_CONFIG.K - 1}]"
                )
                seq_num += PERM_CONFIG.K

                counter += PERM_CONFIG.K
                if counter >= NUMBER_OF_PACKETS:
                    break

        print("All packets sent..")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    sender()
