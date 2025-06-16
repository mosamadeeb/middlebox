/**
 * @file switch.c
 * @brief A packet switch implementation that captures packets from two interfaces (ethsec and ethinsec) and forwards them to the other interface.
 * 
 * This program creates raw sockets for two network interfaces (ethsec and ethinsec), captures packets from each interface, and publishes them to NATS topics.
 * It uses pthreads to handle packet capturing and forwarding concurrently.
 * The program integrates with NATS for message publishing and subscribing:
 * - Captured packets are published to NATS subjects ("inpktfromsec" and "inpktfrominsec").
 * - Subscribes to NATS subjects ("outpktsec" and "outpktinsec") to receive packets from packet processors and forwards them to the appropriate interface.
 * 
 * @dependencies
 * - pthread
 * - raw sockets 
 * - nats
 * 
 * @author
 * - Ertan Onur
 * 
 * @date
 * - February 21, 2025
 * 
 * @version
 * - 1.0
 * 
 * @details
 * The program performs the following steps:
 * 1. Configures the switch by reading environment variables.
 * 2. Creates raw sockets for ethsec and ethinsec.
 * 3. Binds the raw sockets to the respective network interfaces.
 * 4. Creates two threads to capture packets from ethsec and ethinsec.
 * 5. Captures packets in each thread.
 * 6. Prints packet details for IP, TCP, UDP, and ICMP headers.
 * 7. Publishes packets to NATS subjects for further processing.
 * 8. Subscribes to NATS subjects to receive packets and forwards them to the appropriate interface.
 * 9. Handles NATS messages and prints Ethernet packet details.
 * 10. Cleans up NATS connections and subscriptions on program exit.
 * 
 * @functions
 * - int main()
 *   - Entry point of the program. Initializes raw sockets, binds them to interfaces, and creates threads for packet capturing.
 * 
 * - void *capture_packets(void *arg)
 *   - Captures packets from the specified interface and forwards them to the other interface.
 *   - @param arg Pointer to the interface name (ethsec or ethinsec).
 *   - @return NULL
 * 
 * - void handle_packet_from_interface(unsigned char *buffer, int size, char *in_iface)
 *   - Switches the packet to the other interface and prints packet details.
 *   - @param buffer Pointer to the packet buffer.
 *   - @param size Size of the packet.
 *   - @param in_iface Name of the input interface (ethsec or ethinsec).
 * 
 * - bool configure_switch()
 *   - Configures the switch by reading environment variables and querying MAC addresses.
 *   - @return true if configuration is successful, false otherwise.
 * 
 * - bool configureRawSockets()
 *   - Configures raw sockets for ethsec and ethinsec.
 *   - @return true if configuration is successful, false otherwise.
 * 
 * - bool configure_nats()
 *   - Configures NATS connection and subscriptions.
 *   - @return true if configuration is successful, false otherwise.
 * 
 * - char *get_interface_for_subnet(char *subnet)
 *   - Gets the interface name for a given subnet.
 *   - @param subnet Subnet in CIDR notation.
 *   - @return Pointer to the interface name.
 * 
 * - void query_mac_address(char *interface, char *host_ip, unsigned char *mac_address)
 *   - Queries the MAC address for a given interface and host IP.
 *   - @param interface Name of the network interface.
 *   - @param host_ip IP address of the host.
 *   - @param mac_address Pointer to the MAC address buffer.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <netpacket/packet.h>
#include <stdbool.h>
#include <nats/nats.h>

#define BUF_SIZE 65536

int sock_raw_ethsec;
int sock_raw_ethinsec;
unsigned char mac_ethsec[6];
unsigned char mac_ethinsec[6];
unsigned char mac_secure_net_host[6];
unsigned char mac_insecure_net_host[6];

void *capture_packets(void *arg);
void handle_packet_from_nats(natsConnection *nc, natsSubscription *sub, natsMsg *msg, void *closure);
void handle_packet_from_interface(unsigned char *buffer, int size, char *in_iface);
bool configure_switch();
bool configureRawSockets();
bool configure_nats();
char *get_interface_for_subnet(char *subnet);
void query_mac_address(char *interface, char *host_ip, unsigned char *mac_address);
void query_mac_address_with_arp(char *interface, char *host_ip, unsigned char *mac_address);
void query_mac_address_with_arp_query(char *interface, char *host_ip, unsigned char *mac_address);
void print_packet(unsigned char *buffer, int size, char *iface, bool is_outgoing);

// NOT A GOOD EXERCISE TO USE GLOBAL VARIABLES
// But for the sake of simplicity, we are using them here
char *ethsec ;
char *ethinsec ;
char *secure_net_host_ip;
char *insecure_net_host_ip;
char *secure_net_subnet;
char *insecure_net_subnet;
char *nats_url;

natsConnection *conn = NULL;
natsOptions *opts = NULL;


int main() {

    // READ ENVIRONMENT VARIABLES and CONFIGURE IP ADDRESS, MAC ADDRESS, INTERFACE NAMES
    bool configured = configure_switch();
    if (!configured) {
        fprintf(stderr, "Switch configuration failed; check your docker-compose settings, define env variables correctly.\n");
        exit(1);
    }
    else
    {
        printf("Switch configuration successful\n");
    }

    // CONFIGURE RAW SOCKETS, create raw sockets for ethsec and ethinsec
    configured = configureRawSockets();
    if (!configured) {
        fprintf(stderr, "Raw socket configuration failed; check your docker-compose settings, define env variables correctly.\n");
        exit(1);
    }
    else
    {
        printf("Raw socket configuration successful\n");
    }

    // CONFIGURE NATS CONNECTION, create NATS connection and subscriptions
    configured = configure_nats(); 
    if (!configured) {
        fprintf(stderr, "NATS configuration failed; check your docker-compose settings, define env variables correctly.\n");
        exit(1);
    }
    else
    {
        printf("NATS configuration successful\n");
    }

    pthread_t thread1, thread2;

    if (pthread_create(&thread1, NULL, capture_packets, (void *)ethsec) < 0) {
        perror("Thread creation failed for ethsec");
        exit(1);
    }

    if (pthread_create(&thread2, NULL, capture_packets, (void *)ethinsec) < 0) {
        perror("Thread creation failed for ethinsec");
        exit(1);
    }


    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    // Cleanup NATS connection
    natsConnection_Destroy(conn);
    natsOptions_Destroy(opts);

    return 0;
}

void *capture_packets(void *arg) {
    int sock_raw;
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);
    unsigned char *buffer = (unsigned char *)malloc(BUF_SIZE);
    char *interface = (char *)arg;

    if (strcmp(interface, ethsec) == 0) {
        sock_raw = sock_raw_ethsec;
        printf("Capturing packets from ethsec\n");
    } else {
        sock_raw = sock_raw_ethinsec;
        printf("Capturing packets from ethinsec\n");
    } 

    while (1) {
        int data_size = recvfrom(sock_raw, buffer, BUF_SIZE, 0, &saddr, (socklen_t *)&saddr_len);
        if (data_size < 0) {
            perror("Recvfrom error");
            return NULL;
        }
        handle_packet_from_interface(buffer, data_size, interface);
    }

    return NULL;
}


void handle_packet_from_interface(unsigned char *buffer, int size, char *in_iface) {
    
    natsStatus s;
    // print_packet(buffer, size, in_iface, false);
    if (strcmp(in_iface, ethsec) == 0) {
        // Publish the packet to NATS
        s = natsConnection_Publish(conn, "inpktsec", buffer, size);
        if (s != NATS_OK) {
            fprintf(stderr, "Error publishing packet to NATS: %s\n", natsStatus_GetText(s));
        }
    } else {                
        s = natsConnection_Publish(conn, "inpktinsec", buffer, size);
        if (s != NATS_OK) {
            fprintf(stderr, "Error publishing packet to NATS: %s\n", natsStatus_GetText(s));
        }
    }    
}


void handle_packet_from_nats(natsConnection *nc, natsSubscription *sub, natsMsg *msg, void *closure) {
    unsigned char *buffer = (unsigned char *)natsMsg_GetData(msg);
    int size = natsMsg_GetDataLength(msg);
    struct ethhdr *eth = (struct ethhdr *)buffer;
    char * outiface;
    if (strcmp(natsMsg_GetSubject(msg), "outpktsec") == 0) {
        memcpy(eth->h_dest, mac_secure_net_host, 6);
        //memcpy(eth->h_source, mac_ethsec, 6);

        outiface = ethsec;
        if (sendto(sock_raw_ethsec, buffer, size, MSG_DONTROUTE, NULL, 0) < 0) {
            perror("Sendto error for ethsec");
        }
    } else if (strcmp(natsMsg_GetSubject(msg), "outpktinsec") == 0) {
        memcpy(eth->h_dest, mac_insecure_net_host, 6);
        //memcpy(eth->h_source, mac_ethinsec, 6);
        outiface = ethinsec;
        if (sendto(sock_raw_ethinsec, buffer, size, MSG_DONTROUTE, NULL, 0) < 0) {
            perror("Sendto error for ethinsec");
        }
    }

    // print_packet(buffer, size, outiface, true);

    natsMsg_Destroy(msg);
}



bool configure_switch(){

    bool configured = true;

    nats_url = getenv("NATS_SURVEYOR_SERVERS");
    if (nats_url == NULL) {
        fprintf(stderr, "Environment variable NATS_SURVEYOR_SERVERS not set.\n");
        configured = false;
    }
    printf("NATS_SURVEYOR_SERVERS: %s\n", nats_url);
    

    secure_net_host_ip = getenv("SECURENET_HOST_IP");
    if (secure_net_host_ip == NULL) {
        fprintf(stderr, "Environment variable SECURENET_HOST_IP not set.\n");
        configured = false;
    }
    printf("SECURENET_HOST_IP: %s\n", secure_net_host_ip);
    

    insecure_net_host_ip = getenv("INSECURENET_HOST_IP");
    if (insecure_net_host_ip == NULL) {
        fprintf(stderr, "Environment variable INSECURENET_HOST_IP not set.\n");
        configured = false;
    }
    printf("INSECURENET_HOST_IP: %s\n", insecure_net_host_ip);

    secure_net_subnet = getenv("SECURE_NET");
    if (secure_net_subnet == NULL) {
        fprintf(stderr, "Environment variable SECURE_NET not set.\n");
        configured = false;
    }
    printf("SECURE_NET: %s\n", secure_net_subnet);

    insecure_net_subnet = getenv("INSECURE_NET");
    if (insecure_net_subnet == NULL) {
        fprintf(stderr, "Environment variable INSECURE_NET not set.\n");
        configured = false;
    }
    printf("INSECURE_NET: %s\n", insecure_net_subnet);

    // Get the interface names for the secure and insecure subnets
    ethsec = get_interface_for_subnet(secure_net_subnet);
    ethinsec = get_interface_for_subnet(insecure_net_subnet);


    printf("Interface for secure subnet (%s): %s\n", secure_net_subnet, ethsec);
    printf("Interface for insecure subnet (%s): %s\n", insecure_net_subnet, ethinsec);

    // Query the MAC address of secure_net_host_ip    
    query_mac_address_with_arp_query(ethsec, secure_net_host_ip, mac_secure_net_host);
    query_mac_address_with_arp_query(ethinsec, insecure_net_host_ip, mac_insecure_net_host);

    printf("MAC address of (%s): %02x:%02x:%02x:%02x:%02x:%02x\n",
        secure_net_host_ip,
        mac_secure_net_host[0], mac_secure_net_host[1], mac_secure_net_host[2],
        mac_secure_net_host[3], mac_secure_net_host[4], mac_secure_net_host[5]);

    printf("MAC address of (%s): %02x:%02x:%02x:%02x:%02x:%02x\n",
        insecure_net_host_ip,
        mac_insecure_net_host[0], mac_insecure_net_host[1], mac_insecure_net_host[2],
        mac_insecure_net_host[3], mac_insecure_net_host[4], mac_insecure_net_host[5]);

    return configured;
}


bool configureRawSockets() {
    bool configured = true;
    struct ifreq ifr_ethsec, ifr_ethinsec;
    struct sockaddr_ll sll_ethsec, sll_ethinsec;

    if ((sock_raw_ethsec = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("Socket Error for ethsec");
        configured = false;
    }

    if ((sock_raw_ethinsec = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("Socket Error for ethinsec");
        configured = false;
    }

    // Bind raw socket sock_raw_ethsec to interfaces ethsec
    memset(&ifr_ethsec, 0, sizeof(ifr_ethsec));
    strncpy(ifr_ethsec.ifr_name, ethsec, IFNAMSIZ - 1);
    if (ioctl(sock_raw_ethsec, SIOCGIFINDEX, &ifr_ethsec) < 0) {
        perror("ioctl error for ethsec");
        configured = false;
    }
    memset(&sll_ethsec, 0, sizeof(sll_ethsec));
    sll_ethsec.sll_family = AF_PACKET;
    sll_ethsec.sll_ifindex = ifr_ethsec.ifr_ifindex;
    sll_ethsec.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock_raw_ethsec, (struct sockaddr *)&sll_ethsec, sizeof(sll_ethsec)) < 0) {
        perror("Bind error for ethsec");
        configured = false;
    }

    // Get MAC address of ethsec
    if (ioctl(sock_raw_ethsec, SIOCGIFHWADDR, &ifr_ethsec) < 0) {
        perror("ioctl error for getting MAC address of ethsec");
        configured = false;
    }
    memcpy(mac_ethsec, ifr_ethsec.ifr_hwaddr.sa_data, 6);

    printf("MAC address of ethsec: %02x:%02x:%02x:%02x:%02x:%02x\n",
           mac_ethsec[0], mac_ethsec[1], mac_ethsec[2], mac_ethsec[3], mac_ethsec[4], mac_ethsec[5]);
    
    // Bind raw socket sock_raw_ethinsec to interfaces ethinsec
    memset(&ifr_ethinsec, 0, sizeof(ifr_ethinsec));
    strncpy(ifr_ethinsec.ifr_name, ethinsec, IFNAMSIZ - 1);
    if (ioctl(sock_raw_ethinsec, SIOCGIFINDEX, &ifr_ethinsec) < 0) {
        perror("ioctl error for ethinsec");
        configured = false;
    }
    memset(&sll_ethinsec, 0, sizeof(sll_ethinsec));
    sll_ethinsec.sll_family = AF_PACKET;
    sll_ethinsec.sll_ifindex = ifr_ethinsec.ifr_ifindex;
    sll_ethinsec.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock_raw_ethinsec, (struct sockaddr *)&sll_ethinsec, sizeof(sll_ethinsec)) < 0) {
        perror("Bind error for ethinsec");
        configured = false;
    }

    // Get MAC address of ethinsec
    if (ioctl(sock_raw_ethinsec, SIOCGIFHWADDR, &ifr_ethinsec) < 0) {
        perror("ioctl error for getting MAC address of ethinsec");
        configured = false;
    }
    memcpy(mac_ethinsec, ifr_ethinsec.ifr_hwaddr.sa_data, 6);

    printf("MAC address of ethinsec: %02x:%02x:%02x:%02x:%02x:%02x\n",
           mac_ethinsec[0], mac_ethinsec[1], mac_ethinsec[2], mac_ethinsec[3], mac_ethinsec[4], mac_ethinsec[5]);


    return configured;
}


bool configure_nats() {
    // Initialize NATS connection
    bool configured = true;
    natsStatus s = natsOptions_Create(&opts);
    if (s == NATS_OK) {
        s = natsOptions_SetURL(opts, nats_url);
    }
    if (s == NATS_OK) {
        s = natsConnection_Connect(&conn, opts);
    }
    if (s != NATS_OK) {
        fprintf(stderr, "Error connecting to NATS: %s\n", natsStatus_GetText(s));
        configured =false;
    }

    natsSubscription *sub_outpktsec = NULL;
    natsSubscription *sub_outpktinsec = NULL;
    s = natsConnection_Subscribe(&sub_outpktsec, conn, "outpktsec", handle_packet_from_nats, NULL);
     if (s != NATS_OK) {
        fprintf(stderr, "Error subscribing to outpktsec: %s\n", natsStatus_GetText(s));
        configured =false;
    }
    s = natsConnection_Subscribe(&sub_outpktinsec, conn, "outpktinsec", handle_packet_from_nats, NULL);
    if (s != NATS_OK) {
        fprintf(stderr, "Error subscribing to outpktinsec: %s\n", natsStatus_GetText(s));
        configured =false;
    }
    return configured;
}

// Function to get the interface name for a given subnet
char *get_interface_for_subnet(char *subnet) {
    FILE *fp;
    char path[1035];
    char *interface = (char *)malloc(IFNAMSIZ);
    // Shell command to list interfaces and fetch the interface name that has the subnet
    // Run the shell command to find the interface name
    snprintf(path, sizeof(path), "ip route | grep %s | awk '{print $3}'", subnet);
    fp = popen(path, "r");
    if (fp == NULL) {
        perror("Failed to run command");
        exit(1);
    }

    // Read the output a line at a time
    if (fgets(interface, IFNAMSIZ, fp) != NULL) {
        // Remove the newline character from the end
        interface[strcspn(interface, "\n")] = 0;
    } else {
        fprintf(stderr, "No interface found for subnet %s\n", subnet);
        exit(1);
    }

    pclose(fp);
    return interface;
}

void query_mac_address_with_arp_query(char *interface, char *host_ip, unsigned char *mac_address) {
    int sock;
    struct sockaddr_in target;
    struct arpreq req;
    struct sockaddr_in *sin;

    // Create a socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    // Set up the target address
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    inet_pton(AF_INET, host_ip, &target.sin_addr);

    // Set up the ARP request
    memset(&req, 0, sizeof(req));
    sin = (struct sockaddr_in *)&req.arp_pa;
    sin->sin_family = AF_INET;
    sin->sin_addr = target.sin_addr;
    strncpy(req.arp_dev, interface, IFNAMSIZ - 1);

    // Perform the ARP query
    if (ioctl(sock, SIOCGARP, &req) < 0) {
        perror("ARP query failed");
        close(sock);
        exit(1);
    }
    memcpy(mac_address, req.arp_ha.sa_data, 6);
    printf("Queried MAC address for %s on interface %s: %02x:%02x:%02x:%02x:%02x:%02x\n",
        host_ip, interface,
        mac_address[0], mac_address[1], mac_address[2],
        mac_address[3], mac_address[4], mac_address[5]);
    // Copy the MAC address

    close(sock);
}

void query_mac_address_with_arp_cache(char *interface, char *host_ip, unsigned char *mac_address) {
    FILE *arp_cache = fopen("/proc/net/arp", "r");
    if (!arp_cache) {
        perror("Failed to open ARP cache");
        exit(1);
    }

    char line[256];
    bool found = false;

    // Skip the header line
    fgets(line, sizeof(line), arp_cache);

    while (fgets(line, sizeof(line), arp_cache)) {
        char ip[INET_ADDRSTRLEN], hw_type[8], flags[8], mac[18], mask[8], dev[IFNAMSIZ];
        if (sscanf(line, "%s %s %s %s %s %s", ip, hw_type, flags, mac, mask, dev) == 6) {
            if (strcmp(ip, host_ip) == 0 && strcmp(dev, interface) == 0) {
                sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                       &mac_address[0], &mac_address[1], &mac_address[2],
                       &mac_address[3], &mac_address[4], &mac_address[5]);
                found = true;
                break;
            }
        }
    }

    fclose(arp_cache);

    if (!found) {
        fprintf(stderr, "MAC address for IP %s on interface %s not found in ARP cache\n", host_ip, interface);
        exit(1);
    }
}

// This is how docker assigns mac addresses to interfaces
// Starts with 02:42 and then the ip address
// For example, 02:42:0a:00:00:15 with 02:42 and then the 10.0.0.21 in hex byte-by-byte.
void query_mac_address(char *interface, char *host_ip, unsigned char *mac_address){
   mac_address[0] = 0x02;
   mac_address[1] = 0x42;
    struct in_addr ip_addr;
    inet_pton(AF_INET, host_ip, &ip_addr);
    unsigned char *ip_bytes = (unsigned char *)&ip_addr.s_addr;
    mac_address[2] = ip_bytes[0];
    mac_address[3] = ip_bytes[1];
    mac_address[4] = ip_bytes[2];
    mac_address[5] = ip_bytes[3];
}


void print_packet(unsigned char *buffer, int size, char *iface, bool is_outgoing)
{
    struct ethhdr *eth = (struct ethhdr *)buffer;
    
    if (ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        if (is_outgoing)
            printf("Packet from %s IP Header:\n", iface);
        else
            printf("Packet to %s IP Header:\n", iface);
        printf("   |-IP Version        : %d\n", (unsigned int)iph->version);
        printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)iph->ihl, ((unsigned int)(iph->ihl)) * 4);
        printf("   |-Type Of Service   : %d\n", (unsigned int)iph->tos);
        printf("   |-IP Total Length   : %d Bytes(Size of Packet)\n", ntohs(iph->tot_len));
        printf("   |-Identification    : %d\n", ntohs(iph->id));
        printf("   |-TTL               : %d\n", (unsigned int)iph->ttl);
        printf("   |-Protocol          : %d\n", (unsigned int)iph->protocol);
        printf("   |-Checksum          : %d\n", ntohs(iph->check));
        printf("   |-Source IP         : %s\n", inet_ntoa(*(struct in_addr *)&iph->saddr));
        printf("   |-Destination IP    : %s\n", inet_ntoa(*(struct in_addr *)&iph->daddr));
        
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ihl * 4 + sizeof(struct ethhdr));
            printf("TCP Header:\n");
            printf("   |-Source Port       : %u\n", ntohs(tcph->source));
            printf("   |-Destination Port  : %u\n", ntohs(tcph->dest));
            printf("   |-Sequence Number   : %u\n", ntohl(tcph->seq));
            printf("   |-Acknowledge Number: %u\n", ntohl(tcph->ack_seq));
            printf("   |-Header Length     : %d DWORDS or %d Bytes\n", (unsigned int)tcph->doff, (unsigned int)tcph->doff * 4);
            printf("   |-Urgent Flag       : %d\n", (unsigned int)tcph->urg);
            printf("   |-Acknowledgement Flag : %d\n", (unsigned int)tcph->ack);
            printf("   |-Push Flag         : %d\n", (unsigned int)tcph->psh);
            printf("   |-Reset Flag        : %d\n", (unsigned int)tcph->rst);
            printf("   |-Synchronise Flag  : %d\n", (unsigned int)tcph->syn);
            printf("   |-Finish Flag       : %d\n", (unsigned int)tcph->fin);
            printf("   |-Window            : %d\n", ntohs(tcph->window));
            printf("   |-Checksum          : %d\n", ntohs(tcph->check));
            printf("   |-Urgent Pointer    : %d\n", tcph->urg_ptr);
        } else if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = (struct udphdr *)(buffer + iph->ihl * 4 + sizeof(struct ethhdr));
            printf("UDP Header:\n");
            printf("   |-Source Port       : %d\n", ntohs(udph->source));
            printf("   |-Destination Port  : %d\n", ntohs(udph->dest));
            printf("   |-UDP Length        : %d\n", ntohs(udph->len));
            printf("   |-UDP Checksum      : %d\n", ntohs(udph->check));
        } else if (iph->protocol == IPPROTO_ICMP) {
            struct icmphdr *icmph = (struct icmphdr *)(buffer + iph->ihl * 4 + sizeof(struct ethhdr));
            printf("ICMP Header:\n");
            printf("   |-Type              : %d\n", (unsigned int)(icmph->type));
            printf("   |-Code              : %d\n", (unsigned int)(icmph->code));
            printf("   |-Checksum          : %d\n", ntohs(icmph->checksum));
            printf("   |-ID                : %d\n", ntohs(icmph->un.echo.id));
            printf("   |-Sequence          : %d\n", ntohs(icmph->un.echo.sequence));
        }
            
    }
    
        
        const char *protocol_name;
        switch (ntohs(eth->h_proto)) {
            case ETH_P_IP:
            protocol_name = "IP";
            break;
            case ETH_P_ARP:
            protocol_name = "ARP";
            break;
            case ETH_P_IPV6:
            protocol_name = "IPv6";
            break;
            default:
            protocol_name = "Unknown";
            break;
        }

        const char *iface_type;
        if (strcmp(iface, ethsec) == 0) {
            iface_type = "sec";
        } else if (strcmp(iface, ethinsec) == 0) {
            iface_type = "ins";
        } else {
            iface_type = "unknown";
        }

        printf("Interface: %s (%s), %s SMAC: %02x:%02x:%02x:%02x:%02x:%02x, DMAC: %02x:%02x:%02x:%02x:%02x:%02x, Protocol: %s\n",
               iface, iface_type, is_outgoing ? "Outgoing" : "Incoming",
               eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5],
               eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5],
               protocol_name);
}