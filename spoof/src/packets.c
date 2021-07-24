#include "packets.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

eth_header* createArpPacket(const uint16_t opcode,
                              const uint8_t *sender_mac,
                              const char *spoof_ip,
                              const uint8_t *reciever_mac,
                              const char *reciever_ip)
{
    arp_packet  *arp_pkt;
    arp_pkt = malloc(sizeof(arp_packet));
    arp_pkt->hardware_type = htons(1);
    arp_pkt->protocol_type = htons(ETH_P_IP);
    arp_pkt->hardware_len = MACADDR_LEN;
    arp_pkt->protocol_len = IP_LENGTH;
    arp_pkt->opcode = htons(opcode);

    memcpy(&arp_pkt->sender_mac, sender_mac, sizeof(uint8_t) * MACADDR_LEN);
    memcpy(&arp_pkt->target_mac, reciever_mac,sizeof(uint8_t) * MACADDR_LEN);

    /* 1 on succesful convertion from text to binary*/
    if (inet_pton(AF_INET, spoof_ip, arp_pkt->sender_ip) != 1
        || inet_pton(AF_INET, reciever_ip, arp_pkt->target_ip) != 1)
        return (NULL);



    /** Now wrap the ARP packet in IP header */
    eth_header *eth_pkt;
    eth_pkt = malloc(sizeof(uint8_t) * IP_MAXPACKET);

    memcpy(&eth_pkt->target_mac, reciever_mac,
           sizeof(uint8_t) * MACADDR_LEN);
    memcpy(&eth_pkt->sender_mac, sender_mac,
           sizeof(uint8_t) * MACADDR_LEN);

    /* NOTE: Simply doing `memcpy(&eth_pkt->eth_type,htons(ETHERTYPE_ARP),size)`
     * doesn't work. The two char bytes need to be separately placed in
     * the upper and lower bytes. */
    memcpy(&eth_pkt->eth_type, (uint8_t[2]) {
           htons(ETHERTYPE_ARP) & 0xff,
           htons(ETHERTYPE_ARP) >> 8
           }, sizeof(uint8_t)*2);

    memcpy((uint8_t *)eth_pkt + ETH_HDR_LEN, arp_pkt,
           sizeof(uint8_t) * ARP_PKT_LEN);

    return eth_pkt;
}
