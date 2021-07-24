#ifndef _PACKETS_H_
# define _PACKETS_H_

# include <stdint.h>
# define ETH_HDR_LEN 14
# define ARP_PKT_LEN 28
# define MACADDR_LEN 6
# define IP_LENGTH 4

// Inspired by the <net/ethernet.h> header
typedef struct
{
    uint8_t target_mac[MACADDR_LEN];
    uint8_t sender_mac[MACADDR_LEN];
    uint16_t eth_type;
} eth_header;

typedef struct
{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t opcode;
    uint8_t sender_mac[MACADDR_LEN];
    uint8_t sender_ip[IP_LENGTH];
    uint8_t target_mac[MACADDR_LEN];
    uint8_t target_ip[IP_LENGTH];
} arp_packet;

eth_header* createArpPacket(const uint16_t opcode,
                              const uint8_t *sender_mac,
                              const char *sender_ip,
                              const uint8_t *reciever_mac,
                              const char *reciever_ip);
#endif /* _PACKETS_H_ */
