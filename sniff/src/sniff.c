#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>

#include <netinet/ip_icmp.h>     //Provides declarations for icmp header
#include <netinet/udp.h>         //Provides declarations for udp header
#include <netinet/tcp.h>         //Provides declarations for tcp header
#include <netinet/ip.h>          //Provides declarations for ip header
#include <netinet/if_ether.h>    //For ETH_P_ALL
#include <net/ethernet.h>        //For ether_header
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/if_packet.h>

struct sockaddr_in source,dest;

static unsigned short compute_checksum(unsigned short *addr, unsigned int count);
/* set ip checksum of a given ip header*/
void compute_ip_checksum(struct iphdr* iphdrp)
{
    iphdrp->check = 0;
    iphdrp->check = compute_checksum((unsigned short*)iphdrp, iphdrp->ihl<<2);
}

/* Compute checksum for count bytes starting at addr,
 * using one's complement of one's complement sum. */
static unsigned short compute_checksum(unsigned short *addr,
                                       unsigned int count)
{
    register unsigned long sum = 0;
    while (count > 1) {
        sum += * addr++;
        count -= 2;
    }

    //if any bytes left, pad the bytes and add
    if(count > 0) {
        sum += ((*addr)&htons(0xFF00));
    }

    //Fold sum to 16 bits: add carrier to result
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    //one's complement
    sum = ~sum;
    return ((unsigned short)sum);
}

static uint16_t icmp_checksum(uint16_t *icmph, int len)
{
    uint16_t ret = 0;
    uint32_t sum = 0;
    uint16_t odd_byte;

    while (len > 1) {
        sum += *icmph++;
        len -= 2;
    }

    if (len == 1) {
        *(uint8_t*)(&odd_byte) = * (uint8_t*)icmph;
        sum += odd_byte;
    }

    sum =  (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    ret =  ~sum;

    return ret;
}

void relay_icmp_packet(int sockid, unsigned char* buffer, int size)
{
    struct ethhdr *eth = (struct ethhdr *)buffer;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen =iph->ihl*4;

    if (iph->protocol != 1) return;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;;

    if (iph->saddr == inet_addr("10.9.0.5") && iph->daddr== inet_addr("10.9.0.6")){
        eth->h_dest[0] = 0X02;
        eth->h_dest[1] = 0X42;
        eth->h_dest[2] = 0X0A;
        eth->h_dest[3] = 0X09;
        eth->h_dest[4] = 0X00;
        eth->h_dest[5] = 0X06;

        eth->h_source[0] = 0X02;
        eth->h_source[1] = 0X42;
        eth->h_source[2] = 0X0A;
        eth->h_source[3] = 0X09;
        eth->h_source[4] = 0X69;
        eth->h_source[5] = 0X00;

    }else if(iph->saddr == inet_addr("10.9.0.6") && iph->daddr== inet_addr("10.9.0.5")){
        eth->h_dest[0] = 0X02;
        eth->h_dest[1] = 0X42;
        eth->h_dest[2] = 0X0A;
        eth->h_dest[3] = 0X09;
        eth->h_dest[4] = 0X00;
        eth->h_dest[5] = 0X05;

        eth->h_source[0] = 0X02;
        eth->h_source[1] = 0X42;
        eth->h_source[2] = 0X0A;
        eth->h_source[3] = 0X09;
        eth->h_source[4] = 0X69;
        eth->h_source[5] = 0X00;
    }
    struct icmphdr *icmph = (struct icmphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    compute_ip_checksum(iph);
    icmph->checksum = 0;
    icmph->checksum = icmp_checksum((uint16_t *)icmph, size - iphdrlen);

    struct sockaddr_ll device;
    memset(&device, 0, sizeof device);
    device.sll_ifindex = if_nametoindex();
    if (device.sll_ifindex = if_nametoindex("eth0")) {
        //fprintf(stdout, "Got index '%d' from interface eth0\n",device.sll_ifindex);
    }
    int ret = -1;
    ret = sendto(sockid, eth, size, 0, (const struct sockaddr *)&device, sizeof(device));

    if (ret)
        printf("Echo request sent from %.2X:%.2X:%.2X:%.2X:%.2X:%.2X to %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
               eth->h_source[0], eth->h_source[1], eth->h_source[2],
               eth->h_source[3], eth->h_source[4], eth->h_source[5],
               eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
               eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
}

