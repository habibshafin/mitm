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
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;


void process_packet(FILE* logfile, unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) {
    case 1:  //ICMP Protocol
        ++icmp;
        print_icmp_packet(logfile, buffer , size);
        break;

    case 2:  //IGMP Protocol
        ++igmp;
        break;

    case 6:  //TCP Protocol
        ++tcp;
        // print_tcp_packet(logfile, buffer, size);
        // relay_tcp_packet(buffer, size);
        break;

    case 17: //UDP Protocol
        ++udp;
        // print_udp_packet(logfile, buffer , size);
        break;

    default: //Some Other Protocol like ARP etc.
        ++others;
        break;
    }
    // printf("TCP : %d  UDP: %d  ICMP: %d  IGMP: %d  Others: %d  Total: %d\r",
    //        tcp, udp, icmp, igmp, others, total);
}

void print_ethernet_header(FILE* logfile, unsigned char* Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;

    fprintf(logfile, "\n");
    fprintf(logfile, "Ethernet Header\n");
    fprintf(logfile,
            "   |-Destination Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n",
            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
            eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    fprintf(logfile,
            "   |-Source Address      : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n",
            eth->h_source[0], eth->h_source[1], eth->h_source[2],
            eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    fprintf(logfile, "   |-Protocol            : %u\n",
            (unsigned short)eth->h_proto);
}

void print_ip_header(FILE* logfile, unsigned char* Buffer, int Size)
{
    print_ethernet_header(logfile, Buffer, Size);

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
    iphdrlen =iph->ihl*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    fprintf(logfile, "\n");
    fprintf(logfile, "IP Header\n");
    fprintf(logfile, "   |-IP Version        : %d\n",
            (unsigned int)iph->version);
    fprintf(logfile, "   |-IP Header Length  : %d DWORDS or %d Bytes\n",
            (unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile, "   |-Type Of Service   : %d\n", (unsigned int)iph->tos);
    fprintf(logfile, "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",
            ntohs( iph->tot_len));
    fprintf(logfile, "   |-Identification    : %d\n", ntohs(iph->id));
    // fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",
    //         (unsigned int)iphdr->ip_reserved_zero);
    // fprintf(logfile , "   |-Dont Fragment Field   : %d\n",
    //         (unsigned int)iphdr->ip_dont_fragment);
    // fprintf(logfile , "   |-More Fragment Field   : %d\n",
    //         (unsigned int)iphdr->ip_more_fragment);
    fprintf(logfile, "   |-TTL              : %d\n", (unsigned int)iph->ttl);
    fprintf(logfile, "   |-Protocol         : %d\n", (unsigned int)iph->protocol);
    fprintf(logfile, "   |-Checksum         : %d\n", ntohs(iph->check));
    fprintf(logfile, "   |-Source IP        : %s\n", inet_ntoa(source.sin_addr));
    fprintf(logfile, "   |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr));
}

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

void print_tcp_packet(FILE* logfile, unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)( Buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;

    struct tcphdr *tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    fprintf(logfile, "\n\n***************TCP Packet***************\n");

    print_ip_header(logfile, Buffer,Size);

    fprintf(logfile, "\n");
    fprintf(logfile, "TCP Header\n");
    fprintf(logfile, "   |-Source Port      : %u\n", ntohs(tcph->source));
    fprintf(logfile, "   |-Destination Port : %u\n", ntohs(tcph->dest));
    fprintf(logfile, "   |-Sequence Number    : %u\n", ntohl(tcph->seq));
    fprintf(logfile, "   |-Acknowledge Number : %u\n", ntohl(tcph->ack_seq));
    fprintf(logfile, "   |-Header Length      : %d DWORDS or %d BYTES\n",
            (unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(logfile , "   |-CWR Flag : %d\n", (unsigned int)tcph->cwr);
    //fprintf(logfile , "   |-ECN Flag : %d\n", (unsigned int)tcph->ece);
    fprintf(logfile, "   |-Urgent Flag          : %d\n",
            (unsigned int)tcph->urg);
    fprintf(logfile, "   |-Acknowledgement Flag : %d\n",
            (unsigned int)tcph->ack);
    fprintf(logfile, "   |-Push Flag            : %d\n",
            (unsigned int)tcph->psh);
    fprintf(logfile, "   |-Reset Flag           : %d\n",
            (unsigned int)tcph->rst);
    fprintf(logfile, "   |-Synchronise Flag     : %d\n",
            (unsigned int)tcph->syn);
    fprintf(logfile, "   |-Finish Flag          : %d\n",
            (unsigned int)tcph->fin);
    fprintf(logfile, "   |-Window         : %d\n", ntohs(tcph->window));
    fprintf(logfile, "   |-Checksum       : %d\n", ntohs(tcph->check));
    fprintf(logfile, "   |-Urgent Pointer : %d\n", tcph->urg_ptr);
    fprintf(logfile, "\n");
    fprintf(logfile, "                       DATA Dump                       ");
    fprintf(logfile, "\n");

    fprintf(logfile, "IP Header\n");
    print_data(logfile, Buffer,iphdrlen);

    fprintf(logfile, "TCP Header\n");
    print_data(logfile, Buffer+iphdrlen,tcph->doff*4);

    fprintf(logfile, "Data Payload\n");
    print_data(logfile, Buffer + header_size, Size - header_size );

    fprintf(logfile, "\n################################################");
}

void print_udp_packet(FILE* logfile, unsigned char *Buffer, int Size)
{

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;

    struct udphdr *udph =
        (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    fprintf(logfile, "\n\n***************UDP Packet***************\n");

    print_ip_header(logfile, Buffer,Size);

    fprintf(logfile, "\nUDP Header\n");
    fprintf(logfile, "   |-Source Port      : %d\n", ntohs(udph->source));
    fprintf(logfile, "   |-Destination Port : %d\n", ntohs(udph->dest));
    fprintf(logfile, "   |-UDP Length       : %d\n", ntohs(udph->len));
    fprintf(logfile, "   |-UDP Checksum     : %d\n", ntohs(udph->check));

    fprintf(logfile, "\n");
    fprintf(logfile, "IP Header\n");
    print_data(logfile, Buffer, iphdrlen);

    fprintf(logfile, "UDP Header\n");
    print_data(logfile, Buffer+iphdrlen, sizeof udph);

    fprintf(logfile, "Data Payload\n");

    //Move the pointer ahead and reduce the size of string
    print_data(logfile, Buffer + header_size, Size - header_size);

    fprintf(logfile, "\n################################################");
}

void relay_icmp_packet(int sockid, unsigned char* buffer, int size)
{
    // 02:42:0a:09:00:06

    // sockid = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    struct ethhdr *eth = (struct ethhdr *)buffer;
    eth->h_dest[0] = 0X02;
    eth->h_dest[1] = 0X42;
    eth->h_dest[2] = 0X0A;
    eth->h_dest[3] = 0X09;
    eth->h_dest[4] = 0X00;
    eth->h_dest[5] = 0X06;

    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen =iph->ihl*4;

    if (iph->protocol != 1) return;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    // printf("%s\n", inet_ntoa(source.sin_addr));

    if (!(iph->saddr == inet_addr("10.9.0.5")
        && iph->daddr== inet_addr("10.9.0.6")))
        return;

    struct icmphdr *icmph = (struct icmphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    compute_ip_checksum(iph);
    icmph->checksum = 0;
    icmph->checksum = icmp_checksum((uint16_t *)icmph, size - iphdrlen);

    struct sockaddr_ll device;
    memset(&device, 0, sizeof device);
    device.sll_ifindex = if_nametoindex("eth0");

    int ret = -5;
    // ret = send(sockid, eth, size, 0);
    ret = sendto(sockid, eth, size, 0, (const struct sockaddr *)&device, sizeof(device));

    // int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
    // print_data(stdout, buffer + header_size, size - header_size );

    if (ret)
        printf("Echo request sent from %.2X:%.2X:%.2X:%.2X:%.2X:%.2X to %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
               eth->h_source[0], eth->h_source[1], eth->h_source[2],
               eth->h_source[3], eth->h_source[4], eth->h_source[5],
               eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
               eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    // close(sockid);
}

void print_icmp_packet(FILE* logfile, unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

    fprintf(logfile, "\n\n**************ICMP Packet***************\n");

    print_ip_header(logfile, Buffer, Size);

    fprintf(logfile, "\n");

    fprintf(logfile, "ICMP Header\n");
    fprintf(logfile, "   |-Type : %d",(unsigned int)(icmph->type));

    if((unsigned int)(icmph->type) == 11)
    {
        fprintf(logfile, "  (TTL Expired)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        fprintf(logfile, "  (ICMP Echo Reply)\n");
    }

    fprintf(logfile, "   |-Code : %d\n", (unsigned int)(icmph->code));
    fprintf(logfile, "   |-Checksum : %d\n", ntohs(icmph->checksum));
    //fprintf(logfile , "   |-ID       : %d\n", ntohs(icmph->id));
    //fprintf(logfile , "   |-Sequence : %d\n", ntohs(icmph->sequence));
    fprintf(logfile, "\n");

    fprintf(logfile, "IP Header\n");
    print_data(logfile, Buffer, iphdrlen);

    fprintf(logfile, "UDP Header\n");
    print_data(logfile, Buffer + iphdrlen, sizeof icmph);

    fprintf(logfile, "Data Payload\n");

    //Move the pointer ahead and reduce the size of string
    print_data(logfile, Buffer + header_size, (Size - header_size));

    fprintf(logfile, "\n################################################");
}

void print_data (FILE* logfile, unsigned char* data, int Size)
{
    int i, j;
    for(i=0; i < Size; i++) {
       //if one line of hex printing is complete...
        if( i!=0 && i%16==0) {
            fprintf(logfile, "         ");
            for(j=i-16; j<i; j++) {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile, "%c", (unsigned char)data[j]);

                else fprintf(logfile, ".");
            }
            fprintf(logfile, "\n");
        }

        if(i%16==0) fprintf(logfile, "   ");
        fprintf(logfile, " %02X",(unsigned int)data[i]);

        //print the last spaces
        if( i==Size-1) {
            for(j=0; j<15-i%16; j++) {
                fprintf(logfile, "   "); //extra spaces
            }

            fprintf(logfile, "         ");

            for(j=i-i%16; j<=i; j++) {
                if(data[j]>=32 && data[j]<=128) {
                    fprintf(logfile, "%c",(unsigned char)data[j]);
                } else {
                    fprintf(logfile, ".");
                }
            }
            fprintf(logfile,  "\n" );
        }
    }
}
