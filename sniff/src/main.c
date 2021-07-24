#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

int main()
{
    int saddr_size , data_size;
    struct sockaddr saddr;

    unsigned char *buffer = (unsigned char *) malloc(65536); //Its Big!

    printf("Starting...\n");

    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    
    if (sock_raw == -1) {
        fprintf(stderr,"Socket creation failed\n");
        return EXIT_FAILURE;
    }
    while(1)
    {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        /*struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        unsigned short iphdrlen =iph->ihl*4;

        printf("Packet recieved from %s. Original target %s",iph->saddr, iph->daddr);*/
        relay_icmp_packet(sock_raw, buffer, data_size);
    }
    close(sock_raw);
    printf("Finished");
    return 0;
}
