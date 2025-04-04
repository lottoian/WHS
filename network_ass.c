#include <stdio.h>
#include <pcap.h>
#include "../../Sniffing_Spoofing/C_spoof/myheader.h"

void capture_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
        struct ethheader *eth = (struct ethheader *)packet;
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        int ip_header_len = ip->iph_ihl * 4;

        if (ip->iph_protocol != IPPROTO_TCP) return;


        const struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
        int tcp_header_len = TH_OFF(tcp) * 4;

        int total_headers_size = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
        const u_char *payload = packet + total_headers_size;
        int payload_len = header->caplen - total_headers_size;

        printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);

        printf("Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

        printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("Dest IP: %s\n", inet_ntoa(ip->iph_destip));
        printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
        printf("Dest Port: %d\n", ntohs(tcp->tcp_dport));
        if (payload_len > 0){
                for(int i = 0; i < payload_len; i++){
                        if( isprint(payload[i]))
                                printf("%c", payload[i]);
                        else
                                printf(".");
                }
                printf("\n");
        }
        else{
                printf("None\n");
        }
        printf("\n\n");
}

int main(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    if(handle == NULL){
         fprintf(stderr, "Failed to open device: %s\n", errbuf);
         return 1;
    }

    pcap_loop(handle, 0, capture_packet, NULL);

    pcap_close(handle);

    return 0;
}
