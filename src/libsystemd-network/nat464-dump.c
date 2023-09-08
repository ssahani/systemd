
#include <stdio.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>

#include "nat464-dump.h"
#include "nat464-checksum.h"

/* print ip header */
void dump_ip(struct iphdr *header) {
        u_int16_t frag_flags;
        char addrstr[INET6_ADDRSTRLEN];

        frag_flags = be16toh(header->frag_off);

        printf("IP packet\n");
        printf("header_len = %d\n",header->ihl);
        printf("version = %d\n",header->version);
        printf("tos = %x\n",header->tos);
        printf("tot_len = %x\n",be16toh(header->tot_len));
        printf("id = %x\n",be16toh(header->id));
        printf("frag: ");
        if(frag_flags & IP_RF) {
          printf("(RF) ");
        }
        if(frag_flags & IP_DF) {
          printf("DF ");
        }
        if(frag_flags & IP_MF) {
          printf("MF ");
        }
        printf("offset = %d\n",frag_flags & IP_OFFMASK);
        printf("ttl = %x\n",header->ttl);
        printf("protocol = %x\n",header->protocol);
        printf("checksum = %x\n",be16toh(header->check));
        inet_ntop(AF_INET, &header->saddr, addrstr, sizeof(addrstr));
        printf("saddr = %s\n",addrstr);
        inet_ntop(AF_INET, &header->daddr, addrstr, sizeof(addrstr));
        printf("daddr = %s\n",addrstr);
}

/* print ip6 header */
void dump_ip6(struct ip6_hdr *header) {
       char addrstr[INET6_ADDRSTRLEN];

       printf("ipv6\n");
       printf("version = %x\n",header->ip6_vfc >> 4);
       printf("traffic class = %x\n",header->ip6_flow >> 20);
       printf("flow label = %x\n",ntohl(header->ip6_flow & 0x000fffff));
       printf("payload len = %x\n",be16toh(header->ip6_plen));
       printf("next header = %x\n",header->ip6_nxt);
       printf("hop limit = %x\n",header->ip6_hlim);

       inet_ntop(AF_INET6, &header->ip6_src, addrstr, sizeof(addrstr));
       printf("source = %s\n",addrstr);

       inet_ntop(AF_INET6, &header->ip6_dst, addrstr, sizeof(addrstr));
       printf("dest = %s\n",addrstr);
}

/* print udp header */
void dump_udp_generic(const struct udphdr *udp, uint32_t temp_checksum, const char *payload, size_t payload_size) {
      printf("UDP\n");
      printf("source = %x\n",be16toh(udp->source));
      printf("dest = %x\n",be16toh(udp->dest));
      printf("len = %x\n",be16toh(udp->len));
}

/* print ipv4/udp header */
void dump_udp(const struct udphdr *udp, const struct iphdr *ip, const char *payload, size_t payload_size) {
        uint32_t temp_checksum = 0;
        dump_udp_generic(udp, temp_checksum, payload, payload_size);
}

/* print ipv6/udp header */
void dump_udp6(const struct udphdr *udp, const struct ip6_hdr *ip6, const char *payload, size_t payload_size) {
  uint32_t temp_checksum = 0;
  dump_udp_generic(udp, temp_checksum, payload, payload_size);
}

/* print tcp header */
void dump_tcp_generic(const struct tcphdr *tcp, const char *options, size_t options_size, uint32_t temp_checksum, const char *payload, size_t payload_size) {
      uint16_t my_checksum = 0;

      printf("TCP\n");
      printf("source = %x\n",be16toh(tcp->source));
      printf("dest = %x\n",be16toh(tcp->dest));
      printf("seq = %x\n",ntohl(tcp->seq));
      printf("ack = %x\n",ntohl(tcp->ack_seq));
      printf("d_off = %x\n",tcp->doff);
      printf("res1 = %x\n",tcp->res1);
      printf("urg = %x  ack = %x  psh = %x  rst = %x  syn = %x  fin = %x\n",
             tcp->urg, tcp->ack, tcp->psh, tcp->rst, tcp->syn, tcp->fin);
      printf("window = %x\n",be16toh(tcp->window));
      printf("check = %x [mine %x]\n",tcp->check,my_checksum);
      printf("urgent = %x\n",tcp->urg_ptr);

      if(options) {
        size_t i;

        printf("options: ");
        for(i=0; i<options_size; i++) {
          printf("%d ",*(options+i));
        }
        printf("\n");
      }
}

/* print ipv4/tcp header */
void dump_tcp(const struct tcphdr *tcp, const struct iphdr *ip, const char *payload, size_t payload_size, const char *options, size_t options_size) {
      uint32_t temp_checksum = 0;
      dump_tcp_generic(tcp, options, options_size, temp_checksum, payload, payload_size);
}

/* print ipv6/tcp header */
void dump_tcp6(const struct tcphdr *tcp, const struct ip6_hdr *ip6, const char *payload, size_t payload_size, const char *options, size_t options_size) {
      uint32_t temp_checksum = 0;

      dump_tcp_generic(tcp, options, options_size, temp_checksum, payload, payload_size);
}
