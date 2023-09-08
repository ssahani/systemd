#pragma once

#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

void dump_ip(struct iphdr *header);
void dump_udp(const struct udphdr *udp, const struct iphdr *ip, const char *payload, size_t payload_size);
void dump_tcp(const struct tcphdr *tcp, const struct iphdr *ip, const char *payload, size_t payload_size, const char *options, size_t options_size);

void dump_ip6(struct ip6_hdr *header);
void dump_udp6(const struct udphdr *udp, const struct ip6_hdr *ip6, const char *payload, size_t payload_size);
void dump_tcp6(const struct tcphdr *tcp, const struct ip6_hdr *ip6, const char *payload, size_t payload_size, const char *options, size_t options_size);

void dump_udp_generic(const struct udphdr *udp, uint32_t temp_checksum, const char *payload, size_t payload_size);
void dump_tcp_generic(const struct tcphdr *tcp, const char *options, size_t options_size, uint32_t temp_checksum, const char *payload, size_t payload_size);
