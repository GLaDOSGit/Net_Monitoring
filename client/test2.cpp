#include <stdio.h>  
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>  
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <iostream>

#define URL_MAX_LEN        2048
#define MAX_HOST_LEN       1024
#define MAX_GET_LEN        2048

#define get_u_int8_t(X,O)  (*(uint8_t *)(((uint8_t *)X) + O))
#define get_u_int16_t(X,O)  (*(uint16_t *)(((uint8_t *)X) + O))
#define get_u_int32_t(X,O)  (*(uint32_t *)(((uint8_t *)X) + O))
#define get_u_int64_t(X,O)  (*(uint64_t *)(((uint8_t *)X) + O))

using namespace std;

/*Display Ethernet Header*/
void show_ethhdr(struct ethhdr *eth)
{
    printf("----------------eth---------------------\n");
    printf("destination eth addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->h_dest[0], eth->h_dest[1],
        eth->h_dest[2], eth->h_dest[3],
        eth->h_dest[4], eth->h_dest[5]);
    printf("source eth addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->h_source[0], eth->h_source[1],
        eth->h_source[2], eth->h_source[3],
        eth->h_source[4], eth->h_source[5]);
    printf("protocol is: %04x\n", ntohs(eth->h_proto));
}

/*Display IP Header*/
void show_iphdr(struct iphdr *ip)
{
    struct in_addr addr;

    printf("----------------ip----------------------\n");
    printf("version: %d\n", ip->version);
    printf("head len: %d\n", ip->ihl * 4);
    printf("total len: %d\n", ntohs(ip->tot_len));
    printf("ttl: %d\n", ip->ttl);
    printf("protocol: %d\n", ip->protocol);
    printf("check: %x\n", ip->check);
    addr.s_addr = ip->saddr;
    printf("saddr: %s\n", inet_ntoa(addr));
    addr.s_addr = ip->daddr;
    printf("daddr: %s\n", inet_ntoa(addr));
}

/*Display TCP Header*/
void show_tcphdr(struct tcphdr *tcp)
{
    printf("----------------tcp---------------------\n");
    cout << sizeof(struct tcphdr) << endl;
    printf("tcp->doff: %d\n", tcp->doff * 4);
    printf("source port: %d\n", ntohs(tcp->source));
    printf("dest port: %d\n", ntohs(tcp->dest));
    printf("sequence number: %d\n", ntohs(tcp->seq));
    printf("ack sequence: %d\n", ntohs(tcp->ack_seq));
}

/*Display TCP Header*/
void show_udphdr(struct udphdr *udp)
{
    printf("----------------udp---------------------\n");
    printf("source port: %d\n", ntohs(udp->source));
    printf("dest port: %d\n", ntohs(udp->dest));
}

int parse_http_head(const u_char *payload, int payload_len, char *url)
{
    int line_len, offset;
    int hstrlen; //"host: " 
    int hostlen;
    int getlen; 
    char host[MAX_HOST_LEN];
    char get[MAX_GET_LEN]; 
    int a, b;
    
    /*filter get packet*/
    if(memcmp(payload, "GET ", 4)) {
        return 0;
    }

    for(a = 0, b = 0; a < payload_len - 1; a++) {
        if (get_u_int16_t(payload, a) == ntohs(0x0d0a)) {
            line_len = (u_int16_t)(((unsigned long) &payload[a]) - ((unsigned long)&payload[b]));
    
            if (line_len >= (9 + 4)
                && memcmp(&payload[line_len - 9], " HTTP/1.", 8) == 0) {
                memcpy(get, payload + 4, line_len - 13); //"GET  HTTP/1.x" 13bit
                getlen = line_len - 13;
            }   
            /*get url host of pcaket*/
            if (line_len > 6 
                && memcmp(&payload[b], "Host:", 5) == 0) {
                if(*(payload + b + 5) == ' ') {
                    hstrlen = b + 6;
                } else {
                    hstrlen = b + 5;
                }
                hostlen = a - hstrlen;   
                memcpy(host, payload + hstrlen, (a - hstrlen));
            }   
            b = a + 2;
        }   
    }
    offset =  7;
    memcpy(url, "http://", offset);
    memcpy(url + offset, host, hostlen);
    offset += hostlen;
    memcpy(url + offset, get, getlen);

    return strlen(url);
}

void packet_http_handle(const u_char *tcp_payload, int payload_len)
{    
    int url_len;
    char url[URL_MAX_LEN];
    
    url_len = parse_http_head(tcp_payload, payload_len, url);
    if (url_len <= 7) {
        return;    
    }
    printf("----------------HTTP---------------------\n");
    printf("url_len: %d\n", url_len);
    printf("url: %s\n", url);
}

int prase_packet(const u_char *buf,  int caplen)
{
    uint16_t e_type;
    uint32_t offset;
    //int payload_len;
    //const u_char *tcp_payload;
    
    /* ether header */
    struct ethhdr *eth = NULL;
    // 将数据包塞入以太帧的结构体
    eth = (struct ethhdr *)buf;
    // 解析端口协议
    e_type = ntohs(eth->h_proto);
    // 偏移量
    offset = sizeof(struct ethhdr);
    //show_ethhdr(eth);

    /*vlan 802.1q*/    
    //while(e_type == ETH_P_8021Q) {
        //e_type = (buf[offset+2] << 8) + buf[offset+3];
        //offset += 4;
    //}  
    if (e_type != ETH_P_IP) {
        return -1;
    }   

    /* ip header */    
    struct iphdr *ip = (struct iphdr *)(buf + offset);
    e_type = ntohs(ip->protocol);
    offset += sizeof(struct iphdr);
    //show_iphdr(ip);
     
    if (ip->protocol == IPPROTO_UDP) {
      printf("--------udp\n");
      struct udphdr *udp = (struct udphdr *)(buf + offset);

      show_udphdr(udp);
      
    //} else if (ip->protocol == IPPROTO_TCP) {
      ////[>tcp header<]
      //struct tcphdr *tcp = (struct tcphdr *)(buf + offset);
      //offset += (tcp->doff << 2);
      //payload_len = caplen - offset;
      //tcp_payload = (buf + offset);
      //show_tcphdr(tcp);

      ////[>prase http header<]
      //packet_http_handle(tcp_payload, payload_len);
    } else {
      return -1;
    }

    return 0;
}

void get_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    static int count = 0;
    printf("\n----------------------------------------\n");
    printf("\t\tpacket %d\n", count);
    printf("----------------------------------------\n");
    printf("Packet length: %d\n", pkthdr->len);  
    printf("Number of bytes: %d\n", pkthdr->caplen);  
    printf("Recieved time: %s\n", ctime((const time_t *)&pkthdr->ts.tv_sec));

    prase_packet(packet, pkthdr->len);
    count++;
}

int main()  
{  
    char error_buf[PCAP_ERRBUF_SIZE]; /*error Buff*/
    pcap_t *dev; /*network interface*/
    char *DEVICE=pcap_lookupdev(error_buf);
    bpf_u_int32 netp, maskp;

    if(pcap_lookupnet(DEVICE, &netp, &maskp, error_buf)) {
        printf("get net failure\n");
        exit(1);
    }

    dev = pcap_open_live(DEVICE, 65536, 1, 0, error_buf);
    if(NULL == dev) {
        printf("open %s failure\n", DEVICE);
        exit(1);
    }
    
    pcap_loop(dev, 0, get_packet, NULL);
    
    pcap_close(dev);

    return 0; 
} 
