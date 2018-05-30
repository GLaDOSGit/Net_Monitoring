/*******************************************
 * Author(s): Gu Kai <540867841@qq.com>
 *
 * This file is for probe info client.
*******************************************/

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>

#include "http_post.h"
#include "probe.h"

using namespace std;

namespace {
const unsigned short kSocketPort = 60482;
const unsigned short kIptablePort = 60483;
const double kPostTimeMax = 10;
const int kQueue = 5;
}

// target[0]:ip target[1]:post_url target[2]:post_port
vector<string>* target = new vector<string>;
mutex target_mutex;

map<string, unsigned long long>* network_data = new map<string, unsigned long long>;
mutex network_data_mutex;
time_t last_time;

ProbeProcessor* probe_ptr = new ProbeProcessor();

void* iptable_server(void* args) {
  HttpPost* http_post = new HttpPost;
  while (1) {
    if (target->empty()) {
      continue;
    }
    sleep(kPostTimeMax);
    stringstream temp;
    int port;
    string temp_str;
    temp << (*target)[2];
    temp >> port;

    string data = "get iptables";

    string iptables = http_post->Post((*target)[0], (*target)[1], data, port);

  }
  return NULL;
}

void* http_post(void* args) {
  HttpPost* http_post = new HttpPost;
  while (1) {
    if (target->empty()) {
      continue;
    }
    sleep(kPostTimeMax + 1);
    stringstream temp;
    int port;
    string temp_str;
    temp << (*target)[2];
    temp >> port;

    string data = "";
    lock_guard<mutex> guard(network_data_mutex);
    for (auto iter = network_data->begin(); iter != network_data->end(); iter++) {
      data += iter->first + "="  + to_string(iter->second) + "&";
    }
    //cout << data <<endl;

    http_post->Post((*target)[0], (*target)[1], data, port);
  }
  return NULL;
}

void processing(char* buffer, const int& buffer_len) {
  vector<string>* temp_target = new vector<string>;
  string temp_value;
  for (int i = 0; i < buffer_len; ++i) {
    if (buffer[i] == '&') {
      cout << temp_value << endl;
      temp_target->push_back(temp_value);
      temp_value.clear();
      continue;
    }
    temp_value += buffer[i];
  }

  lock_guard<mutex> guard(target_mutex);
  delete target;
  target = temp_target;
  return;
}

void* socket_server(void* args) {
  int s_id = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in server_sockaddr;
  server_sockaddr.sin_family = AF_INET;
  server_sockaddr.sin_port = htons(kSocketPort);
  server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);

  if(bind(s_id, (struct sockaddr*) &server_sockaddr,
          sizeof(server_sockaddr)) == -1) {
    exit(1);
  }
  if(listen(s_id, kQueue) == -1) {
    exit(1);
  }

  struct sockaddr_in client_addr;
  socklen_t length = sizeof(client_addr);
  while(true) {
    int conn = accept(s_id, (struct sockaddr*)&client_addr, &length);
    if(conn < 0) {
      exit(1);
    }

    char buffer[1024];
    memset(buffer, 0 ,sizeof(buffer));
    int buffer_len = recv(conn, buffer, sizeof(buffer), 0);
    processing(buffer, buffer_len);
    close(conn);
  } 

  close(s_id);
  return NULL;
}

void GetPacket(u_char *user,
               const struct pcap_pkthdr *pkthdr,
               const u_char *packet) {
  struct ethhdr *eth = (struct ethhdr *)packet;
  uint16_t e_type = ntohs(eth->h_proto);
  uint32_t offset = sizeof(struct ethhdr);
  bool is_download = false;
  
  if (probe_ptr->IsDownload(eth)) {
    probe_ptr->SetDownload(pkthdr->len);
    is_download = true;
  } else if (probe_ptr->IsDownload(eth) == 0) {
    probe_ptr->SetUpload(pkthdr->len);
  }

  if (e_type == ETH_P_IP) {
    struct iphdr *ip = (struct iphdr *)(packet + offset);
    e_type = ntohs(ip->protocol);
    offset += sizeof(struct iphdr);

    if (ip->protocol == IPPROTO_UDP) {
      struct udphdr *udp = (struct udphdr *)(packet + offset);
      int source_port = ntohs(udp->source);
      int dest_port = ntohs(udp->dest);

      if (is_download) {
        probe_ptr->SetPortData(dest_port, pkthdr->len);
      } else {
        probe_ptr->SetPortData(source_port, pkthdr->len);
      }

    } else if (ip->protocol == IPPROTO_TCP) {
      struct tcphdr *tcp = (struct tcphdr *)(packet + offset);
      int source_port = ntohs(tcp->source);
      int dest_port = ntohs(tcp->dest);

      if (is_download) {
        probe_ptr->SetPortData(dest_port, pkthdr->len);
      } else {
        probe_ptr->SetPortData(source_port, pkthdr->len);
      }

    }
  }

  time_t now_time;  
  time(&now_time); 
  if (difftime(now_time, last_time) > kPostTimeMax) {
    last_time = now_time;
    probe_ptr->PrintfPortData();
    //printf("----------------\n");
    lock_guard<mutex> guard(network_data_mutex);
    probe_ptr->GetNetworkData(network_data);
    probe_ptr->DataClear(); 
  }
}

void start_socket_server() {
  pthread_t socket_server_tid;
  int ret = pthread_create(&socket_server_tid, NULL, socket_server, NULL);
  if(ret != 0) {
    cout << "socket_server_create error:error_code=" << ret << endl;
  }
  return;
}

void start_http_server() {
  pthread_t http_post_tid;
  int ret = pthread_create(&http_post_tid, NULL, http_post, NULL);
  if(ret != 0) {
    cout << "http_post_create error:error_code=" << ret << endl;
  }
  return;
}

void start_iptable_server() {
  pthread_t iptable_server_tid;
  int ret = pthread_create(&iptable_server_tid, NULL, iptable_server, NULL);
  if(ret != 0) {
    cout << "iptable_server_create error:error_code=" << ret << endl;
  }
  return;
}

int main(int argc, char * argv[]) {
  start_socket_server(); 
  start_http_server(); 
  start_iptable_server(); 

  if (argc < 4) {
    printf("argc num ERROR!\n");
    return 1;
  }
  
  probe_ptr->SetLocalIp(argv[1]);
  probe_ptr->SetLocalMac(argv[2]);
	
  char error_buf[PCAP_ERRBUF_SIZE];
  // char *DEVICE=pcap_lookupdev(error_buf);
  char *DEVICE= argv[3];
  bpf_u_int32 netp, maskp;

  if(pcap_lookupnet(DEVICE, &netp, &maskp, error_buf)) {
      printf("get net failure\n");
      exit(1);
  }

  pcap_t* dev;
  dev = pcap_open_live(DEVICE, 65536, 1, 0, error_buf);
  if(NULL == dev) {
      printf("open %s failure\n", DEVICE);
      exit(1);
  }

  time(&last_time);
  pcap_loop(dev, 0, GetPacket, NULL);
  
  pcap_close(dev);
  pthread_exit(NULL);
}
