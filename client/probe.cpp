/*******************************************
 * Author(s): Gu Kai <540867841@qq.com>
 *
 * This file_ptr is for probe info client.
*******************************************/

#include "probe.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <sstream>

using namespace std;

namespace {
const char kDevPath[] = "/proc/net/dev";
const char kGetLocalIp[] = "ifconfig | grep 'inet'| grep -v '127.0.0.1' | cut -d: -f2 | awk '{ print $1 }'";
const char kGetLocalMac[] = "ifconfig | grep 'HWaddr' | awk '{ print $5 }'";
const char kGetPort[] = "netstat -napl";
}

ProbeProcessor* x = new ProbeProcessor();

ProbeProcessor::ProbeProcessor() {
  download_ = 0;
  upload_ = 0;
  port_data_.clear();
  SetLocalMac();

  char error_buf[PCAP_ERRBUF_SIZE];
  char *DEVICE=pcap_lookupdev(error_buf);
  bpf_u_int32 netp, maskp;

  if(pcap_lookupnet(DEVICE, &netp, &maskp, error_buf)) {
      printf("get net failure\n");
      exit(1);
  }

  dev_ = pcap_open_live(DEVICE, 65536, 1, 0, error_buf);
  if(NULL == dev_) {
      printf("open %s failure\n", DEVICE);
      exit(1);
  }
};

ProbeProcessor::~ProbeProcessor() {
  pcap_close(dev_);
};

bool IsDownload(struct ethhdr *eth)
{
  char dest[18];
  sprintf(dest, "%02x:%02x:%02x:%02x:%02x:%02x",
      eth->h_dest[0], eth->h_dest[1],
      eth->h_dest[2], eth->h_dest[3],
      eth->h_dest[4], eth->h_dest[5]);
  
  //cout << dest <<endl;
  //cout << x->GetLocalMac().c_str() << endl;
  //cout << strcasecmp(x->GetLocalMac().c_str(), dest) << endl;
  if (strcasecmp(x->GetLocalMac().c_str(), dest)) {
    return true;
  }
  return false;
  //char source[18];
  //sprintf(source, "%02x:%02x:%02x:%02x:%02x:%02x",
      //eth->h_source[0], eth->h_source[1],
      //eth->h_source[2], eth->h_source[3],
      //eth->h_source[4], eth->h_source[5]);
}

void GetPacket(
    u_char *user,
    const struct pcap_pkthdr *pkthdr,
    const u_char *packet) {
  //int len = pkthdr->caplen;
  //char* time = ctime((const time_t *)&pkthdr->ts.tv_sec);

  struct ethhdr *eth = (struct ethhdr *)packet;
  uint16_t e_type = ntohs(eth->h_proto);
  uint32_t offset = sizeof(struct ethhdr);
  bool is_download = false;
  if (IsDownload(eth)) {
    x->SetDownload(pkthdr->caplen);
    is_download = true;
  } else {
    x->SetUpload(pkthdr->caplen);
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
        x->SetPortData(dest_port, pkthdr->caplen);
      } else {
        x->SetPortData(source_port, pkthdr->caplen);
      }
    } else if (ip->protocol == IPPROTO_TCP) {
      struct tcphdr *tcp = (struct tcphdr *)(packet + offset);
      int source_port = ntohs(tcp->source);
      int dest_port = ntohs(tcp->dest);

      if (is_download) {
        x->SetPortData(dest_port, pkthdr->caplen);
      } else {
        x->SetPortData(source_port, pkthdr->caplen);
      }
    }
  }
  x->PrintfPortData();
}

void ProbeProcessor::CapturePacket() {
  pcap_loop(dev_, 0, GetPacket, NULL);
}

void ProbeProcessor::ProbeNetworkAdapter() {
  fstream dev_file(kDevPath);
  if (!dev_file) {
    cout << "error" << endl;
  }

  while (1) {
    dev_file.clear();
    dev_file.seekp(0, std::ios::beg);
    string str;
    IOData data;
    string adapter;
    int num = -1;
    while (dev_file >> str) {
      int data_size = str.size();
      if (str[data_size - 1] == ':') {
        adapter = str.substr(0, data_size - 1);
        num = 0;
      } else if (num != -1) {
        std::stringstream data_int;
        data_int << str;
        if (num < 8) {
          data_int >> data.receive[num];
        } else {
          data_int >> data.transmit[num%8];
        }
        num++;
      }
      if (num == 16) {
        adapter_data_[adapter] = data;
      }
    }
    //for (auto iter = adapter_data_.begin(); iter != adapter_data_.end(); iter++) {
      //cout << iter->first <<endl;
      //for (int i = 0; i < 8; i++) {
        //cout << iter->second.receive[i] << "  ";
      //}
      //cout << endl;
      //for (int i = 0; i < 8; i++) {
        //cout << iter->second.transmit[i] << "  ";
      //}
      //cout << endl;
    //}
    sleep (1);
  }
}

void ProbeProcessor::PortMonitoring() {
  FILE *port_file_ptr=NULL;
  if((port_file_ptr = popen(kGetPort, "r")) == NULL) {
    cout << "error" << endl;
  }

  char buff [1024];
  while(fgets(buff, sizeof(buff), port_file_ptr) != NULL) {
    if (buff[strlen(buff) - 1] == '\n') {
      buff[strlen(buff) - 1] = '\0';                    
    }
    string str = buff; 
    int pos = str.find(local_ip_);
    if (pos != -1) {
      int start_pos = pos + local_ip_.size() + 1;
      int end_pos = start_pos;
      while (str[end_pos] <= '9' && str[end_pos] >= '0') {
        end_pos++;
      }
      //cout << str << endl;
      //cout << str.substr(start_pos, end_pos - start_pos) << endl;
      open_port_.insert(str.substr(start_pos, end_pos - start_pos));
    }
  }
  //for (auto iter = open_port_.begin(); iter != open_port_.end(); iter++) {
    //cout << *iter << endl;
  //}
  pclose(port_file_ptr);
  
}

void ProbeProcessor::SetLocalIp() {
  FILE *ip_file_ptr=NULL;
  if((ip_file_ptr = popen(kGetLocalIp, "r")) == NULL) {
    cout << "error" << endl;
  }

  char buff [1024];
  if (fgets(buff, sizeof(buff), ip_file_ptr) != NULL) {
    if (buff[strlen(buff) - 1] == '\n') {
      buff[strlen(buff) - 1] = '\0';
    }
    local_ip_ = buff;
  } else {
    cout << "error" << endl;
  }
  //cout << local_ip_ << endl;
  pclose(ip_file_ptr);
}

void ProbeProcessor::SetLocalMac() {
  FILE *ip_file_ptr=NULL;
  if((ip_file_ptr = popen(kGetLocalMac, "r")) == NULL) {
    cout << "error" << endl;
  }

  char buff [1024];
  if (fgets(buff, sizeof(buff), ip_file_ptr) != NULL) {
    if (buff[strlen(buff) - 1] == '\n') {
      buff[strlen(buff) - 1] = '\0';
    }
    local_mac_ = buff;
  } else {
    cout << "error" << endl;
  }
  cout << local_mac_ << endl;
  pclose(ip_file_ptr);
}

int main () {
  x->CapturePacket();
  //x->PortMonitoring();
}
