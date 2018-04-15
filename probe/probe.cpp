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
const char kGetLocalIp[] = "ifconfig | grep 'inet'| grep -v '127.0.0.1' | cut -d: -f2 | awk '{ print $1 }'";
const char kGetLocalMac[] = "ifconfig | grep 'HWaddr' | awk '{ print $5 }'";
}

ProbeProcessor::ProbeProcessor() {
  download_ = 0;
  upload_ = 0;
  port_data_.clear();
  SetLocalMac();
  SetLocalIp();
};

ProbeProcessor::~ProbeProcessor() {
};

bool ProbeProcessor::IsDownload(struct ethhdr *eth) {
  char dest[18];
  sprintf(dest, "%02x:%02x:%02x:%02x:%02x:%02x",
      eth->h_dest[0], eth->h_dest[1],
      eth->h_dest[2], eth->h_dest[3],
      eth->h_dest[4], eth->h_dest[5]);
  if (strcasecmp(GetLocalMac().c_str(), dest)) {
    return 1;
  }
  return 0;
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
