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

ProbeProcessor::ProbeProcessor() {
  DataClear();
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

void ProbeProcessor::SetLocalIp(char* ip) {
	local_ip_ = ip;
	cout << local_ip_<<endl;
  return;
}

void ProbeProcessor::SetLocalMac(char* mac) {
	local_mac_ = mac;
	cout << local_mac_<<endl;
}
