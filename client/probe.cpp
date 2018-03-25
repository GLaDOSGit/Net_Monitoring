/*******************************************
 * Author(s): Gu Kai <540867841@qq.com>
 *
 * This file_ptr is for probe info client.
*******************************************/

#include "probe.h"

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sstream>
#include <fstream>
#include <iostream>

using namespace std;

namespace {
const char kDevPath[] = "/proc/net/dev";
const char kGetLocalIp[] = "ifconfig | grep 'inet'| grep -v '127.0.0.1' | cut -d: -f2 | awk '{ print $1 }'";
const char kGetPort[] = "netstat -napl";
}

ProbeProcessor::ProbeProcessor() {
};

ProbeProcessor::~ProbeProcessor() {
};

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

void ProbeProcessor::GetLocalIp() {
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

int main () {
  //ProbeProcessor* x = new ProbeProcessor();
  //x->GetLocalIp();
  //x->PortMonitoring();
}
