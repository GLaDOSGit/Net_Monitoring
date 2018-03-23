/*******************************************
 * Author(s): Gu Kai <540867841@qq.com>
 *
 * This file is for probe info client.
*******************************************/

#include "probe.h"

#include <sstream>

#include <fstream>
#include <iostream>
#include <unistd.h>

using namespace std;

ProbeProcessor::ProbeProcessor() {
};

ProbeProcessor::~ProbeProcessor() {
};

void ProbeProcessor::ProbeNetworkAdapter() {
  fstream infile("/proc/net/dev");

  if (!infile) {
    cout << "error" << endl;
  }

  while (1) {
    infile.clear();
    infile.seekp(0, std::ios::beg);
    string str;
    IOData data;
    string adapter;
    int num = -1;
    while (infile >> str) {
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

int main () {
  ProbeProcessor* x = new ProbeProcessor();
  x->ProbeNetworkAdapter();
}
