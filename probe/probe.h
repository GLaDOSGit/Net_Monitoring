/*******************************************
 * Author(s): Gu Kai <540867841@qq.com>
 *
 * This file is for probe info client.
*******************************************/

#ifndef NET_MONITORING_CLIENT_PROBE_H_
#define NET_MONITORING_CLIENT_PROBE_H_

#include <stdio.h>
#include <pcap.h>

#include <map>
#include <set>
#include <string>
#include <vector>

#include <iostream>

class ProbeProcessor {
 public:
  ProbeProcessor();
  ~ProbeProcessor();
 
  std::string GetLocalIp() {
    return local_ip_;
  };

  std::string GetLocalMac() {
    return local_mac_;
  };

  bool IsDownload(struct ethhdr *eth);

  void SetLocalIp(char* ip);

  void SetLocalMac(char* mac);

  void SetPortData(const int& port, const int& caplen) {
    std::string port_str = std::to_string(port);;
    port_data_[port_str] = port_data_[port_str] + caplen;
  };

  void SetDownload(int caplen) {
    port_data_["download"] += caplen;
  };

  void SetUpload(int caplen) {
    port_data_["upload"] += caplen;
  };

  void PrintfPortData() {
    for (auto iter = port_data_.begin(); iter != port_data_.end(); iter++) {
      std::cout << iter->first;
      printf (" --- %lld\n", iter->second);
    }
  };

  void GetNetworkData(std::map<std::string, unsigned long long>* port_data) {
    *port_data = port_data_;
  }

  void DataClear() {
    port_data_.clear();
  }

 private:
  std::map<std::string, unsigned long long> port_data_;

  std::string local_ip_;

  std::string local_mac_;
};

#endif // NET_MONITORING_CLIENT_PROBE_H_
