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

  void SetLocalIp();

  void SetLocalMac();

  void SetPortData(const int& port, const int& caplen) {
    port_data_[port] = port_data_[port] + caplen;
  };

  void SetDownload(int caplen) {
    download_ += caplen;
    //printf ("len : %d\n", caplen);
  };

  void SetUpload(int caplen) {
    upload_ += caplen;
    //printf ("len : %d\n", caplen);
  };

  void PrintfPortData() {
    for (auto iter = port_data_.begin(); iter != port_data_.end(); iter++) {
      printf ("%d --- %d\n", iter->first, iter->second);
    }
    printf ("in :%lld     out:%lld\n", download_, upload_);
  };

 private:
  unsigned long long download_;

  unsigned long long upload_;

  std::map<int, int> port_data_;

  std::string local_ip_;

  std::string local_mac_;
};

#endif // NET_MONITORING_CLIENT_PROBE_H_
