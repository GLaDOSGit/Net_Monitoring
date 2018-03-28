/*******************************************
 * Author(s): Gu Kai <540867841@qq.com>
 *
 * This file is for probe info client.
*******************************************/

#ifndef NET_MONITORING_CLIENT_PROBE_H_
#define NET_MONITORING_CLIENT_PROBE_H_

#include <map>
#include <pcap.h>
#include <set>
#include <string>
#include <vector>

struct IOData {
  long long receive[8];
  long long transmit[8];
};

class ProbeProcessor {
 public:
   ProbeProcessor();
   ~ProbeProcessor();
 
   void CapturePacket();

   void GetLocalIp();

   void GetLocalMac();

   void PortMonitoring();

   void ProbeNetworkAdapter();

 private:
   pcap_t* dev_;

   unsigned long long download_;

   unsigned long long upload_;

   std::map<std::string, IOData> adapter_data_;
   
   std::string local_ip_;

   std::string local_mac_;
   
   std::set<std::string> open_port_;
};

#endif // NET_MONITORING_CLIENT_PROBE_H_
