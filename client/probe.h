/*******************************************
 * Author(s): Gu Kai <540867841@qq.com>
 *
 * This file is for probe info client.
*******************************************/

#ifndef NET_MONITORING_CLIENT_PROBE_H_
#define NET_MONITORING_CLIENT_PROBE_H_

#include <map>
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
 
   void GetLocalIp();

   void PortMonitoring();

   void ProbeNetworkAdapter();
 private:
   std::map<std::string, IOData> adapter_data_;
   
   std::string local_ip_;
   
   std::set<std::string> open_port_;
};

#endif // NET_MONITORING_CLIENT_PROBE_H_
