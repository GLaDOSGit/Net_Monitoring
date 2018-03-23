/*******************************************
 * Author(s): Gu Kai <540867841@qq.com>
 *
 * This file is for probe info client.
*******************************************/

#ifndef NET_MONITORING_CLIENT_PROBE_H_
#define NET_MONITORING_CLIENT_PROBE_H_

#include <map>
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
 
   void ProbeNetworkAdapter();
 private:
   std::map<std::string, IOData> adapter_data_;
};

#endif // NET_MONITORING_CLIENT_PROBE_H_
