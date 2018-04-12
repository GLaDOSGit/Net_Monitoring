/*******************************************
 * Author(s): Gu Kai <540867841@qq.com>
 *
 * This file is for probe info client.
*******************************************/

#ifndef NET_MONITORING_CLIENT_HTTP_CONNECT_H_
#define NET_MONITORING_CLIENT_HTTP_CONNECT_H_

#include <string>

class HttpConnect {
 public:
  HttpConnect();
  ~HttpConnect();

  void Post(std::string host, std::string url, std::string data, int port);
};

#endif // NET_MONITORING_CLIENT_HTTP_CONNECT_H_
