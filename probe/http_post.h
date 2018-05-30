/*******************************************
 * Author(s): Gu Kai <540867841@qq.com>
 *
 * This file is for http post of client.
*******************************************/

#ifndef NET_MONITORING_CLIENT_HTTP_POST_H_
#define NET_MONITORING_CLIENT_HTTP_POST_H_

#include <string>

class HttpPost {
 public:
  HttpPost();
  ~HttpPost();

	std::string Post(std::string host, std::string url, std::string data, int port);
};

#endif // NET_MONITORING_CLIENT_HTTP_POST_H_
