/*******************************************
 * Author(s): Gu Kai <540867841@qq.com>
 *
 * This file_ptr is for http post of client.
*******************************************/
#include "http_post.h"

#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <sstream>

using namespace std;

HttpPost::HttpPost() {
};

HttpPost::~HttpPost() {
};

void HttpPost::Post(string host, string url, string data, int port) {
    struct hostent *p_hostent = gethostbyname(host.c_str());
    if(p_hostent == NULL) {
        return;
    }

    sockaddr_in addr_server;
    addr_server.sin_family = AF_INET;
    addr_server.sin_port = htons(port);
    memcpy(&(addr_server.sin_addr), p_hostent->h_addr_list[0], sizeof(addr_server.sin_addr));
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int res = connect(sock, (sockaddr*)&addr_server, sizeof(addr_server));
    if(res == -1) {
        cout<< "Connect failed "<<endl;
        close(sock);
        return;
    }

    std::stringstream stream;
    stream << "POST " << url;
    stream << " HTTP/1.0\r\n";
    stream << "Host: "<< host  << "\r\n";
    stream << "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3\r\n";
    stream << "Content-Type:application/x-www-form-urlencoded\r\n";
    stream << "Content-Length:" << data.length()<<"\r\n";
    stream << "Connection:close\r\n\r\n";
    stream << data.c_str();

    string sendData = stream.str();
    send(sock,sendData.c_str(),sendData.size(),0);
    string  m_readBuffer;
    if(m_readBuffer.empty())
        m_readBuffer.resize(512);
    recv(sock,&m_readBuffer[0], m_readBuffer.size(),0);

    close(sock);
} 
