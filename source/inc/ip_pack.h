/*
 * @Author: Snitro
 * @Date: 2022-12-14 12:02:50
 * @LastEditors: Snitro
 * @LastEditTime: 2022-12-14 13:51:19
 * @Description: IP数据包
 */
#ifndef __IP_PACK_H
#define __IP_PACK_H

#include <arpa/inet.h>

#include <cstdio>

class IP_PACK {
   public:
    IP_PACK(uint8_t protocol);

    struct sockaddr_in addr;

    static unsigned short checksum(unsigned short* buffer, unsigned short size);

    void setBroadcastState(bool enable) {
        int on = enable;

        if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(int)) !=
            0) {
            perror("setsockopt SO_BROADCAST error");
        }
    }

    void setSource(int addr);

    ssize_t sendPack(const void* buffer, size_t len, int s_addr,
                     const sockaddr_in& d_addr);
    ssize_t sendPack(const void* buffer, size_t len, const sockaddr_in& addr);

   private:
    int sockfd;  // 套接字

    int source_ip;  // 源网络地址

    uint8_t protocol;  // 协议类型

    int mut;  // MTU
};

#endif