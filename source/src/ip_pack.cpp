#include "ip_pack.h"

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include <cstring>

/**
 * @brief CRC16 校验
 *
 * @param buffer 数据
 * @param size 数据长度
 * @return unsigned short 校验和
 */
unsigned short IP_PACK::checksum(unsigned short* buffer, unsigned short size) {
    unsigned long cksum = 0;

    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }

    if (size) cksum += *(unsigned char*)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);

    return ((unsigned short)(~cksum));
}

/**
 * @brief Construct a new ip pack::ip pack object
 *
 * @param protocol 协议类型
 */
IP_PACK::IP_PACK(uint8_t protocol) : protocol(protocol) {
    // 建立socket
    sockfd = socket(AF_INET, SOCK_RAW, protocol);
    if (sockfd < 0) {
        perror("create socket error");
        exit(1);
    }

    // 设置IP选项:使用原始套接字
    int on = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (char*)&on, sizeof(on)) <
        0) {
        perror("set socket option error");
        exit(1);
    }
}

/**
 * @brief 设置源地址
 *
 * @param addr 源地址
 */
void IP_PACK::setSource(int addr) { this->source_ip = addr; }

/**
 * @brief 发送IP数据包
 *
 * @param buffer 上层数据包
 * @param len 上层数据包长度
 * @param s_addr 源地址
 * @param d_addr 目的地址
 * @return ssize_t 实际发送字符数，发送失败返回－1
 */
ssize_t IP_PACK::sendPack(const void* buffer, size_t len, int s_addr,
                          const sockaddr_in& d_addr) {
    this->setSource(s_addr);
    return this->sendPack(buffer, len, d_addr);
}

/**
 * @brief 发送IP数据包
 *
 * @param buffer 上层数据包
 * @param len 上层数据包长度
 * @param addr 目的地址
 * @return ssize_t 实际发送字符数，发送失败返回－1
 */
ssize_t IP_PACK::sendPack(const void* buffer, size_t len,
                          const sockaddr_in& addr) {
    struct ip* ip_pack = (struct ip*)malloc(sizeof(struct ip) + len);
    memcpy(((uint8_t*)ip_pack) + sizeof(struct ip), buffer, len);

    ip_pack->ip_v = IPVERSION;                         // 版本
    ip_pack->ip_hl = sizeof(struct ip) >> 2;           // 首部长度
    ip_pack->ip_tos = 0;                               // 区分服务
    ip_pack->ip_len = htons(sizeof(struct ip) + len);  // 总长度
    ip_pack->ip_id = 0;                                // 标识
    ip_pack->ip_off = 0x40;                            // 标致与片偏移
    ip_pack->ip_ttl = MAXTTL;                          // 生存时间
    ip_pack->ip_p = protocol;                          // 协议
    ip_pack->ip_sum = 0;                               // 首部检验和
    ip_pack->ip_src.s_addr = this->source_ip;          // 源地址
    ip_pack->ip_dst = addr.sin_addr;                   // 目的地址

    // 计算首部检验和
    ip_pack->ip_sum = IP_PACK::checksum((u_short*)ip_pack, sizeof(struct ip));

    ssize_t ret;

    // 发送IP数据包
    if ((ret = sendto(sockfd, ip_pack, sizeof(struct ip) + len, 0,
                      (struct sockaddr*)&addr, sizeof(struct sockaddr))) < 0)
        perror("can not sendto");

    free(ip_pack);

    return ret;
}