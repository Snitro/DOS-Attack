/*
 * @Author: Snitro
 * @Date: 2022-12-14 12:02:50
 * @LastEditors: Snitro
 * @LastEditTime: 2022-12-14 13:51:03
 * @Description: ICMP 攻击
 */

#ifndef __ICMP_ATTACK_H
#define __ICMP_ATTACK_H

#include <netinet/ip_icmp.h>

#include <cstdlib>
#include <ctime>

#include "ip_pack.h"

class ICMP_Attack {
   public:
    ICMP_Attack(IP_PACK &ip_pack) : ip_pack(ip_pack) {
        addr.sin_family = AF_INET;

        srand((unsigned)time(NULL));
    }

    void start(char *source, char *dest);
    void start(in_addr_t source, in_addr_t dest);

    void start_rand_source(char *dest);
    void start_rand_source(in_addr_t dest);

   private:
    IP_PACK &ip_pack;

    struct sockaddr_in addr;

    void init_pack(icmp *icmp_pack);
};

#endif