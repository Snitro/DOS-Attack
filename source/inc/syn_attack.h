/*
 * @Author: Snitro
 * @Date: 2022-12-14 12:02:50
 * @LastEditors: Snitro
 * @LastEditTime: 2022-12-14 13:51:27
 * @Description: SYN 攻击
 */

#ifndef __SYN_ATTACK_H
#define __SYN_ATTACK_H

#include <cstdlib>
#include <ctime>

#include "ip_pack.h"

class SYN_Attack {
   public:
    SYN_Attack(IP_PACK &ip_pack) : ip_pack(ip_pack) {
        addr.sin_family = AF_INET;

        srand((unsigned)time(NULL));
    }

    void start(char *dest, int port);
    void start(in_addr_t dest, int port);

   private:
    IP_PACK &ip_pack;

    struct sockaddr_in addr;
};

#endif