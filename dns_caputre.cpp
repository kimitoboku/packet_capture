#include <iostream>
#include <tins/tins.h>

using namespace Tins;

bool callback(const PDU& pdu) {
    DNS dns = pdu.rfind_pdu<RawPDU>().to<DNS>();

    for (const auto& query : dns.queries()) {
      std::cout << query.dname() << std::endl;
    }
    return true;
}

int main(int argc, char* argv[]) {
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter("udp and dst port 53");
    Sniffer sniffer(argv[1], config);
    sniffer.sniff_loop(callback);
}

