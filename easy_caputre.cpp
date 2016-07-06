#include <iostream>
#include <tins/tins.h>

using namespace Tins;

bool callback(const PDU &pdu) {
  const IP *ip = pdu.find_pdu<IP>();
  const TCP *tcp = pdu.find_pdu<TCP>();
  const UDP *udp = pdu.find_pdu<UDP>();

  if(tcp){
    std::cout << "TCP ";
    std::cout << ip->src_addr() << ':' << tcp->sport() << "->"
              << ip->dst_addr() << ':' << tcp->dport()
              << std::endl;
  }
  if(udp){
    std::cout << "UDP ";
    std::cout << ip->src_addr() << ':' << udp->sport() << "->"
              << ip->dst_addr() << ':' << udp->dport() << std::endl;
  }

  return true;
}

int main(int argc, char* argv[]) {
  SnifferConfiguration config;
  config.set_promisc_mode(true);
  config.set_filter("udp or tcp");
  Sniffer sniffer(argv[1], config);
  sniffer.sniff_loop(callback);
}

