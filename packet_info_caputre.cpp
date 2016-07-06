#include <iostream>
#include <tins/tins.h>

using namespace Tins;

bool callback(const PDU &pdu) {
  const EthernetII *ether = pdu.find_pdu<EthernetII>();
  const IP *ip = pdu.find_pdu<IP>();
  const TCP *tcp = pdu.find_pdu<TCP>();
  const UDP *udp = pdu.find_pdu<UDP>();

  if(ether){
    std::cout << "Ether "
              << ether->dst_addr() << ":" << "->"
              << ether->src_addr()
              << " Payload_type:0x" << std::hex << ether->payload_type()
              << std::dec
              << std::endl;
  }

  if(tcp){
    std::cout << "    TCP "
              << ip->src_addr() << ':' << tcp->sport() << "->"
              << ip->dst_addr() << ':' << tcp->dport()
              << " Total Size:" << ip->tot_len()
              << " IP Flags:" << ip->flags()
              << " TTL:" << unsigned(ip->ttl())
              << " IP Protocol:" << unsigned(ip->protocol())
              << std::endl;
  }

  if(udp){
    std::cout << "    UDP "
              << ip->src_addr() << ':' << udp->sport() << "->"
              << ip->dst_addr() << ':' << udp->dport()
              << " Total Size:" << ip->tot_len()
              << " IP Flags:" << ip->flags()
              << " TTL:" << unsigned(ip->ttl())
              << " IP Protocol:" << unsigned(ip->protocol())
              << std::endl;
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

