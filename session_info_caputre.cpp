#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <tins/tins.h>
#include <tins/tcp_ip/stream_follower.h>

using namespace Tins;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

void on_new_connection(Stream& stream) {
  std::cout << stream.client_addr_v4() << ":" << stream.client_port() << "->" << stream.server_addr_v4() << ":" << stream.server_port() << std::endl;
  stream.auto_cleanup_payloads(false);
}

int main(int argc, char* argv[]) {
  SnifferConfiguration config;
  config.set_promisc_mode(true);
  config.set_filter("tcp");
  Sniffer sniffer(argv[1], config);
  StreamFollower follower;
  follower.new_stream_callback(&on_new_connection);
  sniffer.sniff_loop([&](Packet& packet) {
      follower.process_packet(packet);
      return true;
    });
}

