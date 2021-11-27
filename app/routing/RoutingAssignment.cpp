/*
 * E_RoutingAssignment.cpp
 *
 */

#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

#include "RoutingAssignment.hpp"

namespace E {

RoutingAssignment::RoutingAssignment(Host &host)
    : HostModule("UDP", host), RoutingInfoInterface(host),
      TimerModule("UDP", host) {}

RoutingAssignment::~RoutingAssignment() {}

void RoutingAssignment::initialize() {

  IP_Header i_header;
  i_header.dest_ip = inet_addr("255.255.255.255");
  UDP_Header u_header {.len = htons(32)};
  rip_header_t rip_header {.command = 1, .version = 1};
  rip_entry_t rip_entry {.metric = htonl(16)};
  uint8_t packet_buffer[DATA_START + 24];
  memcpy(packet_buffer+UDP_START, &u_header, 8);
  memcpy(packet_buffer+DATA_START, &rip_header, 4);
  memcpy(packet_buffer+DATA_START+4, &rip_entry, 20);
  
  int port_num = getPortCount();
  for (int i = 0; i < port_num; i++){
    printf("%d", i);
    u_header.checksum = 0;
    i_header.src_ip = NetworkUtil::arrayToUINT64<4>(*getIPAddr(i));//inet_addr("10.0.0.1");
    memcpy(packet_buffer+IP_START, &i_header, 20);
    memcpy(packet_buffer+UDP_START, &u_header, 8);
    u_header.checksum = htons(~NetworkUtil::tcp_sum(i_header.src_ip, i_header.dest_ip,
                              &packet_buffer[UDP_START], 32));
    memcpy(packet_buffer+UDP_START, &u_header, 8);
    Packet pkt (DATA_START + 24);  
    pkt.writeData(IP_START, &packet_buffer[IP_START], DATA_START + 24 - IP_START);
    sendPacket("IPv4", pkt);  
  }
}

void RoutingAssignment::finalize() {}

/**
 * @brief Query cost for a host
 *
 * @param ipv4 querying host's IP address
 * @return cost or -1 for no found host
 */
Size RoutingAssignment::ripQuery(const ipv4_t &ipv4) {
  // Implement below
  auto ip = NetworkUtil::arrayToUINT64<4>(ipv4);

  auto route_info = routing_table.find(ip);
  if (route_info == routing_table.end()){
    return -1;
  } else {
    return routing_table[ip].cost;
  }
}

void RoutingAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  (void)fromModule;
  (void)packet;
}

void RoutingAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload; 
}

} // namespace E
