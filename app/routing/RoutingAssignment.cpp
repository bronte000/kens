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
/*
void RoutingAssignment::set_RIP(Packet* pkt, uint8_t* data){
  IP_Header i_header;
  UDP_Header u_header;
  uint8_t packet_buffer[PACKET_SIZE];
  i_header.src_ip = socket->host_address.sin_addr.s_addr;
  i_header.dest_ip = socket->peer_address.sin_addr.s_addr;
  t_header.src_port = socket->host_address.sin_port;
  t_header.dest_port = socket->peer_address.sin_port;
  t_header.seq_num = htonl(socket->seq_base); 
  t_header.ack_num = htonl(socket->ack_base); 
  t_header.flag = flag; 
  t_header.checksum = 0;
  memcpy(packet_buffer+TCP_START, &t_header, 20);
  memcpy(packet_buffer+DATA_START, data, pkt->getSize()-DATA_START);
  t_header.checksum = htons(~NetworkUtil::tcp_sum(i_header.src_ip, i_header.dest_ip,
                              &packet_buffer[TCP_START], pkt->getSize() - TCP_START));

  pkt -> writeData(IP_START, &i_header, sizeof(i_header));
  //pkt -> writeData(IP_START+12, &(i_header.src_ip), 8);
  pkt -> writeData(TCP_START, &t_header, 20);
  pkt -> writeData(DATA_START, data, pkt->getSize() - DATA_START);
}
*/

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
    i_header.src_ip =  NetworkUtil::arrayToUINT64<4>(*getIPAddr(i));//inet_addr("10.0.0.1");
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

  return -1;
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
