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
  rip_entry_t rip_entry {.address_family = htons(2), .metric = htonl(16)};
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
  if (route_info != routing_table.end()){
    return routing_table[ip];
  }
  return -1;
}

void RoutingAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  
  int pkt_size = packet.getSize();
  uint8_t packet_buffer[PACKET_SIZE];
  packet.readData(0, packet_buffer, pkt_size); 
  IP_Header* i_header = (IP_Header*) &packet_buffer[IP_START];
  UDP_Header* u_header = (UDP_Header*) &packet_buffer[UDP_START];
  uint16_t checksum = u_header->checksum;
  u_header->checksum = 0;
  if (ntohs(checksum) & NetworkUtil::tcp_sum(i_header->src_ip, i_header->dest_ip,
               &packet_buffer[UDP_START], pkt_size-UDP_START))  {
      printf("som?????\n");
                 assert(0);
                 return;
               }
  rip_t* rip = (rip_t*) &packet_buffer[DATA_START];

  routing_table[i_header -> src_ip] = 1;
  switch (rip->header.command){
    case 1: {
      size_t size = routing_table.size();
      rip_header_t response_header = rip_header_t{.command = 2, .version = 1};
      rip_entry_t response_entries[size];
      size_t it = 0;
      for (const auto& [ip, cost] : routing_table) {
        struct rip_entry_t rip_entry{.address_family = htons(2), .ip_addr = ip, .metric = htonl(cost)};
        response_entries[it] = rip_entry;
        it++;
      }
      
      IP_Header r_i_header;
      //printf("%d", ntohl(i_header->src_ip));
      r_i_header.dest_ip = i_header->src_ip;
      int src_port = getRoutingTable(NetworkUtil::UINT64ToArray<4>(i_header->dest_ip));
      r_i_header.src_ip = NetworkUtil::arrayToUINT64<4>(*getIPAddr(src_port));
      UDP_Header r_u_header {.len = htons(12+size*20)};
      memcpy(packet_buffer+IP_START, &r_i_header, 20);
      memcpy(packet_buffer+UDP_START, &r_u_header, 8);
      memcpy(packet_buffer+DATA_START, &response_header, sizeof(response_header));
      memcpy(packet_buffer+DATA_START+4, &response_entries, sizeof(response_entries));
      printf("response rip: %ld, size: %ld\n", sizeof(response_entries), size);
  
      r_u_header.checksum = htons(~NetworkUtil::tcp_sum(r_i_header.src_ip, r_i_header.dest_ip,
                              &packet_buffer[UDP_START], 12 + size*20));
                 
      memcpy(packet_buffer+UDP_START, &r_u_header, 8);
      Packet pkt (DATA_START + 4 + size*20);  
      pkt.writeData(IP_START, &packet_buffer[IP_START], ENTRY_START - IP_START + size*ENTRY_SIZE);
      sendPacket("IPv4", pkt);          
      break;
    }
    case 2: {
      int inc=0;
      printf("here:%d",pkt_size-(DATA_START+4));
      while(DATA_START+4+inc<pkt_size/*rest_size<=0*/){
        rip_entry_t* entry = (rip_entry_t*) &packet_buffer[DATA_START+4+inc];
        uint32_t src_metric=1;
        if(routing_table.find(entry->ip_addr) == routing_table.end()){
          routing_table[entry->ip_addr] = entry->metric+src_metric;}
        else{
          if(routing_table[entry->ip_addr] > entry->metric+src_metric)
          {routing_table[entry->ip_addr]=entry->metric+src_metric;}
        }
      inc+=20;
      }
      break;
    }
    default: {
      assert(0);
    }
  }

  return;
}

void RoutingAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload; 
}

} // namespace E
