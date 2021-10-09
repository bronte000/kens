/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_TimerModule.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <map>
#include <queue>



namespace E {

typedef uint32_t seq_t;

enum S_STATE {
  S_DEFAULT = 0,
  S_BIND,
  S_LISTEN,
  S_CONNECTING,
  S_ACQUIRING,
  S_CONNECTED,
};

struct IP_Header {
  uint16_t extra;
  uint16_t length;
  uint16_t identifier;
  uint16_t flags;
  uint16_t lifetime;
  uint16_t checksum;  // sum 12 byte
  uint32_t src_ip;  
  uint32_t dest_ip;   // sum 8 bytes
}; // should be 20 bytes

struct TCP_Header {
  in_port_t src_port; //2byte
  in_port_t dest_port;  //2byte
  seq_t seq_num;  
  seq_t ack_num;  //sum 8 bytes
  uint16_t flag;
  uint16_t recv_wdw;
  uint16_t checksum;  
  uint16_t zero;  // sum 8 bytes
};  //should be 20 bytes

struct Socket {
  sockaddr_in host_address;
  sockaddr_in peer_address;
  // You may add some other fields below here
  S_STATE state = S_DEFAULT;
  int backlog = 0;
  seq_t send_base = 0;
  seq_t ack_base = 0;
  UUID syscallUUID;
  UUID timerKey;
  std::queue<int> backlog_queue;
  Socket(){
    host_address.sin_family = AF_INET;
    peer_address.sin_family = AF_INET;
  }
};

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;
  int find_socket(const sockaddr_in* host_addr, const sockaddr_in* peer_addr);
  void set_header(const Socket* src_socket, const sockaddr_in* dest_addr, Packet* pkt);
  std::map<int, struct Socket*> socket_map;
  std::queue<int> backlog_queue;
  const int pkt_size = 1000;
public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();

protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;
};

class TCPAssignmentProvider {
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}

public:
  static void allocate(Host &host) { host.addHostModule<TCPAssignment>(host); }
};

} // namespace E

#endif /* E_TCPASSIGNMENT_HPP_ */
