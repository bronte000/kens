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
};

struct TCP_Header {
  sockaddr_in src_addr;
  sockaddr_in dest_addr;
  seq_t seq_num;
  seq_t ack_num;
  uint16_t checksum;
};

struct Socket {
  sockaddr_in host_address;
  sockaddr_in peer_address;
  // You may add some other fields below here
  S_STATE state = S_DEFAULT;
  int backlog = 0;
  seq_t send_base = 0;
  seq_t ack_base = 0;
  UUID syscallUUID;
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
  std::map<int, struct Socket*> socket_map;
  std::queue<int> backlog_queue;
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
