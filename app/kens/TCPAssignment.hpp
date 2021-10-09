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

#define S_DEFAULT 0
#define S_BIND 1
#define S_LISTEN 2


namespace E {

struct Socket {
  sockaddr_in host_address;
  sockaddr_in peer_address;
  // You may add some other fields below here
  int state;
  int backlog;
  Socket(){
    host_address.sin_family = AF_INET;
    host_address.sin_port = 0;
    peer_address.sin_family = AF_INET;
    peer_address.sin_port = 0;
    //You may add some other fields below here
    state=0;
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
