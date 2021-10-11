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

const uint16_t ACKbit = 1 << 4;
const uint16_t RSTbit = 1 << 2;
const uint16_t SYNbit = 1 << 1;
const uint16_t FINbit = 1 << 0;

const int IP_START = 14;
const int TCP_START = 34;
const int DATA_START = 54;

enum S_STATE {
  S_DEFAULT = 0,
  S_BIND,
  S_LISTEN,
  S_CONNECTING,
  S_ACCEPTING,
  S_CONNECTED,
  S_BLOCKED,
  S_CLOSE_WAIT,
  S_FINWAIT1,
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

// should set unused, flag, recv_wdw, zero, manually
struct TCP_Header {
  in_port_t src_port; //2byte
  in_port_t dest_port;  //2byte
  seq_t seq_num;  
  seq_t ack_num;  //sum 8 bytes
  uint8_t unused;   
  uint8_t flag;
  uint16_t recv_wdw;
  uint16_t checksum;  
  uint16_t zero;  // sum 8 bytes
};  //should be 20 bytes

struct Socket {
  sockaddr_in host_address;
  sockaddr_in peer_address;
  // You may add some other fields below here
  S_STATE state = S_DEFAULT;
  //uint accepting_num=0;   //why do we need
  seq_t send_base = 10; 
  seq_t ack_base = 10;
  int pid;
  int sd;
  UUID syscallUUID = 0;
  UUID timerKey = 0;
  // For accept
  uint backlog = 0;
  int listen_key = -1;	
  uint back_count = 0;
  bool accept_called = false;
  bool close_available = false;
  Socket* accepted_socket = nullptr;
  struct sockaddr* return_address = nullptr;
  socklen_t* return_addr_len = nullptr;
  //std::queue<struct Socket*> backlog_queue;
  std::queue<struct Socket*> connected_queue;
  Socket(int _pid, int _sd){
    host_address = {AF_INET, 0, 0};
    peer_address = {AF_INET, 0, 0};
    pid = _pid;
    sd = _sd;
  }
};

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;
  int find_socket(const sockaddr_in* host_addr, const sockaddr_in* peer_addr);
  void set_packet(const Socket* src_socket, Packet* pkt, TCP_Header* tcp_buffer);
  void try_connect(Socket* socket);
  std::map<int, struct Socket*> socket_map;

  const int BUFFER_SIZE = 2000;
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
