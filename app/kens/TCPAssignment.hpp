/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/E_TimeUtil.hpp>
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

const uint8_t HEADER_SIZE = 5 << 4;

const int IP_START = 14;
const int TCP_START = 34;
const int DATA_START = 54;

const int BUFFER_SIZE = 2000000;
const int PACKET_SIZE = 1500 * 8;

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

enum C_STATE {
  C_NONE = 0,
  C_ACCEPT,
  C_READ,
  C_WRITE,
  C_CLOSE,
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
  uint8_t unused = HEADER_SIZE;   
  uint8_t flag;
  uint16_t recv_wdw = 50;
  uint16_t checksum;  
  uint16_t zero;  // sum 8 bytes
};  //should be 20 bytes

struct Socket {
  sockaddr_in host_address;
  sockaddr_in peer_address;
  // You may add some other fields below here
  S_STATE state = S_DEFAULT;
  C_STATE called = C_NONE;
  //uint accepting_num=0;   //why do we need
  seq_t seq_base = 10; 
  seq_t ack_base = 10;
  int pid;
  int sd;
  // Syscall paramters
  UUID syscallUUID = 0;
  void* syscall_ptr = nullptr;
  int syscall_int;
  socklen_t* return_addr_len = nullptr;
  // Timer
  UUID timer_key = 0;
  Time start_time;
  Time RTT = 0;
  Time DevRTT = 0;
  Time timeout_interval;
  // For accept
  uint backlog = 0;
  int listen_key = -1;	
  uint back_count = 0;
  Socket* accepted_socket = nullptr;
  //std::queue<struct Socket*> backlog_queue;
  std::queue<struct Socket*> connected_queue;
  // For close
  bool close_available = false;
  // For read/write
  uint8_t* recv_buffer; // size: 2000000  2MB
  size_t recv_base = 0;
  size_t recv_top = 0;
  uint8_t* send_buffer; // size: 2000000  2MB
  size_t send_base = 0;
  size_t sent_top = 0;
  size_t send_top = 0;
  bool send_full = false;
  // flow control
  size_t rcv_wdw = 0;

  Socket(int _pid, int _sd){
    host_address = {AF_INET, 0, 0};
    peer_address = {AF_INET, 0, 0};
    pid = _pid;
    sd = _sd;
    timeout_interval = TimeUtil::makeTime(200, TimeUtil::MSEC);
    recv_buffer = (uint8_t*) malloc(sizeof(uint8_t)*BUFFER_SIZE);
    send_buffer = (uint8_t*) malloc(sizeof(uint8_t)*BUFFER_SIZE);
  }
  ~Socket(){
    free(recv_buffer);
    free(send_buffer);
  }
};

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;
  int find_socket(const sockaddr_in* host_addr, const sockaddr_in* peer_addr);
  void set_packet(const Socket* src_socket, Packet* pkt, uint8_t flag, uint8_t* data);
  void try_connect(Socket* socket);
  void try_accept(Socket* socket);
  void try_write(Socket* socket, bool timeout);
  std::map<int, struct Socket*> socket_map;

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
