/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#include "TCPAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/E_TimeUtil.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

namespace E {

TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {
}

void TCPAssignment::finalize() {
}

// Find sockete with host_addr/peer_Addr. You can put nullptr to peer_Addr.
int TCPAssignment::find_socket(const sockaddr_in* host_addr, const sockaddr_in* peer_addr){
  auto addr_equal = [](const sockaddr_in* sock_addr1, const sockaddr_in* sock_addr2){
    if (sock_addr1->sin_port == sock_addr2->sin_port){
      if (sock_addr1->sin_addr.s_addr == htonl(INADDR_ANY)  ||
          sock_addr2->sin_addr.s_addr == htonl(INADDR_ANY)  ||
          sock_addr1->sin_addr.s_addr == sock_addr2->sin_addr.s_addr){
            return true;
      }
    }
    return false;
  };
  for (auto iter = socket_map.begin() ; iter != socket_map.end(); iter++) {
    if (addr_equal(&iter->second->host_address, host_addr)){
      if (peer_addr == nullptr || addr_equal(&iter->second->peer_address, peer_addr)){
        return iter->first;  
      }
    }
  }
  return -1;
}

// Write everything. Should set buffer which will be written to packet
void TCPAssignment::set_packet(const Socket* socket, Packet* pkt, TCP_Header* tcp_buffer){

  IP_Header i_header;
  TCP_Header* t_header = (TCP_Header*) tcp_buffer;
  i_header.src_ip = socket->host_address.sin_addr.s_addr;
  i_header.dest_ip = socket->peer_address.sin_addr.s_addr;
  t_header->src_port = socket->host_address.sin_port;
  t_header->dest_port = socket->peer_address.sin_port;
  t_header->seq_num = htonl(socket->send_base); 
  t_header->ack_num = htonl(socket->ack_base); 
  t_header->checksum = 0;
  t_header->checksum = htons(~NetworkUtil::tcp_sum(i_header.src_ip, i_header.dest_ip,
                                (uint8_t*) t_header, pkt->getSize() - TCP_START));

  pkt -> writeData(IP_START, &i_header, sizeof(i_header));
  //pkt -> writeData(IP_START+12, &(i_header.src_ip), 8);
  pkt -> writeData(TCP_START, t_header, pkt->getSize() - TCP_START);
}

// call with socket trying to connecting
void TCPAssignment::try_connect(Socket* socket){
  assert(socket->state == S_CONNECTING);
  Packet pkt (DATA_START);  
  TCP_Header t_header2 = {.flag = SYNbit};
  set_packet(socket, &pkt, &t_header2);
  socket->timerKey = addTimer(socket, TimeUtil::makeTime(5, TimeUtil::SEC));
  sendPacket("IPv4", pkt);  
  return;
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  // Remove below
  // (void)syscallUUID;
  // (void)pid;

  switch (param.syscallNumber) {
  case SOCKET: {
    // this->syscall_socket(syscallUUID, pid, param.param1_int,
    // param.param2_int, param.param3_int);    
    assert(param.param1_int == AF_INET);  // domain
    assert(param.param2_int == SOCK_STREAM);  // type
    assert(param.param3_int == IPPROTO_TCP);  // protocol

    int socket_descriptor = createFileDescriptor(pid);
    assert(socket_descriptor > -1);
    int map_key = pid * 10 + socket_descriptor;
    Socket* new_socket = new Socket(pid, socket_descriptor);
    new_socket->pid = pid;
    assert(socket_map.find(map_key) == socket_map.end());
    socket_map[map_key] = new_socket;

    returnSystemCall(syscallUUID, socket_descriptor);
    break;
  }
  case CLOSE:{
    // this->syscall_close(syscallUUID, pid, param.param1_int);
    int socket_descriptor = param.param1_int;
    int map_key = pid * 10 + socket_descriptor;
    if (socket_map.find(map_key) == socket_map.end()){
      returnSystemCall(syscallUUID, -1);
    }
    else {
      removeFileDescriptor(pid, socket_descriptor);
      delete(socket_map[map_key]);
      socket_map.erase(map_key);
      returnSystemCall(syscallUUID, 0);
    }
    break;
  }
  case READ:
    // this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr,
    // param.param3_int);
    break;
  case WRITE:
    // this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr,
    // param.param3_int);
    break;
  case CONNECT: {
    break;
    // this->syscall_connect(syscallUUID, pid, param.param1_int,
    //		static_cast<struct sockaddr*>(param.param2_ptr),
    //(socklen_t)param.param3_int);
    int socket_descriptor = param.param1_int;
    int map_key = pid * 10 + socket_descriptor;
    if (socket_map.find(map_key) != socket_map.end()){
      struct Socket* socket = socket_map[map_key];
      if(socket->state != S_BIND){
        // should bind with arbitrary adrress;
      }
      socket->state = S_CONNECTING;
      socket->syscallUUID = syscallUUID;
      socket->peer_address = *(const sockaddr_in*) param.param2_ptr;
      try_connect(socket);
    } else {
      returnSystemCall(syscallUUID, -1);
    }
    break;
  }
  case LISTEN: {
    // this->syscall_listen(syscallUUID, pid, param.param1_int,
    // param.param2_int);
    int socket_descriptor = param.param1_int;
    int map_key = pid * 10 + socket_descriptor;
    int validance=-1;
    if (socket_map.find(map_key) != socket_map.end()){
      struct Socket* socket = socket_map[map_key];
      if(socket->state==S_BIND){
        socket->state=S_LISTEN;
        socket->backlog=param.param2_int;
        validance=0;
      }
    }
    //now, I set the queue value to global... but is it right? Should the queue is in Socket Structure?
    returnSystemCall(syscallUUID, validance);
    break;
  }
  case ACCEPT:{
    // this->syscall_accept(syscallUUID, pid, param.param1_int,
    //		static_cast<struct sockaddr*>(param.param2_ptr),
    //		static_cast<socklen_t*>(param.param3_ptr));
    int socket_descriptor = param.param1_int;
    int map_key = pid * 10 + socket_descriptor;
    if (socket_map.find(map_key) != socket_map.end()){
      struct Socket* socket = socket_map[map_key];
      if(socket->state!=S_LISTEN){
        returnSystemCall(syscallUUID,-1);
        break;
      }
      if(socket->backlog_queue.size()!=0){
        Socket *new_socket= socket->backlog_queue.front();
        socket->backlog_queue.pop();
        assert(new_socket->state == S_BLOCKED);
        new_socket->state=S_CONNECTED;
        memcpy(param.param2_ptr, &socket->peer_address, sizeof(struct sockaddr));
        *static_cast<socklen_t *>(param.param3_ptr) = sizeof(struct sockaddr);
        new_socket->syscallUUID = syscallUUID;
        returnSystemCall(syscallUUID, new_socket->sd);
      } else {
        // wait until S_listen takes it
        Socket *new_socket= new Socket(pid, createFileDescriptor(pid));
        new_socket->host_address = socket->host_address;
        new_socket->state = S_ACCEPTING;
        new_socket->syscallUUID = syscallUUID;
        socket->backlog_queue.push(new_socket);
      }
    } else {
      returnSystemCall(syscallUUID, -1);
    }
    break;
  }
  case BIND: {
    // this->syscall_bind(syscallUUID, pid, param.param1_int,
    //		static_cast<struct sockaddr *>(param.param2_ptr),
    //		(socklen_t) param.param3_int);
    int socket_descriptor = param.param1_int;
    int map_key = pid * 10 + socket_descriptor;
    int validance = -1; 
    // Should check whether it uses the dupplicate address!
    if (socket_map.find(map_key) != socket_map.end()){
      struct Socket* socket = socket_map[map_key];
      const struct sockaddr_in* socket_address = (const sockaddr_in*) param.param2_ptr;
      if (!socket->state && find_socket(socket_address, nullptr) == -1){
        socket->host_address.sin_port = socket_address->sin_port;
        socket->host_address.sin_addr = socket_address->sin_addr;
        validance=0;
        socket->state=S_BIND;
      }
    }
    returnSystemCall(syscallUUID, validance);
    break;
  }
  case GETSOCKNAME:{
    // this->syscall_getsockname(syscallUUID, pid, param.param1_int,
    //		static_cast<struct sockaddr *>(param.param2_ptr),
    //		static_cast<socklen_t*>(param.param3_ptr)); 
    int socket_descriptor = param.param1_int;
    int map_key = pid * 10 + socket_descriptor;
    int validance = -1;
    if (socket_map.find(map_key) != socket_map.end()){
      struct Socket* socket = socket_map[map_key];
      if (socket->state != S_DEFAULT) {
        memcpy(param.param2_ptr, &socket->host_address, sizeof(struct sockaddr));
        *static_cast<socklen_t *>(param.param3_ptr) = sizeof(struct sockaddr);
        validance = 0;
      }
    }
    returnSystemCall(syscallUUID, validance);
    break;
  }
  case GETPEERNAME:{
    // this->syscall_getpeername(syscallUUID, pid, param.param1_int,
    //		static_cast<struct sockaddr *>(param.param2_ptr),
    //		static_cast<socklen_t*>(param.param3_ptr));
    int socket_descriptor = param.param1_int;
    int map_key = pid * 10 + socket_descriptor;
    int validance = -1;
    if (socket_map.find(map_key) != socket_map.end()){
      struct Socket* socket = socket_map[map_key];
      if (socket->state == S_CONNECTED || socket->state == S_ACCEPTING) {
        memcpy(param.param2_ptr, &socket->peer_address, sizeof(struct sockaddr));
        *static_cast<socklen_t *>(param.param3_ptr) = sizeof(struct sockaddr);
        validance = 0;
      }
    }
    returnSystemCall(syscallUUID, validance);
    break;
  }
  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  // (void)fromModule;
  // (void)packet;
  
  uint8_t buffer[BUFFER_SIZE];
  int pkt_size = packet.getSize();
  packet.readData(0, buffer, pkt_size); 
  IP_Header* i_header = (IP_Header*) &buffer[IP_START];
  TCP_Header* t_header = (TCP_Header*) &buffer[TCP_START];
  uint16_t checksum = t_header->checksum;
  t_header->checksum = 0;
  printf("recieevd seq: %d, ack: %d\n", ntohl(t_header->seq_num), ntohl(t_header->ack_num));

  if (ntohs(checksum) & NetworkUtil::tcp_sum(i_header->src_ip, i_header->dest_ip,
               &buffer[TCP_START], pkt_size-TCP_START))  return;

  sockaddr_in src_addr = {.sin_family = AF_INET, .sin_port = t_header->src_port, .sin_addr = in_addr{i_header->src_ip}};
  sockaddr_in dest_addr = {.sin_family = AF_INET, .sin_port = t_header->dest_port, .sin_addr = in_addr{i_header->dest_ip}};

  int map_key = find_socket(&dest_addr, &src_addr); 
  if (map_key == -1){
    map_key = find_socket(&dest_addr, nullptr);
    if (map_key == -1){
      printf("-1 arrived => ip: %d, port: %d.\n", dest_addr.sin_addr, dest_addr.sin_port);
      //assert(0);
      return;
    }  
  }

  Socket* socket = socket_map[map_key];
  printf("state: %d\n", socket->state);
  switch (socket->state) {
    case S_DEFAULT: case S_BIND:
      break;
    case S_LISTEN:{
      //socket->backlog//backlog
      bool accept_waiting = (socket->backlog_queue.size() == 1) && (socket->backlog_queue.front()->state == S_ACCEPTING);
      if( (!accept_waiting) && (socket->loading_queue.size() >= socket->backlog)) break;
      if (t_header->flag&SYNbit){

        Socket* new_socket;
        if (accept_waiting){
          new_socket = socket->backlog_queue.front();
          socket->backlog_queue.pop();
        } else {
          int socket_descriptor = createFileDescriptor(socket->pid);
          new_socket = new Socket(socket->pid, socket_descriptor);
          new_socket->state = S_ACCEPTING;
        }
        new_socket->host_address = dest_addr;
        new_socket->peer_address = src_addr;
        new_socket->ack_base =  ntohl(t_header->seq_num) + 1;
        new_socket->listen_key = map_key;
        int map_key = new_socket->pid * 10 + new_socket->sd;
        assert(socket_map.find(map_key) == socket_map.end());
        socket_map[map_key] = new_socket;

        Packet pkt (DATA_START);  
        t_header->flag = SYNbit | ACKbit;
        set_packet(new_socket, &pkt, t_header);
        sendPacket("IPv4", pkt);  
        if (accept_waiting) returnSystemCall(new_socket->syscallUUID, new_socket->sd);
        else
         socket->loading_queue.push(new_socket);  
      } 
      break;
    }
    case S_CONNECTING:{
      if(t_header->flag&SYNbit && t_header->flag&ACKbit){
        if (t_header->ack_num == socket->send_base +1){
        socket->send_base++;
        socket->state = S_CONNECTED;
        cancelTimer(socket->timerKey);
        returnSystemCall(socket->syscallUUID, 0);
        }
      } /*else if ((~t_header.flag&ACKbit) && (i_header.length == 0)){
        cancelTimer(socket->timerKey);
        try_connect(socket);
      } */else {
        assert(pkt_size > DATA_START);
        socket->state = S_BIND;
        cancelTimer(socket->timerKey);
        returnSystemCall(socket->syscallUUID, -1);
      }
      break;
    }
    case S_ACCEPTING:{
      if(t_header->flag&ACKbit){
      int listenkey=socket->listen_key;
      Socket* listensk =socket_map[listenkey];
      Socket* new_socket=listensk->loading_queue.front();
      new_socket->state=S_BLOCKED;//temporary
      listensk->loading_queue.pop();
      listensk->backlog_queue.push(new_socket);

      }
      break;
    }
    case S_CONNECTED:
      break;
    case S_BLOCKED:{
      break;
    }
    default:
      assert(0);
  }

}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  // (void)payload;
  Socket* socket = std::any_cast<Socket*>(payload);
  assert(socket);
  if (socket->state == S_CONNECTING){
    try_connect(socket);
  }
}

} // namespace E
