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

// Set Ip/TCP headers
void TCPAssignment::set_header(const Socket* src_socket, const sockaddr_in* dest_addr, Packet* pkt){
  IP_Header i_header;
  TCP_Header t_header;
  i_header.src_ip = src_socket->host_address.sin_addr.s_addr;
  i_header.dest_ip = dest_addr->sin_addr.s_addr;
  t_header.src_port = src_socket->host_address.sin_port;
  t_header.dest_port = dest_addr->sin_port;
  t_header.seq_num = src_socket->send_base; 
  t_header.ack_num = src_socket->send_base; 
  t_header.checksum = htons(~NetworkUtil::tcp_sum(i_header.src_ip, i_header.dest_ip, nullptr, 0));

  (*pkt).writeData(14, &i_header, sizeof(i_header));
  (*pkt).writeData(34, &t_header, sizeof(t_header));
}

void TCPAssignment::set_header2(const Socket* src_socket, const sockaddr_in* dest_addr, Packet* pkt, uint16_t flag){
  IP_Header i_header;
  TCP_Header t_header;
  i_header.src_ip = src_socket->host_address.sin_addr.s_addr;
  i_header.dest_ip = dest_addr->sin_addr.s_addr;
  t_header.src_port = src_socket->host_address.sin_port;
  t_header.dest_port = dest_addr->sin_port;
  t_header.flag= flag;
  t_header.seq_num = src_socket->send_base; 
  t_header.ack_num = src_socket->send_base; 
  t_header.checksum = htons(~NetworkUtil::tcp_sum(i_header.src_ip, i_header.dest_ip, nullptr, 0));

  (*pkt).writeData(14, &i_header, sizeof(i_header));
  (*pkt).writeData(34, &t_header, sizeof(t_header));
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
    Socket* new_socket = new Socket;
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
    // this->syscall_connect(syscallUUID, pid, param.param1_int,
    //		static_cast<struct sockaddr*>(param.param2_ptr),
    //(socklen_t)param.param3_int);
    int socket_descriptor = param.param1_int;
    int map_key = pid * 10 + socket_descriptor;
    if (socket_map.find(map_key) != socket_map.end()){
      struct Socket* socket = socket_map[map_key];
      const struct sockaddr_in* dest_address = (const sockaddr_in*) param.param2_ptr;

      Packet pkt (pkt_size);  
      set_header(socket, dest_address, &pkt);
      socket->state = S_CONNECTING;
      socket->syscallUUID = syscallUUID;
   //   socket->timerKey = addTimer(syscallUUID, TimeUtil::makeTime(20000000, TimeUtil::USEC));
      sendPacket("IPv4", pkt);  
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
      if(socket->state==S_LISTEN){
        //socket->backlog_queue.front();
      }
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
      if (socket->state != 0) {
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
      if (!socket->state) {
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
  IP_Header i_header;
  TCP_Header t_header;
  packet.readData(14, &i_header, sizeof(i_header));
  packet.readData(34, &t_header, sizeof(t_header));
  sockaddr_in src_addr = {.sin_port = t_header.src_port, .sin_addr = in_addr{i_header.src_ip}};
  sockaddr_in dest_addr = {.sin_port = t_header.dest_port, .sin_addr = in_addr{i_header.dest_ip}};

  int map_key = find_socket(&dest_addr, nullptr);  
  if (map_key == -1){
    //printf("-1 arrived => ip: %d, port: %d.\n", dest_addr.sin_addr, dest_addr.sin_port);
    //assert(0);
    return;
  }

  Socket* socket = socket_map[map_key];
  //printf("state: %d\n", socket->state);
  switch (socket->state) {
    case S_DEFAULT: case S_BIND:
      break;
    case S_LISTEN:
      //socket->backlog//backlog
      if(socket->backlog_queue.size()>=socket->backlog){
        break;
      }
      if(t_header.flag&SYNbit){
        //create new socket
        int pid = socket->pid;
        int socket_descriptor = createFileDescriptor(pid);
        int map_key = pid * 10 + socket_descriptor;
        assert(socket_map.find(map_key) == socket_map.end());
        Socket* new_socket = new Socket;
        new_socket->host_address = socket->host_address;
        new_socket->peer_address = src_addr;
        new_socket->ack_base = t_header.seq_num + 1;
        new_socket->pid = pid;
        socket_map[map_key] = new_socket;

        //seq_t ACK_num = t_header.seq_num+1;
        const struct sockaddr_in* dest_address = (const sockaddr_in*) &src_addr;
        Packet pkt (pkt_size);  

        set_header2(socket, dest_address, &pkt,(SYNbit||ACKbit));
        sendPacket("IPv4", pkt);  
        socket->backlog_queue.push(new_socket);       
      }

      break;
    case S_CONNECTING:{
      if (t_header.ack_num == socket->send_base){
        socket->send_base++;
        socket->state = S_CONNECTED;
     //   cancelTimer(socket->timerKey);
        returnSystemCall(socket->syscallUUID, 0);
      }
      break;
    }
    case S_ACQUIRING:
      break;
    case S_CONNECTED:
      break;
    default:
      assert(0);
  }

}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  // (void)payload;
  if (std::any_cast<UUID>(payload)){
    printf("time out! return -1\n");
    returnSystemCall(std::any_cast<UUID>(payload), -1);
  } else {
    assert(0);
  }
}

} // namespace E
