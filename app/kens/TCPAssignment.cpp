/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#include "TCPAssignment.hpp"
#include <E/E_Common.hpp>
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
      if (peer_addr == nullptr || addr_equal(&iter->second->host_address, peer_addr)){
        return iter->first;  
      }
    }
  }
  return -1;
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

      TCP_Header header;
      header.src_addr = socket->host_address;
      header.dest_addr = *dest_address;
      header.seq_num = socket->send_base; 

      header.checksum = htons(~NetworkUtil::tcp_sum(header.src_addr.sin_addr.s_addr,
                                            header.dest_addr.sin_addr.s_addr, nullptr, 0));

      Packet pkt (100);  
      pkt.writeData(0, &header, sizeof(header));  
      socket->state = S_CONNECTING;
      socket->syscallUUID = syscallUUID;
      sendPacket("IPv4", std::move(pkt));  

      // Should add timer here
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
  case ACCEPT:
    // this->syscall_accept(syscallUUID, pid, param.param1_int,
    //		static_cast<struct sockaddr*>(param.param2_ptr),
    //		static_cast<socklen_t*>(param.param3_ptr));
    int socket_descriptor = param.param1_int;
    int map_key = pid * 10 + socket_descriptor;
    if (socket_map.find(map_key) != socket_map.end()){
      struct Socket* socket = socket_map[map_key];
      if(socket->state==S_LISTEN){
        
      }
    }
    break;
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
  TCP_Header* header = new TCP_Header;
  packet.readData(0, header, sizeof(header));
  int SD = find_socket(&header->dest_addr, &header->src_addr);
  Socket* socket = socket_map[SD];
  
  switch (socket->state) {
    case S_DEFAULT:
    case S_BIND:
    case S_LISTEN:
    case S_CONNECTING:{

    }
    default:
      assert(0);
  }

}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E
