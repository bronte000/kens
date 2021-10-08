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
  case CONNECT:{
    // this->syscall_connect(syscallUUID, pid, param.param1_int,
    //		static_cast<struct sockaddr*>(param.param2_ptr),
    //(socklen_t)param.param3_int);
    int socket_descriptor = param.param1_int;
    int map_key = pid * 10 + socket_descriptor;
    int validance = -1; 
    if (socket_map.find(map_key) != socket_map.end()){
      struct Socket* socket = socket_map[map_key];
      validance = 0;
    }
    returnSystemCall(syscallUUID, validance);
    break;
  }
  case LISTEN:
    // this->syscall_listen(syscallUUID, pid, param.param1_int,
    // param.param2_int);
    break;
  case ACCEPT:
    // this->syscall_accept(syscallUUID, pid, param.param1_int,
    //		static_cast<struct sockaddr*>(param.param2_ptr),
    //		static_cast<socklen_t*>(param.param3_ptr));
    break;
  case BIND: {
    // this->syscall_bind(syscallUUID, pid, param.param1_int,
    //		static_cast<struct sockaddr *>(param.param2_ptr),
    //		(socklen_t) param.param3_int);
    const struct sockaddr_in* socket_address = (const sockaddr_in*) param.param2_ptr;
    assert(socket_address->sin_family == AF_INET);
    int socket_descriptor = param.param1_int;
    int map_key = pid * 10 + socket_descriptor;
    int validance = -1; 
    // Should check whether it uses the dupplicate address!
    if (socket_map.find(map_key) != socket_map.end()){
      struct Socket* socket = socket_map[map_key];
      assert(socket->sin_family == AF_INET);
      if (socket->sin_port == 0) {
        int check=0;
        for (auto iter = socket_map.begin() ; iter != socket_map.end(); iter++) {
          if(
            (socket_address->sin_port==(iter->second->sin_port))&&(
            ((iter->second->sin_addr.s_addr)==htonl(INADDR_ANY))||
            (socket_address->sin_addr.s_addr==htonl(INADDR_ANY))||
            (socket_address->sin_addr.s_addr==(iter->second->sin_addr.s_addr)))
                    ){
          check=1;}
        }
        if(check==0){
        socket->sin_port = socket_address->sin_port;
        socket->sin_addr = socket_address->sin_addr;
        validance=0;
        }
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
      if (socket->sin_port != 0) {
        memcpy(param.param2_ptr, socket, sizeof(struct sockaddr));
        *static_cast<socklen_t *>(param.param3_ptr) = sizeof(struct sockaddr);
        validance = 0;
      }
    }
    returnSystemCall(syscallUUID, validance);
    break;
  }
  case GETPEERNAME:
    // this->syscall_getpeername(syscallUUID, pid, param.param1_int,
    //		static_cast<struct sockaddr *>(param.param2_ptr),
    //		static_cast<socklen_t*>(param.param3_ptr));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  (void)fromModule;
  (void)packet;
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E
