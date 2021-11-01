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
void TCPAssignment::set_packet(const Socket* socket, Packet* pkt, uint8_t flag, uint8_t* data){

  IP_Header i_header;
  TCP_Header t_header;
  uint8_t packet_buffer[PACKET_SIZE];
  i_header.src_ip = socket->host_address.sin_addr.s_addr;
  i_header.dest_ip = socket->peer_address.sin_addr.s_addr;
  t_header.src_port = socket->host_address.sin_port;
  t_header.dest_port = socket->peer_address.sin_port;
  t_header.seq_num = htonl(socket->seq_base); 
  t_header.ack_num = htonl(socket->ack_base); 
  t_header.flag = flag; 
  t_header.checksum = 0;
  memcpy(packet_buffer+TCP_START, &t_header, 20);
  memcpy(packet_buffer+DATA_START, data, pkt->getSize()-DATA_START);
  t_header.checksum = htons(~NetworkUtil::tcp_sum(i_header.src_ip, i_header.dest_ip,
                              &packet_buffer[TCP_START], pkt->getSize() - TCP_START));

  pkt -> writeData(IP_START, &i_header, sizeof(i_header));
  //pkt -> writeData(IP_START+12, &(i_header.src_ip), 8);
  pkt -> writeData(TCP_START, &t_header, 20);
  pkt -> writeData(DATA_START, data, pkt->getSize() - DATA_START);
}

// call with socket trying to connecting
void TCPAssignment::try_connect(Socket* socket){
  /*printf("src ip: %d, port: %d, dest ip: %d, port: %d.\n", ntohl(socket->host_address.sin_addr.s_addr),
    ntohs(socket->host_address.sin_port), ntohl(socket->peer_address.sin_addr.s_addr), ntohs(socket->peer_address.sin_port));*/

  assert(socket->state == S_CONNECTING);
  Packet pkt (DATA_START);  
  //TCP_Header t_header = {.flag = SYNbit};
  set_packet(socket, &pkt, SYNbit, nullptr);
  //uint8_t buffer[1000];
  //pkt.readData(0, buffer, DATA_START); 
  //TCP_Header* t_header2 = (TCP_Header*) &buffer[TCP_START];
  //printf("sendnum: %d,\n", ntohl(t_header2->seq_num));
  socket->start_time = HostModule::getCurrentTime();
  socket->timer_key = addTimer(socket, socket->timeout_interval);
  sendPacket("IPv4", pkt);  
  return;
}

// call with socket trying to connecting
void TCPAssignment::try_accept(Socket* socket){
  /*printf("src ip: %d, port: %d, dest ip: %d, port: %d.\n", ntohl(socket->host_address.sin_addr.s_addr),
    ntohs(socket->host_address.sin_port), ntohl(socket->peer_address.sin_addr.s_addr), ntohs(socket->peer_address.sin_port));*/

  assert(socket->state == S_ACCEPTING);
  Packet pkt (DATA_START);  
  //TCP_Header t_header = {.flag = SYNbit | ACKbit};
  set_packet(socket, &pkt, SYNbit | ACKbit, nullptr);
  socket->start_time = HostModule::getCurrentTime();
  socket->timer_key = addTimer(socket, socket->timeout_interval);
  sendPacket("IPv4", pkt);  
  return;
}

// call with socket trying to writ
void TCPAssignment::try_write(Socket* socket, bool timeout){
  /*printf("src ip: %d, port: %d, dest ip: %d, port: %d.\n", ntohl(socket->host_address.sin_addr.s_addr),
    ntohs(socket->host_address.sin_port), ntohl(socket->peer_address.sin_addr.s_addr), ntohs(socket->peer_address.sin_port));*/
  assert(socket->state == S_CONNECTED);

 // printf("wrinting\n");
  if (timeout){
    socket->sent_top = socket->send_base;
  }
  if (socket->sent_top == socket->send_base){
    socket->start_time = HostModule::getCurrentTime();
    socket->timer_key = addTimer(socket, socket->timeout_interval);
  }

  //printf("top:: %d, base: %d, sent: %d, wdw: %d\n", socket->send_top, socket->send_base, socket->sent_top, socket->rcv_wdw);
  size_t wdw_top = socket->send_base + socket->rcv_wdw;
  size_t base = socket->sent_top > socket->send_base ? socket->sent_top : socket->send_base;
  size_t size = socket->send_top < wdw_top ? socket->send_top - base : wdw_top -base;

  if (size == 0) return;
 // printf("do writing! size: %d\n", size);

  size_t offset = 0;
  if (socket->sent_top > socket->send_base){
    offset = socket->sent_top - socket->send_base;
  } else if (socket->sent_top < socket->send_base){
    offset = BUFFER_SIZE - socket->send_base + socket->sent_top;
  }

  Packet pkt (DATA_START + size);  
  uint8_t data_buffer[size];
  size_t first = base + size < BUFFER_SIZE ? size : BUFFER_SIZE - base;
  size_t second = size - first;
  memcpy(data_buffer, socket->send_buffer+base, first);
  memcpy(&data_buffer[first], socket->send_buffer, second);
  socket->seq_base += offset;
  set_packet(socket, &pkt, ACKbit, data_buffer);
  socket->seq_base -= offset;
  sendPacket("IPv4", pkt);  

  socket->sent_top = (base + size) % BUFFER_SIZE;
 // printf("sent top is : %d, offset is %d\n", socket->sent_top, offset);

  if (socket->called == C_WRITE){
    printf("dd\n");
    //socket->called = C_DEFAULT;
    
  }
  return;
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  //printf("string: %s, uint: %d\n", "10.0.1.4", inet_addr("10.0.1.4"));
  //printf("b");
  // Remove below
  // (void)syscallUUID;
  // (void)pid;
 // printf("uuid: %ld, syscall: %d, pid: %d\n", syscallUUID, param.syscallNumber, pid);
 //printf("syscal : %d\n", param.syscallNumber);
  switch (param.syscallNumber) {
  case SOCKET: {
    // this->syscall_socket(syscallUUID, pid, param.param1_int,
    // param.param2_int, param.param3_int);    
    assert(param.param1_int == AF_INET);  // domain
    assert(param.param2_int == SOCK_STREAM);  // type
    assert(param.param3_int == IPPROTO_TCP);  // protocol

    int socket_descriptor = createFileDescriptor(pid);
    assert(socket_descriptor > -1);
//  printf("open syscall: %d, pid: %d\n", socket_descriptor, pid); 
    int map_key = pid * 10 + socket_descriptor;
    Socket* new_socket = new Socket(pid, socket_descriptor);
    new_socket->pid = pid;
    assert(socket_map.find(map_key) == socket_map.end());
    socket_map[map_key] = new_socket;

    returnSystemCall(syscallUUID, socket_descriptor);
    break;
  }
  case CLOSE:{
   // printf("close doing\n");
    // this->syscall_close(syscallUUID, pid, param.param1_int);
    int socket_descriptor = param.param1_int;
    int map_key = pid * 10 + socket_descriptor;
//  printf("close syscall: %d, pid: %d\n", socket_descriptor, pid); 
    if (socket_map.find(map_key) == socket_map.end()){
      returnSystemCall(syscallUUID, -1);
    }
    else {
      Socket *socket=socket_map[map_key];
      if (socket->send_full || socket->send_base != socket->send_top){
        socket->called = C_CLOSE;
        socket->syscallUUID = syscallUUID;
        break;
      }
      switch (socket->state) {
      case S_CLOSE_WAIT:{
        Packet pkt (DATA_START);  
        //t_header->flag = FINbit;
        socket->close_available=true;
        //Additional t_header initialize?
        
        //socket sequence number random??
        set_packet(socket, &pkt, FINbit, nullptr);
        sendPacket("IPv4", pkt); 
        socket->seq_base++; //CHECK!!!!
      }
      case S_CONNECTED:{
        Packet pkt (DATA_START);  
        //t_header->flag = FINbit;
        socket->state=S_FINWAIT1;//FIN WAIT1
        //Additional t_header initialize?
        //socket sequence number random??
        set_packet(socket, &pkt, FINbit, nullptr);
        sendPacket("IPv4", pkt); 
        socket->seq_base++;
        break;
      }
      default:
          removeFileDescriptor(pid, socket_descriptor);
          delete(socket_map[map_key]);
          socket_map.erase(map_key);
          returnSystemCall(syscallUUID, 0);
      }

    }
    break;
  }
  case READ:{
    // this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr,
    // param.param3_int);
    int socket_descriptor = param.param1_int;
    uint8_t* buffer = (uint8_t*) param.param2_ptr;
    size_t size = param.param3_int;

    int map_key = pid * 10 + socket_descriptor;
    if (socket_map.find(map_key) == socket_map.end()){
   //   printf("dont come\n");
      returnSystemCall(syscallUUID, -1);
      break;
    }
  //  printf("read ding\n");
    struct Socket* socket = socket_map[map_key];
    assert(socket->state == S_CONNECTED);
    if (socket->recv_base != socket->recv_top){
      if (socket->recv_base > socket->recv_top){
        if (socket->recv_base + size <= BUFFER_SIZE){
          memcpy(buffer, socket->recv_buffer+socket->recv_base, size);
          socket->recv_base += size;
        } else {
          size_t read_byte = BUFFER_SIZE - socket->recv_base;
          memcpy(buffer, socket->recv_buffer+socket->recv_base, read_byte);
          size -= read_byte;
          size = size < socket->recv_top ? size : socket->recv_top;
          memcpy(buffer, socket->recv_buffer, size);
          socket->recv_base = size;
          size += read_byte;
        }
      } 
      if (socket->recv_base < socket->recv_top){
        size = size < socket->recv_top-socket->recv_base ? size : socket->recv_top-socket->recv_base;
        memcpy(buffer, socket->recv_buffer+socket->recv_base, size);
        socket->recv_base += size;
      }
    //  printf("dont come\n");
      returnSystemCall(syscallUUID, size);
      break;
    }
    
    socket->called = C_READ;
    socket->syscallUUID = syscallUUID;
    socket->syscall_ptr = buffer;
    socket->syscall_int = size;
    assert(socket->state == S_CONNECTED);
  //  printf("read waiting\n");
    break;
  }
  case WRITE:{
    // this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr,
    // param.param3_int); 
    //printf(" writning\n");
    int socket_descriptor = param.param1_int;
    uint8_t* buffer = (uint8_t*) param.param2_ptr;
    size_t size = param.param3_int;
    int map_key = pid * 10 + socket_descriptor;
    if (socket_map.find(map_key) == socket_map.end()){
   //   printf("size: sss%d\n", size);
      returnSystemCall(syscallUUID, -1);
      break;
    }
    struct Socket* socket = socket_map[map_key];

    if (!socket->send_full){
      size_t& send_top = socket->send_top;
      size_t& send_base = socket->send_base;

      if (send_base <= send_top){
        size_t first = send_top + size < BUFFER_SIZE ? size : BUFFER_SIZE - send_top;
        size_t second = size - first <= send_base ? size - first : send_base;
        //printf("first and second: %d, %d\n", first, second);
        memcpy(socket->send_buffer + send_top, buffer, first);
        memcpy(socket->send_buffer, &buffer[first], second);
        send_top += first + second;
        send_top = send_top < BUFFER_SIZE ? send_top : send_top - BUFFER_SIZE;
        size = first+second;
      } else {  //if (send_base > send_top)
        size = send_top + size < send_base ? size : send_base - send_top;
    //    printf("send base > send_top : %d", size);
        memcpy(socket->send_buffer + send_top, buffer, size);
        send_top += size;
      }
      if (size != 0 && send_base == send_top) socket->send_full = true;
     // printf("size: %d\n", size);
      returnSystemCall(syscallUUID, size);
      try_write(socket, false);
      break;
    } 

  //  printf("no space on writning\n");
    socket->called = C_WRITE;
    socket->syscallUUID = syscallUUID;
    socket->syscall_ptr = buffer;
    socket->syscall_int = size;
    
    break;
  }
  case CONNECT: {
    // this->syscall_connect(syscallUUID, pid, param.param1_int,
    //		static_cast<struct sockaddr*>(param.param2_ptr),
    //(socklen_t)param.param3_int);
    int socket_descriptor = param.param1_int;
    int map_key = pid * 10 + socket_descriptor;
    if (socket_map.find(map_key) != socket_map.end()){
      struct Socket* socket = socket_map[map_key];
      const sockaddr_in* dest_addr = 	static_cast<struct sockaddr_in*>(param.param2_ptr);
      if(socket->state != S_BIND){
        // should bind with arbitrary adrress;
        //char char_ip[INET_ADDRSTRLEN];
        //uint8 uns_char_ip[4] = 
        //inet_ntop(AF_INET, &(dest_addr->sin_addr), char_ip, INET_ADDRSTRLEN);
        ipv4_t dest_ip = NetworkUtil::UINT64ToArray<4>(dest_addr->sin_addr.s_addr);
        int nic_port = getRoutingTable(dest_ip);
        std::optional<ipv4_t> ip_option = getIPAddr(nic_port); // retrieve the source IP address
        assert(ip_option.has_value());
        ipv4_t src_ip = ip_option.value();
    /*    char str_buffer[128];
        snprintf(str_buffer, sizeof(str_buffer), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
        std::string str_ip(str_buffer); */
        sockaddr_in src_addr = {.sin_family = AF_INET};
        src_addr.sin_addr.s_addr = NetworkUtil::arrayToUINT64<4>(src_ip);//inet_addr(str_ip.c_str());
        src_addr.sin_port = htons(5000);
        while (find_socket(&src_addr, nullptr) != -1){
          src_addr.sin_port = htons(ntohs(src_addr.sin_port) + 1);
        }
        socket->host_address = src_addr;
      }
      socket->state = S_CONNECTING;
      socket->syscallUUID = syscallUUID;
      socket->peer_address = *dest_addr;
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
      if(socket->connected_queue.size()!=0){
        Socket *new_socket= socket->connected_queue.front();
        socket->connected_queue.pop();
        assert(new_socket->state == S_BLOCKED);
        new_socket->state=S_CONNECTED;
        memcpy(param.param2_ptr, &socket->peer_address, sizeof(struct sockaddr));
        *static_cast<socklen_t *>(param.param3_ptr) = sizeof(struct sockaddr);
        returnSystemCall(syscallUUID, new_socket->sd);
      } else {
        if (socket->back_count==0){
          int new_sd = createFileDescriptor(pid);
          int new_key = pid * 10 + new_sd;
          Socket * new_socket= new Socket(pid, new_sd);
          new_socket->state = S_BLOCKED;
          assert(socket_map.find(new_key) == socket_map.end());
          socket_map[new_key] = new_socket;
          socket->accepted_socket = new_socket;
          socket->back_count++;
        }
        socket->called = C_ACCEPT;
        socket->syscallUUID = syscallUUID;
        socket->syscall_ptr = param.param2_ptr;
        socket->return_addr_len = static_cast<socklen_t*>(param.param3_ptr);
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
   //   printf("not find sock name???: \n");
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
 //     printf("not find???: \n");
    if (socket_map.find(map_key) != socket_map.end()){
      struct Socket* socket = socket_map[map_key];
   //   printf("socket state: %d\n", socket->state);
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
  
  uint8_t packet_buffer[PACKET_SIZE];
  int pkt_size = packet.getSize();
  packet.readData(0, packet_buffer, pkt_size); 
  IP_Header* i_header = (IP_Header*) &packet_buffer[IP_START];
  TCP_Header* t_header = (TCP_Header*) &packet_buffer[TCP_START];
  uint16_t checksum = t_header->checksum;
  t_header->checksum = 0;
  if (ntohs(checksum) & NetworkUtil::tcp_sum(i_header->src_ip, i_header->dest_ip,
               &packet_buffer[TCP_START], pkt_size-TCP_START))  return;

  sockaddr_in src_addr = {.sin_family = AF_INET, .sin_port = t_header->src_port, .sin_addr = in_addr{i_header->src_ip}};
  sockaddr_in dest_addr = {.sin_family = AF_INET, .sin_port = t_header->dest_port, .sin_addr = in_addr{i_header->dest_ip}};

  int map_key = find_socket(&dest_addr, &src_addr); 
  if (map_key == -1){
    map_key = find_socket(&dest_addr, nullptr);
    if (map_key == -1){
      //printf("-1 arrived => ip: %d, port: %d.\n", dest_addr.sin_addr, dest_addr.sin_port);
      //assert(0);
      return;
    }  
  }

  Socket* socket = socket_map[map_key];
 /* printf("src ip: %d, port: %d, dest ip: %d, port: %d.\n", ntohl(src_addr.sin_addr.s_addr),
    ntohs(src_addr.sin_port), ntohl(dest_addr.sin_addr.s_addr), ntohs(dest_addr.sin_port));*/
//  printf("recieevd seq: %d, ack: %d, pid: %d, flag: %x\n",
 //  ntohl(t_header->seq_num), ntohl(t_header->ack_num), socket->pid, t_header->flag);
 /// printf("state: %d\n", socket->state);
  socket->rcv_wdw = ntohs(t_header->recv_wdw) / 100;
  switch (socket->state) {
    case S_DEFAULT: case S_BIND:
      break;
    case S_LISTEN:{
    //  printf("listening?\n");
      if ((socket->called != C_ACCEPT) && (socket->back_count >= socket->backlog)) break;
      if (t_header->flag&SYNbit){
        Socket* new_socket;
        if (socket->accepted_socket){
          new_socket = socket->accepted_socket;
          assert(new_socket->state == S_BLOCKED);
          socket->accepted_socket = nullptr;
        } else {
          int socket_descriptor = createFileDescriptor(socket->pid);
          new_socket = new Socket(socket->pid, socket_descriptor);
          int new_key = new_socket->pid * 10 + new_socket->sd;
          assert(socket_map.find(new_key) == socket_map.end());
          socket_map[new_key] = new_socket;
        }
        assert(new_socket->state != S_CONNECTED);
        new_socket->host_address = dest_addr;
        new_socket->peer_address = src_addr;
        new_socket->state = S_ACCEPTING;
        new_socket->ack_base =  ntohl(t_header->seq_num) + 1;
        new_socket->listen_key = map_key;

        try_accept(new_socket);
        socket->back_count++;
      } 
      break;
    }
    case S_CONNECTING:{
      //printf("connecting\n");
      if(t_header->flag == (SYNbit | ACKbit)){
 //     printf("syn ack backed\n");
   //   printf("returned ack: %d, current send: %d", ntohs(t_header->ack_num), socket->seq_base +1 );
        if (ntohl(t_header->ack_num) == socket->seq_base +1){
          socket->seq_base++;
          socket->ack_base = ntohl(t_header->seq_num)+1;
          socket->state = S_CONNECTED;
          Packet pkt (DATA_START);  
          //t_header->flag = ACKbit;
          set_packet(socket, &pkt, ACKbit, nullptr);
          sendPacket("IPv4", pkt);  

          cancelTimer(socket->timer_key);
          //time rtt = HostModule::getCurrentTime() - socket->start_time;
          returnSystemCall(socket->syscallUUID, 0);
        }
      } else if (t_header->flag == SYNbit){
          socket->ack_base = ntohl(t_header->seq_num)+1;
          Packet pkt (DATA_START);  
          //t_header->flag = SYNbit | ACKbit;
          set_packet(socket, &pkt, SYNbit | ACKbit, nullptr);
          sendPacket("IPv4", pkt);  
      } else if (t_header->flag&ACKbit){
          socket->seq_base++;
          socket->state = S_CONNECTED;
          cancelTimer(socket->timer_key);
          returnSystemCall(socket->syscallUUID, 0);
      } /*else {
        assert(pkt_size > DATA_START);
        socket->state = S_BIND;
        cancelTimer(socket->timerKey);
        returnSystemCall(socket->syscallUUID, -1);
      } */
      break;
    }
    case S_ACCEPTING:{
      if(t_header->flag&ACKbit && ntohl(t_header->seq_num) == socket->ack_base){
        cancelTimer(socket->timer_key);
        socket->seq_base++;
        int listenkey=socket->listen_key;
        Socket* listensk =socket_map[listenkey];
        listensk->back_count--;
        if (listensk->called == C_ACCEPT){
          listensk->called = C_NONE;
          socket->state = S_CONNECTED;
          memcpy(listensk->syscall_ptr, &socket->peer_address, sizeof(struct sockaddr));
          *(listensk->return_addr_len) = sizeof(struct sockaddr);
      //    printf("uuid: %ld, sd: %d\n", listensk->syscallUUID, socket->sd);
          returnSystemCall(listensk->syscallUUID, socket->sd);
        } else {
          socket->state=S_BLOCKED;
          listensk->connected_queue.push(socket);
        }
      }
      break;
    }
    case S_CONNECTED:{
    //  printf("reading came, seqnum: %d, ack base : %d\n", ntohl(t_header->seq_num), socket->ack_base );
      if(ntohl(t_header->seq_num) == socket->ack_base){          
        if(t_header->flag&FINbit){ //I didn't close.. but fin recieved
          //printf("fin recived\n");
          socket->ack_base=ntohl(t_header->seq_num)+1;
          socket->state=S_CLOSE_WAIT;
          Packet pkt (DATA_START);
          //t_header->flag = ACKbit;
          set_packet(socket, &pkt, ACKbit, nullptr);
          sendPacket("IPv4", pkt); 
          socket->seq_base++;
          break;
        }

        // case write
   //     printf("ack come: \n");
    //    printf("ack num : %d, seq_base : %d\n", ntohl(t_header->ack_num) , socket->seq_base);
        if (ntohl(t_header->ack_num) > socket->seq_base){
     //     printf("ack!!");
          cancelTimer(socket->timer_key);
          size_t offset = ntohl(t_header->ack_num) - socket->seq_base;
          socket->seq_base += offset;
          socket->send_base += offset;
          try_write(socket, false);
          break;
        }

      //printf("base: %d, top: %d\n", socket->recv_base, socket->recv_top);

        // case read
        int data_start = DATA_START;
        int data_size = pkt_size - DATA_START;

        if (socket->called == C_READ){
          size_t read_size = data_size < socket->syscall_int ? data_size : socket->syscall_int;
          memcpy(socket->syscall_ptr, &packet_buffer[data_start], read_size);
    //      printf("read size: %d\n", read_size);
          returnSystemCall(socket->syscallUUID, read_size);
          socket->called = C_NONE;
          data_start += read_size;
          data_size -= read_size;
          socket->ack_base += read_size;
        }
        //printf("data size: %d\n", data_size);
        void* recv_top = socket->recv_buffer + socket->recv_top;
        if (socket->recv_top + data_size <= BUFFER_SIZE){
          memcpy(recv_top, &packet_buffer[data_start], data_size);
          socket->recv_top += data_size;
        } else {
          size_t first = BUFFER_SIZE - socket->recv_top;
          size_t second = data_size - first;
          memcpy(recv_top, &packet_buffer[data_start], first);
          memcpy(socket->recv_buffer, &packet_buffer[data_start+first], second);
          socket->recv_top = second;
        }
        socket->ack_base += data_size;
      }

      Packet pkt (DATA_START);
      //t_header->flag = ACKbit;
      set_packet(socket, &pkt, ACKbit, nullptr);
      sendPacket("IPv4", pkt); 
      break;
    }
    case S_FINWAIT1:{
     // printf("finwai\n");
      if(t_header->flag&FINbit && t_header->flag&ACKbit){//FINWAIT1 stimulous
        if (ntohl(t_header->ack_num)==socket->seq_base){
        socket->ack_base =  ntohl(t_header->seq_num) + 1;
        Packet pkt (DATA_START);  
        //t_header->flag = ACKbit;
        set_packet(socket, &pkt, ACKbit, nullptr);
        sendPacket("IPv4", pkt);  

        //timewait ???? how???

        removeFileDescriptor(socket->pid, socket->sd);
        delete(socket_map[map_key]);
        socket_map.erase(map_key);
        returnSystemCall(socket->syscallUUID, 0);
      }}
      else if( !socket->close_available && (t_header->flag)&FINbit ){//FINWAit -> close
        socket->ack_base =  ntohl(t_header->seq_num) + 1;
        Packet pkt (DATA_START);  
        t_header->flag = ACKbit;
        set_packet(socket, &pkt, ACKbit, nullptr);
        sendPacket("IPv4", pkt); 
        socket->seq_base++;
        socket->close_available=true;
      }
      else if( !socket->close_available && (ntohl(t_header->flag)&ACKbit) ){//FINWAIT1->FINWAIT2
      if (ntohl(t_header->ack_num)==socket->seq_base){
        socket->close_available=true;
      }}
      else if( socket->close_available ){ //FINWAIT2 or close
      ///close case
        if ( (ntohl(t_header->flag)&ACKbit) && ntohl(t_header->ack_num)==socket->seq_base){}
      ///FINWAIT2 case
        else if((t_header->flag)&FINbit){ 
          socket->ack_base =  ntohl(t_header->seq_num) + 1;
          Packet pkt (DATA_START);  
          //t_header->flag = ACKbit;
          set_packet(socket, &pkt, ACKbit, nullptr);
          sendPacket("IPv4", pkt); 
          socket->seq_base++;
        }
      //None of them 
        else{break;}

        //timewait

        removeFileDescriptor(socket->pid, socket->sd);
        delete(socket_map[map_key]);
        socket_map.erase(map_key);
        returnSystemCall(socket->syscallUUID, 0);
      }
      break;
    }
    case S_CLOSE_WAIT:{
      //printf("close waiit\n");
      //printf("%d\n",ntohl(t_header->ack_num) == socket->seq_base);
      if(!socket->close_available){break;}
      if( (t_header->flag&ACKbit) && ntohl(t_header->ack_num) == socket->seq_base ){
        removeFileDescriptor(socket->pid, socket->sd);
        delete(socket_map[map_key]);
        socket_map.erase(map_key);
        returnSystemCall(socket->syscallUUID, 0);
      }
      break;
    }
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
 /* switch(socket->state){
    case S_DEFAULT: case S_BIND: case S_LISTEN: case S_ACCEPTING:
      assert(0);
      break;
    case 
    case S_CONNECTED: case S_BLOCKED: 
  S_CLOSE_WAIT,
  S_FINWAIT1,
  }*/
  if (socket->state == S_CONNECTING){
    try_connect(socket);
  } else if (socket->state == S_ACCEPTING) {
    try_accept(socket);
  } else {
   // printf("write timeout state: %d\n", socket->state);
    if (socket->state == S_CONNECTED) {
     // printf("try write doing\n");
      try_write(socket, true);
    }
  }
}

} // namespace E
