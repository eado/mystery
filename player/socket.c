/* Credits: Xinyu Ma */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

char cmd[65537];
char ip_str[65537];
char buf[65537];

int main(){
  int sock = -1;
  struct sockaddr_in addr;
  socklen_t socklen;
  int port, buflen;

  setbuf(stdout, NULL);

  printf("INTERNAL BLOCK TOOLCHAIN. Type help for available commands.\n");

  for(printf("> "); fgets(cmd, sizeof(cmd), stdin) != NULL; printf("> ")){
    if(strncmp(cmd, "exit", 4) == 0){
      break;
    } else if(strncmp(cmd, "socket", 6) == 0){
      // Print code
      printf("sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);\n");

      // Create socket: IPv4 family, Stream socket, TCP protocol
      // Document: https://man7.org/linux/man-pages/man2/socket.2.html
      sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      printf("sock == %d\n", sock);
      // -1 means error
      if(sock == -1){
        printf("Error with code %d: %s\n", errno, strerror(errno));
      }
    } else if(strncmp(cmd, "connect", 7) == 0) {
      if(sscanf(cmd, "connect %d %s %d", &sock, ip_str, &port) != 3){
        printf("Usage: connect SOCKET IP PORT\n");
        printf("Example: connect 3 192.168.1.1 1234\n");
        continue;
      }

      // Print code
      printf("sockaddr_in addr;\n");
      printf("addr.sin_family = AF_INET;\n");
      printf("addr.sin_port = htons(%d);\n", port);
      printf("inet_pton(AF_INET, %s, &addr.sin_addr);\n", ip_str);

      // IPv4 family
      addr.sin_family = AF_INET;
      // Port number. Note that IP uses big-endian.
      addr.sin_port = htons(port);
      // Convert IP address from string to binary form
      if(!inet_pton(AF_INET, ip_str, &addr.sin_addr)){
        printf("Wrong IP address\n");
        continue;
      }

      // Print code
      printf("ret = connect(%d, (sockaddr*)&addr, sizeof(addr));\n", sock);

      // Connect to a server
      // Document: https://man7.org/linux/man-pages/man2/connect.2.html
      int ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
      printf("ret == %d\n", ret);
      if(ret == -1){
        printf("Error with code %d: %s\n", errno, strerror(errno));
      }
    } else if(strncmp(cmd, "bind", 4) == 0) {
      if(sscanf(cmd, "bind %d %s %d", &sock, ip_str, &port) != 3){
        printf("Usage: bind SOCKET IP PORT\n");
        printf("  use `any` for 0.0.0.0\n");
        printf("Example: bind 3 any 1234\n");
        continue;
      }

      // Print code
      printf("sockaddr_in addr;\n");
      printf("addr.sin_family = AF_INET;\n");
      printf("addr.sin_port = htons(%d);\n", port);

      addr.sin_family = AF_INET;
      addr.sin_port = htons(port);

      if(strcmp(ip_str, "any") == 0){
        printf("addr.sin_addr.s_addr = INADDR_ANY;\n");
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
      } else {
        printf("inet_pton(AF_INET, %s, &addr.sin_addr);\n", ip_str);
        if(!inet_pton(AF_INET, ip_str, &addr.sin_addr)){
          printf("Wrong IP address\n");
          continue;
        }
      }

      // Print code
      printf("ret = bind(%d, (sockaddr*)&addr, sizeof(addr));\n", sock);

      // Bind the address with the socket, as a server
      // Document: https://man7.org/linux/man-pages/man2/bind.2.html
      int ret = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
      printf("ret == %d\n", ret);
      if(ret == -1){
        printf("Error with code %d: %s\n", errno, strerror(errno));
      }
    } else if(strncmp(cmd, "listen", 6) == 0) {
      if(sscanf(cmd, "listen %d", &sock) != 1){
        printf("Usage: listen SOCKET\n");
        printf("Example: listen 3\n");
        continue;
      }

      // Print code
      printf("ret = listen(%d, 0);\n", sock);

      // Listen to connection, with minimal backup queue
      int ret = listen(sock, 0);
      printf("ret == %d\n", ret);
      if(ret == -1){
        printf("Error with code %d: %s\n", errno, strerror(errno));
      }
    } else if(strncmp(cmd, "accept", 6) == 0) {
      if(sscanf(cmd, "accept %d", &sock) != 1){
        printf("Usage: accept SOCKET\n");
        printf("Example: accept 3\n");
        continue;
      }

      // Print code
      printf("socklen = sizeof(addr);\n");
      printf("new_sock = accept(%d, (sockaddr*)&addr, &socklen);\n", sock);

      // Accept a connection
      // Document: https://man7.org/linux/man-pages/man2/accept.2.html
      // addr will contain the client's IP address and port
      socklen = sizeof(addr);
      int new_sock = accept(sock, (struct sockaddr*)&addr, &socklen);
      printf("new_sock == %d\n", new_sock);
      if(new_sock == -1){
        printf("Error with code %d: %s\n", errno, strerror(errno));
        continue;
      }
      inet_ntop(AF_INET, &addr.sin_addr, ip_str, socklen);
      printf("Client IP address: %s port: %d\n", ip_str, ntohs(addr.sin_port));
      printf("Now use socket %d to communicate with the client\n", new_sock);
    } else if(strncmp(cmd, "send", 4) == 0) {
      if(sscanf(cmd, "send %d %[^\n]", &sock, buf) != 2){
        printf("Usage: send SOCKET STRING\n");
        printf("Example: send 3 GET /\n");
        continue;
      }

      // Print code
      printf("ret = send(%d, \"%s\", %lu, 0);\n", sock, buf, strlen(buf));

      // Send data to the socket (you may also use write)
      // Document: https://man7.org/linux/man-pages/man2/send.2.html
      // Length is strlen(buf)
      // The last argument is flag, can be ignored for now
      int ret = send(sock, buf, strlen(buf), 0);
      printf("ret == %d\n", ret);
      if(ret == -1){
        printf("Error with code %d: %s\n", errno, strerror(errno));
      } else {
        printf("Sent %d bytes\n", ret);
      }
    } else if(strncmp(cmd, "recv", 4) == 0) {
      if(sscanf(cmd, "recv %d %d", &sock, &buflen) != 2){
        printf("Usage: recv SOCKET BUFFER-LENGTH\n");
        printf("Example: recv 3 2000\n");
        continue;
      }
      if(buflen < 0){
        buflen = 0;
      } else if (buflen > (int)sizeof(buf)) {
        buflen = sizeof(buf);
      }

      // Print code
      printf("ret = recv(%d, buf, %d, 0);\n", sock, buflen);

      // Receive data from the socket (you may also use read)
      // Document: https://man7.org/linux/man-pages/man2/recv.2.html
      // The last argument is flag, can be ignored for now
      int ret = recv(sock, buf, buflen, 0);
      printf("ret == %d\n", ret);
      if(ret == -1){
        printf("Error with code %d: %s\n", errno, strerror(errno));
      } else {
        buf[ret] = 0;  // Adding a tailing '\0' for print
        printf("Received %d bytes\n", ret);
        printf("buf: %s\n", buf);
      }
    } else if(strncmp(cmd, "close", 5) == 0) {
      if(sscanf(cmd, "close %d", &sock) != 1){
        printf("Usage: close SOCKET\n");
        printf("Example: close 3\n");
        continue;
      }

      // Print code
      printf("ret = close(%d);\n", sock);

      // Shutdown socket
      int ret = close(sock);
      printf("ret == %d\n", ret);
      if(ret == -1){
        printf("Error with code %d: %s\n", errno, strerror(errno));
      }
      sock = -1;
    } else {
      printf("Unknown command: %s\n", cmd);
      printf("Supported: socket, bind, listen, accept, connect, send, recv, close\n");
    }
  }
  return 0;
}
