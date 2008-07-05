#ifndef __FLUIDSNARFS_H__
#define __FLUIDSNARFS_H__


/*
 * Application properties
 */

#define APP_NAME "fluidsnarfs"
#define APP_VERSION "0.1"
#define APP_DESC "I am a HTTP cookie eater monster who helps all of you in the middle"
#define APP_COPYRIGHT "Copyright (c) 2008 Sebastian Castillo Builes"
#define APP_DISCLAIMER "This program comes with ABSOLUTELY NO WARRANTY;\n\
This is free software, and you are welcome to redistribute it under\n\
conditions of the GNU General Public License as published by\n\
the Free Software Foundation, either version 3 of the License,\n\
or (at your option) any later version.\n"

/* --- DEFAULT STUFF --- */
#define ROOT_USER (0x0)
#define DEFAULT_PORT "80"



/*
 * Function definitions
 */


/* --- DEVICE MANAGEMENT --- */

/* get device ip address*/
static bpf_u_int32 device_get_inet4_addr(char *dev_name);

/* check device link type */
static int device_check_link(pcap_t *pcap, char *dev_name);



/* --- HTTP SNIFFING --- */

/* look for a cookie in the tcp payload */
unsigned char * seek_cookie(const unsigned char *payload, int len);

/* open pcap session */
static pcap_t * http_sniff_open_packets(char *dev_name, bpf_u_int32 dev_inet4_addr, char *pcap_filter);

/* reads HTTP packets. mmm... whit jummy cookies inside */
void http_sniff_read_packets(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

/* close pcap session */
static void http_sniff_close_packets(pcap_t *pcap);

/* start http sniffer */
static int http_sniff_packets(pcap_t * pcap);



/* --- OUTPUT METHODS ---*/

/*  prints legal banner */
void print_banner(void);

/* prints monster usage syntax */
void print_usage(void);




/*
 * TCP/IP headers structures
 */

/* Ethernet headers size */
#define SIZE_ETHERNET 14

/* Ethernet addresses size */
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct ethernet_header {
  unsigned char ether_dhost[ETHER_ADDR_LEN]; /* Dest host addr */
  unsigned char ether_shost[ETHER_ADDR_LEN]; /* Src host addr */
  unsigned short ether_type;                 /* Packet type: IP, ARP, etc... */
};

/* IP header */
struct ip_header {
  unsigned char  ip_vhl;         /* version, header length*/
  unsigned char  ip_tos;         /* Type of service */
  unsigned short ip_len;         /* Total package length */
  unsigned short ip_id;          /* Identification */
  unsigned short ip_off;         /* Fragment offset */
#define IP_RF 0x8000             /* reserved fragment flag */
#define IP_DF 0x4000             /* dont fragment flag */
#define IP_MF 0x2000             /* more fragments flag */
#define IP_OFFMASK 0x1fff        /* mask for fragmenting bits */
  u_char  ip_ttl;                /* time to live */
  u_char  ip_p;                  /* protocol */
  u_short ip_sum;                /* checksum */
  struct  in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef unsigned int tcp_seq;
struct tcp_header {
  unsigned short th_sport;       /* source port */
  unsigned short th_dport;       /* dest port */
  tcp_seq th_sec;                /* sequence number */
  tcp_seq th_ack;                /* acknowledge number */
  unsigned char th_offx2;         /* data offset */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
  unsigned char th_flags;        /* tcp flags */
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  unsigned short th_win;         /* window */
  unsigned short th_sum;         /* checksum */
  unsigned short th_urp;         /* urgent pointer */
};

#endif /* fluidsnarfs.h */
