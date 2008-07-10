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

/* Ethernet headers size */
#define SIZE_ETHERNET 14

/*
 * Function definitions
 */

//public

/* --- HTTP SNIFFING --- */

/* look for a cookie in the tcp payload */
inline unsigned char*
get_cookie (const unsigned char *payload, int len);

/* open pcap session */
pcap_t*
open_pcap_session (char *dev_name);

/* close pcap session */
void 
close_pcap_session (pcap_t * pcap);

/* returns the tcp payload for search the cookie inside it */
void 
get_tcp_payload (unsigned char *args,
		 const struct pcap_pkthdr *header,
		 const unsigned char *packet);

/* start http sniffer */
int 
start_sniffing (pcap_t * pcap);





//private

/* --- DEVICE MANAGEMENT --- */

/* get device ip address*/
static bpf_u_int32
device_get_ip_address (char *dev_name);

/* check device link type */
static int
device_check_link (pcap_t * pcap, char *dev_name);

/* --- OUTPUT METHODS ---*/

/*  prints legal banner */
static void 
print_banner (void);

/* prints monster usage syntax */
static void 
print_usage (void);


#endif /* fluidsnarfs.h */
