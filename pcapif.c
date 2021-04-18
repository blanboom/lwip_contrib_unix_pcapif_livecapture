/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#ifndef linux  /* Apparently, this doesn't work under Linux. */

#include "lwip/debug.h"

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap.h>

#include "netif/etharp.h"
#include "netif/pcapif.h"

#include "lwip/stats.h"

#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "netif/unixif.h"
#include "lwip/sys.h"
#include "lwip/timers.h"
#include "lwip/snmp.h"

#include "lwip/ip.h"

#if defined(LWIP_DEBUG) && defined(LWIP_TCPDUMP)
#include "netif/tcpdump.h"
#endif /* LWIP_DEBUG && LWIP_TCPDUMP */

struct pcapif {
  pcap_t *pd;
};

static char errbuf[PCAP_ERRBUF_SIZE];

/*-----------------------------------------------------------------------------------*/
static err_t
pcapif_output(struct netif *netif, struct pbuf *p)
{
    // ref: contrib/ports/win32/pcapif.c
    struct pbuf *q;
    unsigned char buffer[1520];
    unsigned char *buf = buffer;
    unsigned char *ptr;
    struct eth_hdr *ethhdr;
    u16_t tot_len = p->tot_len - ETH_PAD_SIZE;
    struct pcapif *pa = (struct pcapif*)netif->state;

#if defined(LWIP_DEBUG) && LWIP_NETIF_TX_SINGLE_PBUF
    LWIP_ASSERT("p->next == NULL && p->len == p->tot_len", p->next == NULL && p->len == p->tot_len);
#endif

    /* initiate transfer */
    if (p->len == p->tot_len) {
        /* no pbuf chain, don't have to copy -> faster */
        buf = &((unsigned char*)p->payload)[ETH_PAD_SIZE];
    } else {
        /* pbuf chain, copy into contiguous buffer */
        if (p->tot_len >= sizeof(buffer)) {
            LINK_STATS_INC(link.lenerr);
            LINK_STATS_INC(link.drop);
            snmp_inc_ifoutdiscards(netif);
            return ERR_BUF;
        }
        ptr = buffer;
        for(q = p; q != NULL; q = q->next) {
            /* Send the data from the pbuf to the interface, one pbuf at a
               time. The size of the data in each pbuf is kept in the ->len
               variable. */
            /* send data from(q->payload, q->len); */
            LWIP_DEBUGF(NETIF_DEBUG, ("netif: send ptr %p q->payload %p q->len %i q->next %p\n", ptr, q->payload, (int)q->len, (void*)q->next));
            if (q == p) {
                memcpy(ptr, &((char*)q->payload)[ETH_PAD_SIZE], q->len - ETH_PAD_SIZE);
                ptr += q->len - ETH_PAD_SIZE;
            } else {
                memcpy(ptr, q->payload, q->len);
                ptr += q->len;
            }
        }
    }

    /* signal that packet should be sent */
    if (pcap_sendpacket(pa->pd, buf, tot_len) < 0) {
        LINK_STATS_INC(link.memerr);
        LINK_STATS_INC(link.drop);
        snmp_inc_ifoutdiscards(netif);
        return ERR_BUF;
    }

    LINK_STATS_INC(link.xmit);
    snmp_add_ifoutoctets(netif, tot_len);
    ethhdr = (struct eth_hdr *)p->payload;
    if ((ethhdr->dest.addr[0] & 1) != 0) {
        /* broadcast or multicast packet*/
        snmp_inc_ifoutnucastpkts(netif);
    } else {
        /* unicast packet */
        snmp_inc_ifoutucastpkts(netif);
    }
    return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
static struct pbuf *
pcapif_low_level_input(struct netif *netif, const void *packet, int packet_len)
{
    struct pbuf *p, *q;
    int start;
    int length = packet_len;
    struct eth_addr *dest = (struct eth_addr*)packet;
    struct eth_addr *src = dest + 1;
    int unicast;
    const u8_t bcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const u8_t ipv4mcast[] = {0x01, 0x00, 0x5e};
    const u8_t ipv6mcast[] = {0x33, 0x33};

    /* Don't let feedback packets through (limitation in winpcap?) */
    if(!memcmp(src, netif->hwaddr, ETHARP_HWADDR_LEN)) {
        /* don't update counters here! */
        return NULL;
    }

    /* MAC filter: only let my MAC or non-unicast through (pcap receives loopback traffic, too) */
    unicast = ((dest->addr[0] & 0x01) == 0);
    if (memcmp(dest, &netif->hwaddr, ETHARP_HWADDR_LEN) &&
        (memcmp(dest, ipv4mcast, 3) || ((dest->addr[3] & 0x80) != 0)) &&
        memcmp(dest, ipv6mcast, 2) &&
        memcmp(dest, bcast, 6)) {
        /* don't update counters here! */
        return NULL;
    }

    /* We allocate a pbuf chain of pbufs from the pool. */
    p = pbuf_alloc(PBUF_RAW, (u16_t)length + ETH_PAD_SIZE, PBUF_POOL);
    LWIP_DEBUGF(NETIF_DEBUG, ("netif: recv length %i p->tot_len %i\n", length, (int)p->tot_len));

    if (p != NULL) {
        /* We iterate over the pbuf chain until we have read the entire
           packet into the pbuf. */
        start=0;
        for (q = p; q != NULL; q = q->next) {
            u16_t copy_len = q->len;
            /* Read enough bytes to fill this pbuf in the chain. The
               available data in the pbuf is given by the q->len
               variable. */
            /* read data into(q->payload, q->len); */
            LWIP_DEBUGF(NETIF_DEBUG, ("netif: recv start %i length %i q->payload %p q->len %i q->next %p\n", start, length, q->payload, (int)q->len, (void*)q->next));
            if (q == p) {
#if ETH_PAD_SIZE
                LWIP_ASSERT("q->len >= ETH_PAD_SIZE", q->len >= ETH_PAD_SIZE);
        copy_len -= ETH_PAD_SIZE;
#endif /* ETH_PAD_SIZE*/
                memcpy(&((char*)q->payload)[ETH_PAD_SIZE], &((char*)packet)[start], copy_len);
            } else {
                memcpy(q->payload, &((char*)packet)[start], copy_len);
            }
            start += copy_len;
            length -= copy_len;
            if (length <= 0) {
                break;
            }
        }
        LINK_STATS_INC(link.recv);
        snmp_add_ifinoctets(netif, p->tot_len);
        if (unicast) {
            snmp_inc_ifinucastpkts(netif);
        } else {
            snmp_inc_ifinnucastpkts(netif);
        }
    } else {
        /* drop packet(); */
        LINK_STATS_INC(link.memerr);
        LINK_STATS_INC(link.drop);
    }

    return p;
}
/*-----------------------------------------------------------------------------------*/
static void
callback(u_char *arg, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
  struct netif *netif;
  struct pcapif *pcapif;
  struct pbuf *p;

  netif = (struct netif *)arg;
  pcapif = netif->state;

  p = pcapif_low_level_input(netif, pkt, hdr->caplen);

  if (p != NULL) {
      if (netif->input(p, netif) != ERR_OK) {
          LWIP_DEBUGF(NETIF_DEBUG, ("ethernetif_input: IP input error\n"));
          pbuf_free(p);
      }
  }
}
/*-----------------------------------------------------------------------------------*/
#if PCAPIF_RX_USE_THREAD
static void
pcapif_input_thread(void *arg)
{
  struct netif *netif;
  struct pcapif *pcapif;
  netif = arg;
  pcapif = netif->state;

  while (1) {
    pcap_loop(pcapif->pd, 1, callback, (u_char *)netif);
  }
}
#else
int pcapif_input(struct netif *netif)
{
    struct pcapif *pcapif = netif->state;
    pcap_loop(pcapif->pd, 1, callback, (u_char *)netif);
    return 1;
}
#endif

/*-----------------------------------------------------------------------------------*/
err_t
pcapif_init(struct netif *netif)
{
  struct pcapif *p;

  p = malloc(sizeof(struct pcapif));
  if (p == NULL)
      return ERR_MEM;
  netif->state = p;
  netif->name[0] = 'p';
  netif->name[1] = 'c';
  netif->linkoutput = pcapif_output;
#if LWIP_ARP
  netif->output = etharp_output;
#else
  netif->output = NULL
#endif

  netif->mtu = 1500;
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP;
  netif->hwaddr_len = ETHARP_HWADDR_LEN;

  // get MAC address based on PID
  netif->hwaddr[0] = 0x00;
  netif->hwaddr[1] = 0x10;
  netif->hwaddr[2] = (getpid() & 0xff000000) >> 24;
  netif->hwaddr[3] = (getpid() & 0x00ff0000) >> 16;
  netif->hwaddr[4] = (getpid() & 0x0000ff00) >> 8;
  netif->hwaddr[5] = getpid() & 0x000000ff;

  //p->pd = pcap_open_offline("pcapdump", errbuf);
  // ref: contrib/ports/win32/pcapif.c
  p->pd = pcap_create(PCAPIF_DEV_NAME,
                         errbuf);
  if (p->pd == NULL) {
      printf("pcap_create: failed %s\n", errbuf);
      return ERR_IF;
  }

  if (pcap_set_immediate_mode(p->pd, 1) != 0) {
      LWIP_ASSERT("Failed to set pcap immediate mode", 0);
  }

  if (pcap_activate(p->pd) < 0) {
      LWIP_ASSERT("Failed to activate pcap", 0);
  }

  #if PCAPIF_RX_USE_THREAD
  sys_thread_new("pcapif_input_thread", pcapif_input_thread, netif, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
  #endif

  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
#endif /* linux */
