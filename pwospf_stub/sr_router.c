
/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */
    send_rip_request(sr); /* me when i route */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

char *best_prefix(struct sr_instance *sr, uint32_t ip_addr) {
  struct sr_rt *cur_rt = sr->routing_table;
  char *best_match = NULL;  
  uint32_t best_match_mask = 0;

  while (cur_rt) {
    uint32_t cur_mask = cur_rt->mask.s_addr;
    uint32_t cur_addr = cur_rt->dest.s_addr;

    if ((cur_addr & cur_mask) == (ip_addr & cur_mask)) {
      if (cur_mask > best_match_mask) {
        best_match = cur_rt->interface; 
        best_match_mask = cur_mask;
      }
    }
    cur_rt = cur_rt->next;
  }
  
  printf("Best match: %s\n", best_match);
  return best_match;
}

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  /* Sanity check the packet (meets minimum length and has correct checksum). */
  if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) /*minimum length of packet we can receive, 34 bytes*/
  {
    printf("Invalid length > packet dropped. \n");
    return;
  }

  uint8_t *packet_to_send = (uint8_t *)malloc(len);
  memcpy(packet_to_send, packet, len);

  sr_ethernet_hdr_t *p_ethernet_header = (sr_ethernet_hdr_t *)packet_to_send;
  uint16_t packet_type_id = p_ethernet_header->ether_type;
  if(packet_type_id == ethertype_arp) /* ARP */
  {
    printf("Received ARP packet. \n");
    sr_arp_hdr_t *p_arp_header = (sr_arp_hdr_t *)(packet_to_send + sizeof(sr_ethernet_hdr_t));
    unsigned short arp_opcode = p_arp_header->ar_op;
    uint32_t ip_dest = p_arp_header->ar_tip;

    if (arp_opcode == htons(arp_op_request))
    {
      printf("ARP Request.\n");
      struct sr_if *cur = sr->if_list;
      while(cur)
      {
        if(cur->ip == ip_dest)
        {
          p_arp_header->ar_op = htons(arp_op_reply);
          memcpy(p_arp_header->ar_sha, cur->addr, ETHER_ADDR_LEN);
          p_arp_header->ar_sip = cur->ip;
          memcpy(p_arp_header->ar_tha, p_arp_header->ar_sha, ETHER_ADDR_LEN);
          p_arp_header->ar_tip = p_arp_header->ar_sip;
          memcpy(p_ethernet_header->ether_dhost, p_ethernet_header->ether_shost, ETHER_ADDR_LEN);
          memcpy(p_ethernet_header->ether_shost, cur->addr, ETHER_ADDR_LEN);

          sr_send_packet(sr, packet_to_send, len, interface);
          return;
        }
        cur = cur->next;
      }
      return;
    }
    else if (arp_opcode == htons(arp_op_reply)) 
    {
      printf("ARP Reply.\n");
      struct sr_if *cur = sr->if_list;
      while(cur)
      {
        if(p_arp_header->ar_tip == cur->ip)
        {
          printf("Inserting entry into our arpcache.\n");
          struct sr_arpreq *arpreq = sr_arpcache_insert(&sr->cache, p_arp_header->ar_sha, p_arp_header->ar_sip);   
          if(arpreq)
          {
            struct sr_packet *queued_packet = arpreq->packets;
            while (queued_packet)
            {
              sr_ethernet_hdr_t *p_out_ethernet_header = (sr_ethernet_hdr_t *) queued_packet->buf;
              memcpy(p_out_ethernet_header->ether_dhost, p_arp_header->ar_sha, ETHER_ADDR_LEN);
              memcpy(p_out_ethernet_header->ether_shost, p_arp_header->ar_tha, ETHER_ADDR_LEN);
              sr_send_packet(sr, queued_packet->buf, queued_packet->len, queued_packet->iface);
              queued_packet = queued_packet->next;
            }
            sr_arpreq_destroy(&sr->cache, arpreq);
          }   
          break;
        }
        cur = cur->next;
      }
      return;
    }
  } 
  else if(packet_type_id == ethertype_ip) /* IP */
  {
    sr_ip_hdr_t *p_ip_header = (sr_ip_hdr_t *)(packet_to_send + sizeof(sr_ethernet_hdr_t));
    printf("Received IP packet. \n");
    
    uint16_t received_checksum = p_ip_header->ip_sum;
    p_ip_header->ip_sum = 0;
    uint16_t expected_checksum = cksum(p_ip_header, p_ip_header->ip_hl * 4); /*Convert words to bytes*/
    p_ip_header->ip_sum = received_checksum;
    
    if(received_checksum != expected_checksum)
    {
      printf("Checksum detected an error > packet dropped. \n");
      printf("Expected: 0x%x\nReceived: 0x%x\n", expected_checksum, received_checksum);
      return;
    }

    /* Decrement the TTL by 1, and recompute the packet checksum over the modified header. */
    p_ip_header->ip_ttl--;
    if (p_ip_header->ip_ttl == 0)
    {
      printf("Time exceeded. \n");
      send_icmp_t3_packet(sr, packet_to_send, ICMP_TYPE_TIME_EXCEEDED, ICMP_CODE_TIME_EXCEEDED, interface); /*Per ed post? Don't know*/
      return;
    }

    /* Check if packet is for router */
    struct sr_if *cur = sr->if_list;
      while(cur)
      {
        if(p_ip_header->ip_dst == cur->ip)
        {
          printf("Packet for Router IP.\n");
          if(p_ip_header->ip_p == ip_protocol_icmp)
          {
            printf("ICMP Message - ");
            sr_icmp_hdr_t *p_icmp_header = (sr_icmp_hdr_t *)((uint8_t *) p_ip_header + sizeof(sr_ip_hdr_t));
            printf("Type: %d, ", p_icmp_header->icmp_type);
            printf("Code: %d\n", p_icmp_header->icmp_code);
            if((p_icmp_header->icmp_type == ICMP_TYPE_ECHO_REQUEST) && (p_icmp_header->icmp_code == ICMP_CODE_ECHO_REQUEST))
            {
              printf("Sending echo reply.\n");
              send_icmp_packet(sr, packet_to_send, len, ICMP_TYPE_ECHO_REPLY, ICMP_CODE_ECHO_REPLY, interface); /* echo reply */
            }
            else
            {
              printf("Not echo reply > sending port unreachable.\n");
              send_icmp_t3_packet(sr, packet_to_send, ICMP_TYPE_UNREACHABLE, ICMP_CODE_PORT_UNREACHABLE, interface); /* port unreachable */
            }
          }
          else
          {
            printf("Packet destined for Router IP but not ICMP > sending port unreachable. \n");
            send_icmp_t3_packet(sr, packet_to_send, ICMP_TYPE_UNREACHABLE, ICMP_CODE_PORT_UNREACHABLE, interface); /* port unreachable */
          }
          return;
        }
        else if ((p_ip_header->ip_dst == (cur->ip & cur->mask)) && (p_ip_header->ip_p == ip_protocol_udp)) 
        {
          printf("UDP Packet Addressed to one of Router Subnets");
          sr_udp_hdr_t *p_udp_header = (sr_udp_hdr_t *)((uint8_t *) p_ip_header + sizeof(sr_ip_hdr_t));
          sr_rip_pkt_t *p_rip_packet = (sr_rip_pkt_t *)((uint8_t *) p_udp_header + sizeof(sr_udp_hdr_t));
          if(p_rip_packet->command == rip_command_request)
          {
            printf("RIP Request.\n");
            if (!p_rip_packet->entries){ /*don't know if it works or if it's necessary*/
              printf("No entries -> no response.\n");
              return;
            }
            else if ((p_rip_packet->entries[0].afi == 0) && (p_rip_packet->entries[0].metric == INFINITY) && (p_rip_packet->entries[1].afi == 0)) /*still need to check this*/
            {
              printf("Special case -> sending whole ass routing table including split horizon shit.\n");
              uint8_t temp_mac[ETHER_ADDR_LEN];
              memcpy(temp_mac, p_ethernet_header->ether_shost, ETHER_ADDR_LEN);
              memcpy(p_ethernet_header->ether_shost, p_ethernet_header->ether_dhost, ETHER_ADDR_LEN);
              memcpy(p_ethernet_header->ether_dhost, temp_mac, ETHER_ADDR_LEN);
              p_ethernet_header->ether_type = ethertype_ip;

              p_ip_header->ip_v = 4;
              p_ip_header->ip_tos = 0; /*most of this stuff shouldnt change for ip*/
              p_ip_header->ip_hl = 5;
              p_ip_header->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
              p_ip_header->ip_id = 0;
              p_ip_header->ip_off = htons(IP_DF);
              p_ip_header->ip_ttl = 64; /* unsure if this is right */
              p_ip_header->ip_p = ip_protocol_udp;
              uint32_t temp_ip = p_ip_header->ip_src;
              p_ip_header->ip_src = cur->ip;
              struct sr_rt *rt_ip_entry = search_rt(sr, temp_ip);
              p_ip_header->ip_dst = rt_ip_entry->dest;
              p_ip_header->ip_sum = 0;
              p_ip_header->ip_sum = cksum(p_ip_header, sizeof(sr_ip_hdr_t));

              p_rip_packet->command = rip_command_response;
              p_rip_packet->version = 2;
              p_rip_packet->unused = 0;/* actually do we even use this? lmao */

              int entry_index = 0;
              struct sr_rt* routing_entry = sr->routing_table;
              while (routing_entry && (entry_index < MAX_NUM_ENTRIES))
              {
                  if (routing_entry->gw.s_addr != 0) /* split horizon - dont send info about subnet to subnet */
                  {
                    p_rip_packet->entries[entry_index].metric = routing_entry->metric;
                  }
                  else
                  {
                    p_rip_packet->entries[entry_index].metric = INFINITY;
                  }
                  p_rip_packet->entries[entry_index].afi = 2; /*Address is IPv4*/
                  p_rip_packet->entries[entry_index].tag = 0; /*optional I think*/
                  p_rip_packet->entries[entry_index].address = routing_entry->dest.s_addr;
                  p_rip_packet->entries[entry_index].mask = routing_entry->mask.s_addr;
                  p_rip_packet->entries[entry_index].next_hop = routing_entry->gw.s_addr;
                  entry_index++;
                  routing_entry = routing_entry->next;
              }

              p_udp_header->port_src = htons(520);
              p_udp_header->port_dst = htons(520);
              p_udp_header->udp_len = len;
              p_udp_header->udp_sum = 0; /*optional perhaps?*/

              sr_send_packet(sr, packet_to_send, len, interface);
              free(packet_to_send);
              return;
            }
            else
            {
              printf("Default Case -> Asking for some entries. \n"); /*may be dropped*/
              int entry_index = 0;
              while (entry_index < MAX_NUM_ENTRIES)
              {
                struct sr_rt* cur_entry = sr->routing_table;
                int found_entry = 0;
                while (cur_entry)
                {
                  if (cur_entry->dest.s_addr == p_rip_packet->entries[entry_index].address)
                  {
                    found_entry = 1;
                    break;
                  }
                  cur_entry = cur_entry->next;
                }
                if (found_entry)
                {
                  p_rip_packet->entries[entry_index].metric = cur_entry->metric;
                }
                else
                {
                  p_rip_packet->entries[entry_index].metric = INFINITY;
                }
                entry_index++;
              }
              /* ethernet */
              uint8_t temp_et[ETHER_ADDR_LEN];
              memcpy(temp_et, p_ethernet_header->ether_dhost, ETHER_ADDR_LEN);
              memcpy(p_ethernet_header->ether_dhost, p_ethernet_header->ether_shost, ETHER_ADDR_LEN);
              memcpy(p_ethernet_header->ether_shost, temp_et, ETHER_ADDR_LEN);
              /* ip */
              uint32_t temp_ip = p_ip_header->ip_src;
              p_ip_header->ip_src = p_ip_header->ip_dst;
              p_ip_header->ip_dst = temp_ip;
              p_ip_header->ip_sum = 0;
              p_ip_header->ip_sum = cksum(p_ip_header, sizeof(sr_ip_hdr_t));
              /* udp */
              uint16_t temp_udp = p_udp_header->port_src;
              p_udp_header->port_src = p_udp_header->port_dst;
              p_udp_header->port_dst = temp_udp;
              /* tbd if we need to do udp checksum */
              p_rip_packet->command = rip_command_response;
              sr_send_packet(sr, packet_to_send, len, interface);
              free(packet_to_send);
            }

          }
          else if(p_rip_packet->command == rip_command_response)
          {
            printf("RIP Response.\n");
            /* Validate the packet */
            if(p_udp_header->port_src != 520)
            {
              printf("Source port was not 520 > Not from RIP port.\n");
              return;
            }
            
            struct sr_rt *incoming_rt = search_rt(sr, p_ip_header->ip_src);

            if(incoming_rt->gw.s_addr == 0) 
            {
              update_route_table(sr, p_ip_header, p_rip_packet, interface);
            }
            else
            {
              printf("Datagram did not come from a valid neighbor.\n");
              return;
            }            
          }
        }
        cur = cur->next;
      }
      printf("Packet isn't for me. I will forward her!\n");
      /*
      char *iface_out_name = best_prefix(sr, p_ip_header->ip_dst);
      if (iface_out_name == NULL)
      {
        send_icmp_t3_packet(sr, packet_to_send, ICMP_TYPE_UNREACHABLE, ICMP_CODE_DESTINATION_NET_UNREACHABLE, interface);
        return;
      }
      */
      struct sr_rt *rt_out = search_rt(sr, p_ip_header->ip_dst);
      
      if(rt_out == 0 || rt_out->metric == htons(INFINITY))
      {
        printf("Next hop not found.\n");
        send_icmp_t3_packet(sr, packet_to_send, ICMP_TYPE_UNREACHABLE, ICMP_CODE_PORT_UNREACHABLE, interface); /* port unreachable */
        return;
      }
      
      uint32_t nh_addr = 0;
      if (rt_out->gw.s_addr == 0) {
          nh_addr = p_ip_header->ip_dst;
      } else {
          nh_addr = rt_out->gw.s_addr;
      }

    struct sr_arpentry *arpentry = sr_arpcache_lookup(&sr->cache, nh_addr);
    if (arpentry)
    {
      printf("ok so she was in our arpcache. Should find her in interface list...\n");
      struct sr_if *cur = sr->if_list;
      while(cur)
      {
        if(memcmp(arpentry->mac, cur->addr, ETHER_ADDR_LEN) == 0)
        {
          printf("Found address from arpentry in interface list.\n");
          uint8_t temp_ether_dhost[ETHER_ADDR_LEN];
          memcpy(temp_ether_dhost, p_ethernet_header->ether_dhost, ETHER_ADDR_LEN);
          memcpy(p_ethernet_header->ether_dhost, p_ethernet_header->ether_shost, ETHER_ADDR_LEN);
          memcpy(p_ethernet_header->ether_shost, temp_ether_dhost, ETHER_ADDR_LEN);
          sr_send_packet(sr, packet_to_send, len, cur->name);
          break;
        }
      }
      printf("Freeing arpentry now.\n");
      free(arpentry);
    }
    else
    {
      printf("this diva was not cached :(\n");
      struct sr_arpreq *arpreq = sr_arpcache_queuereq(&sr->cache, p_ip_header->ip_dst, packet, len, rt_out->interface);
      handle_arpreq(sr, arpreq);
    }
  }
  else
  {
    printf("Invalid packet type > packet dropped.\n");
    printf("Packet type: 0x%x\n", packet_type_id);
    printf("ethertype_ip: 0x%x\n", ethertype_ip);
    printf("htons(ethertype_ip): 0x%x\n", htons(ethertype_ip));
    printf("ethertype_arp: 0x%x\n", ethertype_arp);
    printf("htons(ethertype_arp): 0x%x\n", htons(ethertype_arp));
    return;
  } 
} /* end sr_handlePacket */



              /*
              The Request is processed entry by entry.  If there are no entries, no
              response is given.  */
              
              /*
              There is one special case.  If there is exactly
              one entry in the request, and it has an address family identifier of
              zero and a metric of infinity (i.e., 16), then this is a request to
              send the entire routing table.  In that case, a call is made to the
              output process to send the routing table to the requesting
              address/port.  
              */

              /*
              Except for this special case, processing is quite
              simple.  Examine the list of RTEs in the Request one by one.  For
              each entry, look up the destination in the router's routing database
              and, if there is a route, put that route's metric in the metric field
              of the RTE.  If there is no explicit route to the specified
              destination, put infinity in the metric field.  Once all the entries
              have been filled in, change the command from Request to Response and
              send the datagram back to the requestor.
              */
              
              /*
              Note that there is a difference in metric handling for specific and
              whole-table requests.  If the request is for a complete routing
              table, normal output processing is done, including Split Horizon (see
              section 3.9 on Split Horizon).  If the request is for specific
              entries, they are looked up in the routing table and the information
              is returned as is; no Split Horizon processing is done.  The reason
              for this distinction is the expectation that these requests are
              likely to be used for different purposes.  When a router first comes
              up, it multicasts a Request on every connected network asking for a
              complete routing table.  It is assumed that these complete routing
              tables are to be used to update the requestor's routing table.  For
              this reason, Split Horizon must be done.  It is further assumed that
              a Request for specific networks is made only by diagnostic software,
              and is not used for routing.  In this case, the requester would want
              to know the exact contents of the routing table and would not want
              any information hidden or modified.
              */