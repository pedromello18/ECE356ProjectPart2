#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"

void handle_arpreq(struct sr_instance *sr, struct sr_arpreq* req) {
    time_t now = time(NULL);
    if (difftime(now, req->sent) >= 1.0) {
        printf("Can resend request! \n");
        if (req->times_sent >= 5) {
            printf("Request sent at least 5 times.\n");
            struct sr_packet *packet = req->packets;
            while(packet != NULL) {
                printf("Sending Host Unreachable ICMP Message.\n");
                send_icmp_t3_packet(sr, packet->buf, ICMP_TYPE_UNREACHABLE, ICMP_CODE_DESTINATION_HOST_UNREACHABLE, packet->iface); 
                packet = packet->next;
            }
            sr_arpreq_destroy(&sr->cache, req);
        } 
        else {
            printf("hello from line 29 in arpcache.\n");
            char *iface_name = best_prefix(sr, req->ip);
            unsigned char mac_addr[ETHER_ADDR_LEN];
            printf("line 32 so 33 is now actually 34\n");
            uint32_t ip_addr;
            printf("line 33\n");
            printf("F*ck u u piece of sh1t FUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU*K");
            printf("made it to interface list");
            struct sr_if *cur = sr->if_list;
            while(cur)
            {
                if (strcmp(cur->name, iface_name) == 0) {
                    memcpy(mac_addr, cur->addr, ETHER_ADDR_LEN);
                    ip_addr = cur->ip;
                    break;
                }
                cur = cur->next;
            }
            
            printf("Sending an ARP request.\n");
            /* create arp request  and send it */
            uint32_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
            uint8_t *packet_to_send = (uint8_t *)malloc(len);
            sr_ethernet_hdr_t *p_ethernet_header = (sr_ethernet_hdr_t *)packet_to_send;
            sr_arp_hdr_t *p_arp_header = (sr_arp_hdr_t *)(packet_to_send + sizeof(sr_ethernet_hdr_t));

            /* link layer */
            memset(p_ethernet_header->ether_dhost, ARP_BROADCAST_ADDRESS, ETHER_ADDR_LEN);
            memcpy(p_ethernet_header->ether_shost, mac_addr, ETHER_ADDR_LEN);
            p_ethernet_header->ether_type = htons(ethertype_arp);

            /* arp header */
            p_arp_header->ar_hrd = htons(arp_hrd_ethernet);
            p_arp_header->ar_pro = htons(ethertype_ip); /* maybe? */
            p_arp_header->ar_hln = ETHER_ADDR_LEN;
            p_arp_header->ar_pln = sizeof(uint32_t); /* hopefully? */
            p_arp_header->ar_op = htons(arp_op_request);
            memcpy(p_arp_header->ar_sha, mac_addr, ETHER_ADDR_LEN);
            p_arp_header->ar_sip = ip_addr; 
            memset(p_arp_header->ar_tha, 0, ETHER_ADDR_LEN);
            p_arp_header->ar_tip = req->ip;            

            sr_send_packet(sr, packet_to_send, len, iface_name);
            printf("ARP request sent!\n");
            free(packet_to_send);

            req->sent = now;
            req->times_sent++;
        }
    }
 }


/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
    struct sr_arpreq* req = sr->cache.requests;
    while(req) {
        struct sr_arpreq *next_req = req->next;
        handle_arpreq(sr, req);
        req = next_req;
    }
}

/*
    Sends an ICMP packet to the interface with the given type and code.
    Must pass in a packet buffer and length.
*/
void send_icmp_packet(struct sr_instance* sr, uint8_t *p_packet, unsigned int len, uint8_t icmp_type, uint8_t icmp_code, char* interface)
{
    /* icmp header */
    sr_icmp_hdr_t *p_icmp_header = (sr_icmp_hdr_t *)(p_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    p_icmp_header->icmp_type = icmp_type;
    p_icmp_header->icmp_code = icmp_code;
    p_icmp_header->icmp_sum = 0;
    p_icmp_header->icmp_sum = cksum(p_icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

    /* ip layer */
    sr_ip_hdr_t *p_ip_header = (sr_ip_hdr_t *)(p_packet + sizeof(sr_ethernet_hdr_t));
    uint32_t temp_ip = p_ip_header->ip_src;
    memcpy(&p_ip_header->ip_src, &p_ip_header->ip_dst, sizeof(uint32_t));
    memcpy(&p_ip_header->ip_dst, &temp_ip, sizeof(uint32_t));
    p_ip_header->ip_sum = 0;
    p_ip_header->ip_sum = cksum(p_ip_header, p_ip_header->ip_hl * 4);

    /* link layer */
    sr_ethernet_hdr_t *p_ethernet_header = (sr_ethernet_hdr_t *)p_packet;
    uint8_t temp_mac[ETHER_ADDR_LEN];
    memcpy(temp_mac, p_ethernet_header->ether_shost, ETHER_ADDR_LEN);
    memcpy(p_ethernet_header->ether_shost, p_ethernet_header->ether_dhost, ETHER_ADDR_LEN);
    memcpy(p_ethernet_header->ether_dhost, temp_mac, ETHER_ADDR_LEN);

    /* send packet */
    sr_send_packet(sr, p_packet, len, interface);
}

void send_icmp_t3_packet(struct sr_instance* sr, uint8_t *p_packet, uint8_t icmp_type, uint8_t icmp_code, char* interface)
{
    /*get ip address of recepient interface*/
    uint32_t ip_addr;
    struct sr_if *cur = sr->if_list;
    while(cur)
    {
        if (strcmp(cur->name, interface) == 0)
        {
            ip_addr = cur->ip;
        }
        cur = cur->next;
    }
    sr_ip_hdr_t *temp_ip_header = (sr_ip_hdr_t *)(p_packet + sizeof(sr_ethernet_hdr_t));
    sr_ethernet_hdr_t *temp_ethernet_header = (sr_ethernet_hdr_t *)(p_packet);

    /* icmp header */
    int icmp_len = sizeof(sr_icmp_t3_hdr_t) + htons(temp_ip_header->ip_len);
    int total_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + icmp_len;
    uint8_t *packet_to_send = (uint8_t *)malloc(total_size);
    
    sr_icmp_t3_hdr_t *p_icmp_header = (sr_icmp_t3_hdr_t *)(packet_to_send + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    sr_ip_hdr_t *p_ip_header = (sr_ip_hdr_t *)(packet_to_send + sizeof(sr_ethernet_hdr_t));
    sr_ethernet_hdr_t *p_ethernet_header = (sr_ethernet_hdr_t *)packet_to_send;

    p_icmp_header->icmp_type = icmp_type;
    p_icmp_header->icmp_code = icmp_code;
    p_icmp_header->icmp_sum = 0;
    p_icmp_header->unused = 0;
    p_icmp_header->next_mtu = 0;
    int i;
    for (i = 0; i < ICMP_DATA_SIZE; i++) {
        p_icmp_header->data[i] = *((uint8_t*) temp_ip_header + i);
    }
    p_icmp_header->icmp_sum = cksum(p_icmp_header, icmp_len);

    /* ip layer */
    p_ip_header->ip_v = 4;
    p_ip_header->ip_hl = 5;
    p_ip_header->ip_tos = 0;
    p_ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + icmp_len);
    p_ip_header->ip_id = 0;
    p_ip_header->ip_off = htons(IP_DF);
    p_ip_header->ip_ttl = 64;
    p_ip_header->ip_p = ip_protocol_icmp;
    p_ip_header->ip_src = ip_addr; /*needs to have our IP*/
    p_ip_header->ip_dst = temp_ip_header->ip_src;
    p_ip_header->ip_sum = 0;
    p_ip_header->ip_sum = cksum(p_ip_header, sizeof(sr_ip_hdr_t));

    /* link layer */
    memcpy(p_ethernet_header, temp_ethernet_header, sizeof(sr_ethernet_hdr_t));
    memcpy(p_ethernet_header->ether_shost, temp_ethernet_header->ether_dhost, ETHER_ADDR_LEN);
    memcpy(p_ethernet_header->ether_dhost, temp_ethernet_header->ether_shost, ETHER_ADDR_LEN);

    /* send packet */
    sr_send_packet(sr, packet_to_send, total_size, interface);
    free(packet_to_send);
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}