/*-----------------------------------------------------------------------------
 * file:  sr_rt.c
 * date:  Mon Oct 07 04:02:12 PDT 2002
 * Author:  casado@stanford.edu
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>


#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_if.h"
#include "sr_utils.h"
#include "sr_router.h"


struct sr_rt* search_rt(struct sr_instance *sr, uint32_t ip_dst) {
    struct sr_rt* cur_rt = sr->routing_table;
    while (cur_rt) {
        if ((cur_rt->dest.s_addr == ip_dst) || (cur_rt->dest.s_addr == (ip_dst & cur_rt->mask.s_addr))) {
            printf("Best match is interface %s\n", cur_rt->interface);
            return cur_rt;
        }
        cur_rt = cur_rt->next;
    }
    return NULL;
}


/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/ 

int sr_load_rt(struct sr_instance* sr,const char* filename)
{
    FILE* fp;
    char  line[BUFSIZ];
    char  dest[32];
    char  gw[32];
    char  mask[32];    
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;
    int clear_routing_table = 0;

    /* -- REQUIRES -- */
    assert(filename);
    if( access(filename,R_OK) != 0)
    {
        perror("access");
        return -1;
    }

    fp = fopen(filename,"r");

    while( fgets(line,BUFSIZ,fp) != 0)
    {
        sscanf(line,"%s %s %s %s",dest,gw,mask,iface);
        if(inet_aton(dest,&dest_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    dest);
            return -1; 
        }
        if(inet_aton(gw,&gw_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    gw);
            return -1; 
        }
        if(inet_aton(mask,&mask_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    mask);
            return -1; 
        }
        if( clear_routing_table == 0 ){
            printf("Loading routing table from server, clear local routing table.\n");
            sr->routing_table = 0;
            clear_routing_table = 1;
        }
        sr_add_rt_entry(sr,dest_addr,gw_addr,mask_addr,(uint32_t)0,iface);
    } /* -- while -- */

    return 0; /* -- success -- */
} /* -- sr_load_rt -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
int sr_build_rt(struct sr_instance* sr){
    struct sr_if* interface = sr->if_list;
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;

    while (interface){
        dest_addr.s_addr = (interface->ip & interface->mask);
        gw_addr.s_addr = 0;
        mask_addr.s_addr = interface->mask;
        strcpy(iface, interface->name);
        sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, (uint32_t)0, iface);
        interface = interface->next;
    }
    return 0;
}

void sr_add_rt_entry(struct sr_instance* sr, struct in_addr dest,
struct in_addr gw, struct in_addr mask, uint32_t metric, char* if_name)
{   
    struct sr_rt* rt_walker = 0;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    pthread_mutex_lock(&(sr->rt_lock));
    /* -- empty list special case -- */
    if(sr->routing_table == 0)
    {
        sr->routing_table = (struct sr_rt*)malloc(sizeof(struct sr_rt));
        assert(sr->routing_table);
        sr->routing_table->next = 0;
        sr->routing_table->dest = dest;
        sr->routing_table->gw   = gw;
        sr->routing_table->mask = mask;
        strncpy(sr->routing_table->interface,if_name,sr_IFACE_NAMELEN);
        sr->routing_table->metric = metric;
        time_t now;
        time(&now);
        sr->routing_table->updated_time = now;

        pthread_mutex_unlock(&(sr->rt_lock));
        return;
    }

    /* -- find the end of the list -- */
    rt_walker = sr->routing_table;
    while(rt_walker->next){
      rt_walker = rt_walker->next; 
    }

    rt_walker->next = (struct sr_rt*)malloc(sizeof(struct sr_rt));
    assert(rt_walker->next);
    rt_walker = rt_walker->next;

    rt_walker->next = 0;
    rt_walker->dest = dest;
    rt_walker->gw   = gw;
    rt_walker->mask = mask;
    strncpy(rt_walker->interface,if_name,sr_IFACE_NAMELEN);
    rt_walker->metric = metric;
    time_t now;
    time(&now);
    rt_walker->updated_time = now;
    
     pthread_mutex_unlock(&(sr->rt_lock));
} /* -- sr_add_entry -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_table(struct sr_instance* sr)
{
    pthread_mutex_lock(&(sr->rt_lock));
    struct sr_rt* rt_walker = 0;

    if(sr->routing_table == 0)
    {
        printf(" *warning* Routing table empty \n");
        pthread_mutex_unlock(&(sr->rt_lock));
        return;
    }
    printf("  <---------- Router Table ---------->\n");
    printf("Destination\tGateway\t\tMask\t\tIface\tMetric\tUpdate_Time\n");

    rt_walker = sr->routing_table;
    
    while(rt_walker){
        if (rt_walker->metric < INFINITY)
            sr_print_routing_entry(rt_walker);
        rt_walker = rt_walker->next;
    }
    pthread_mutex_unlock(&(sr->rt_lock));


} /* -- sr_print_routing_table -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_entry(struct sr_rt* entry)
{
    /* -- REQUIRES --*/
    assert(entry);
    assert(entry->interface);
    
    char buff[20];
    struct tm* timenow = localtime(&(entry->updated_time));
    strftime(buff, sizeof(buff), "%H:%M:%S", timenow);
    printf("%s\t",inet_ntoa(entry->dest));
    printf("%s\t",inet_ntoa(entry->gw));
    printf("%s\t",inet_ntoa(entry->mask));
    printf("%s\t",entry->interface);
    printf("%d\t",entry->metric);
    printf("%s\n", buff);

} /* -- sr_print_routing_entry -- */

struct sr_rt *get_dest_from_iface(struct sr_instance *sr, struct sr_if *iface) {
    struct sr_rt *cur_rt = sr->routing_table;
    while (cur_rt != NULL) {
        if (! strcmp(cur_rt->interface, iface->name)) { 
            break;
        }
        cur_rt = cur_rt->next;
    }
    return cur_rt;
}

void *sr_rip_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    while(1)
    {  
        sleep(5.0);
        printf("RIP Timeout Called\n");
        sr_print_routing_table(sr);
        pthread_mutex_lock(&(sr->rt_lock));
        struct sr_rt *cur_rt = sr->routing_table;
        struct sr_rt *prev_rt = NULL;
        struct sr_rt *del_rt = NULL;
        time_t now = time(NULL);
        while (cur_rt) {
            if ((difftime(now, cur_rt->updated_time) > 20) || (sr_obtain_interface_status(sr, cur_rt->interface) == 0))
            {
                printf("Removing an entry from the routing table.\n");
                if(prev_rt)
                {
                    prev_rt->next = cur_rt->next;
                }
                else {
                    sr->routing_table = cur_rt->next;
                }
                del_rt = cur_rt;
                cur_rt = cur_rt->next;
                free(del_rt);
            }
            else {
                prev_rt = cur_rt;
                cur_rt = cur_rt->next;
            }  
        } 
        /* for each interface, need to check if NOT in routing table, in which case add back if up*/
        struct sr_if *cur_if = sr->if_list;
        int in_rt = 0;
        while (cur_if) {
            if (sr_obtain_interface_status(sr, cur_if->name) == 0) 
            {
                printf("Link %s down\n", cur_if->name);
                cur_if = cur_if->next;
                continue;  
            } 
            in_rt = 0;
            cur_rt = sr->routing_table;
            while (cur_rt) {
                if ((strcmp(cur_rt->interface, cur_if->name) == 0) && (cur_rt->gw.s_addr == 0)) {
                    in_rt = 1;
                    struct in_addr gw;
                    gw.s_addr = 0;
                    cur_rt->gw = gw;
                    cur_rt->metric = 0;
                    cur_rt->updated_time = time(NULL);
                    break;
                }
                cur_rt = cur_rt->next;
            }
            if (in_rt == 0) {
                struct in_addr dest_ip;
                dest_ip.s_addr = cur_if->ip & cur_if->mask;
                struct in_addr gw_ip;
                gw_ip.s_addr = 0;
                struct in_addr mask;
                mask.s_addr = cur_if->mask;
                sr_add_rt_entry(sr, dest_ip, gw_ip, mask, 0, cur_if->name);
            }
            cur_if = cur_if->next;
        }

        send_rip_update(sr);
        pthread_mutex_unlock(&(sr->rt_lock));
    }
    return NULL;
}

void send_rip_request(struct sr_instance *sr){
    /* 
    You should send RIP request packets using UDP
    broadcast here. This function is called when the program started. The router who will
    receive a RIP request packet will send a RIP reponse immediately. 
    */

    uint8_t *p_packet = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_rip_pkt_t) + sizeof(sr_udp_hdr_t));
    sr_ethernet_hdr_t *p_ethernet_header = (sr_ethernet_hdr_t *)p_packet;
    sr_ip_hdr_t *p_ip_header = (sr_ip_hdr_t *)((p_packet + sizeof(sr_ethernet_hdr_t)));
    sr_udp_hdr_t *p_udp_header = (sr_udp_hdr_t *)(p_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    sr_rip_pkt_t *p_rip_packet = (sr_rip_pkt_t *)(p_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
    int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t);

    struct sr_if *cur_if = sr->if_list;
    while(cur_if)
    {
        if(sr_obtain_interface_status(sr, cur_if->name) == 0) 
        {
            cur_if = cur_if->next;
            continue;
        }
        struct sr_rt *dest_rt = get_dest_from_iface(sr, cur_if);
        
        /* struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                        uint32_t ip,
                                        uint8_t *packet,           
                                        unsigned int packet_len,
                                        char *iface)*/
        
        memset(p_ethernet_header->ether_dhost, 0xFFFFFF, ETHER_ADDR_LEN);
        memcpy(p_ethernet_header->ether_shost, cur_if->addr, ETHER_ADDR_LEN);
        p_ethernet_header->ether_type = htons(ethertype_ip);

        p_ip_header->ip_hl = 5;
        p_ip_header->ip_v = 4;
        p_ip_header->ip_tos = 0;
        p_ip_header->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
        p_ip_header->ip_id = 0;
        p_ip_header->ip_off = htons(IP_DF); 
        p_ip_header->ip_ttl = 64;
        p_ip_header->ip_p = ip_protocol_udp;
        p_ip_header->ip_src = cur_if->ip;
        p_ip_header->ip_dst = dest_rt->dest.s_addr;
        p_ip_header->ip_sum = 0;
        p_ip_header->ip_sum = cksum(p_ip_header, p_ip_header->ip_hl * 4);

        p_rip_packet->command = rip_command_request;
        p_rip_packet->version = 2;
        p_rip_packet->unused = 0;

        p_rip_packet->entries[0].afi = 0;
        p_rip_packet->entries[0].metric = INFINITY;

        int i;
        for (i = 1; i < MAX_NUM_ENTRIES; i++) {
            p_rip_packet->entries[i].afi = 0;
            p_rip_packet->entries[i].tag = 0;
            p_rip_packet->entries[i].address = 0;
            p_rip_packet->entries[i].mask = 0;
            p_rip_packet->entries[i].next_hop = 0;
            p_rip_packet->entries[i].metric = 0;
        }

        p_udp_header->port_src = htons(520);
        p_udp_header->port_dst = htons(520);
        p_udp_header->udp_len = len;
        p_udp_header->udp_sum = 0;
        p_udp_header->udp_sum = cksum(p_packet, len);

        sr_send_packet(sr, p_packet, len, cur_if->name);

        printf("Sent RIP request to %s\n", cur_if->name);

        cur_if = cur_if->next;
    }
}

void send_rip_update(struct sr_instance *sr){
    pthread_mutex_lock(&(sr->rt_lock));
    printf("Send RIP Update Called.\n");

    struct sr_if *cur_if = sr->if_list;
    while (cur_if) {
        if (sr_obtain_interface_status(sr, cur_if->name) == 1){
            struct sr_rt *cur_rt = search_rt(sr, cur_if->ip & cur_if->mask);
            if (! cur_rt) {
                cur_if = cur_if->next;
                continue;
            }

            uint8_t *p_packet = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_rip_pkt_t) + sizeof(sr_udp_hdr_t));
            sr_ethernet_hdr_t *p_ethernet_header = (sr_ethernet_hdr_t *)p_packet;
            sr_ip_hdr_t *p_ip_header = (sr_ip_hdr_t *)((p_packet + sizeof(sr_ethernet_hdr_t)));
            sr_udp_hdr_t *p_udp_header = (sr_udp_hdr_t *)(p_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            sr_rip_pkt_t *p_rip_packet = (sr_rip_pkt_t *)(p_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
            int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t);

            memset(p_ethernet_header->ether_dhost, 0xFFFFFF, ETHER_ADDR_LEN); /*may not work (hopefully does)*/
            memcpy(p_ethernet_header->ether_shost, cur_if->addr, ETHER_ADDR_LEN);
            p_ethernet_header->ether_type = htons(ethertype_ip);

            p_ip_header->ip_hl = 5;
            p_ip_header->ip_v = 4;
            p_ip_header->ip_tos = 0;
            p_ip_header->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
            p_ip_header->ip_id = 0;
            p_ip_header->ip_off = htons(IP_DF); 
            p_ip_header->ip_ttl = 64;
            p_ip_header->ip_p = ip_protocol_udp;
            p_ip_header->ip_src = cur_if->ip;
            p_ip_header->ip_dst = cur_rt->dest.s_addr;
            p_ip_header->ip_sum = 0;
            p_ip_header->ip_sum = cksum(p_ip_header, p_ip_header->ip_hl * 4);

            p_rip_packet->command = rip_command_response;
            p_rip_packet->version = 2;
            p_rip_packet->unused = 0;

            int entry_index = 0;
            struct sr_rt* routing_entry = sr->routing_table;
            while (routing_entry && (entry_index < MAX_NUM_ENTRIES))
            {
                if (strcmp(cur_if->name, routing_entry->interface) == 0)
                {
                    p_rip_packet->entries[entry_index].metric = INFINITY;
                    printf("Not sending destination %i through %s\n", routing_entry->dest.s_addr, cur_if->name);
                    /*routing_entry = routing_entry->next;
                    continue;*/
                }
                else
                {
                    p_rip_packet->entries[entry_index].metric = routing_entry->metric;
                }
                p_rip_packet->entries[entry_index].afi = 2; /*Address is IPv4*/
                p_rip_packet->entries[entry_index].tag = 0; /*optional I think*/
                p_rip_packet->entries[entry_index].address = routing_entry->dest.s_addr;
                p_rip_packet->entries[entry_index].mask = routing_entry->mask.s_addr;
                p_rip_packet->entries[entry_index].next_hop = routing_entry->gw.s_addr;
                routing_entry = routing_entry->next;
                entry_index++;
            }

            p_udp_header->port_src = htons(520);
            p_udp_header->port_dst = htons(520);
            p_udp_header->udp_len = htons(sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t)); /*this may not be right*/
            p_udp_header->udp_sum = 0; /*optional perhaps?*/

            sr_send_packet(sr, p_packet, len, cur_if->name);
            printf("RIP Response Sent\n");
            free(p_packet);
        }
        cur_if = cur_if->next;
    }
    pthread_mutex_unlock(&(sr->rt_lock));
}

void update_route_table(struct sr_instance *sr, sr_ip_hdr_t* ip_packet, sr_rip_pkt_t* rip_packet, char* iface){
    pthread_mutex_lock(&(sr->rt_lock));
    printf("update_route_table called.\n");
    int change_made = 0;
    int i;
    int iface_down = 0;
    for (i = 0; i < MAX_NUM_ENTRIES; i++)
    {
        struct sr_if *cur_if = sr->if_list;
        while (cur_if) {
            if ((cur_if->ip & cur_if->mask) == (rip_packet->entries[i].address & rip_packet->entries[i].mask)) {
                if(sr_obtain_interface_status(sr, cur_if->name) == 0){
                    iface_down = 1;
                    printf("Interface down in update RT\n");
                    break;
                }
            }
            cur_if = cur_if->next;
        } 
        if (iface_down) continue;
        if(rip_packet->entries[i].metric < 0 || rip_packet->entries[i].metric > INFINITY)
        {
            printf("invalid metric\n");
            continue;
        }
        if((rip_packet->entries[i].address == 0) || (rip_packet->entries[i].mask == 0))
        {
            /*printf("invalid address\n");*/ 
            continue;
        }

        struct sr_rt *cur_rt = sr->routing_table;
        int entry_found = 0;
        while(cur_rt && (! entry_found))
        {
            if (cur_rt->dest.s_addr == rip_packet->entries[i].address) {
                entry_found = 1;
                if (rip_packet->entries[i].metric < INFINITY) cur_rt->updated_time = time(NULL);
                if (cur_rt->metric > rip_packet->entries[i].metric + 1) {
                    cur_rt->metric = rip_packet->entries[i].metric + 1;
                    cur_rt->gw.s_addr = ip_packet->ip_src;
                    memcpy(cur_rt->interface, iface, sr_IFACE_NAMELEN);
                    change_made = 1;
                }
            }
            cur_rt = cur_rt->next;
        }
        if (! entry_found && (rip_packet->entries[i].metric < INFINITY))
        {
            struct in_addr dest;
            dest.s_addr = rip_packet->entries[i].address;
            struct in_addr gw;
            gw.s_addr = ip_packet->ip_src;
            struct in_addr mask;
            mask.s_addr = rip_packet->entries[i].mask;
            sr_add_rt_entry(sr, dest, gw, mask, rip_packet->entries[i].metric + 1, iface);
            change_made = 1;
        }
    }
    if(change_made)
    {
        send_rip_update(sr);
        /*
        printf("I made a change, here's my new routing table...\n");*/
        sr_print_routing_table(sr);
        
    }
    else
    {
        printf("No change made.\n");
        sr_print_routing_table(sr);
    }
    pthread_mutex_unlock(&(sr->rt_lock));
}

/*

    If there is an existing route, compare the next hop address to the
    address of the router from which the datagram came.  If this datagram
    is from the same router as the existing route, reinitialize the
    timeout.  Next, compare the metrics.  If the datagram is from the
    same router as the existing route, and the new metric is different
    than the old one; or, if the new metric is lower than the old one; do
    the following actions:

    - Adopt the route from the datagram (i.e., put the new metric in and
        adjust the next hop address, if necessary).

    - Set the route change flag and signal the output process to trigger
        an update

    - If the new metric is infinity, start the deletion process
        (described above); otherwise, re-initialize the timeout

    If the new metric is infinity, the deletion process begins for the
    route, which is no longer used for routing packets.  Note that the
    deletion process is started only when the metric is first set to
    infinity.  If the metric was already infinity, then a new deletion
    process is not started.

    If the new metric is the same as the old one, it is simplest to do
    nothing further (beyond re-initializing the timeout, as specified
    above); but, there is a heuristic which could be applied.  Normally,
    it is senseless to replace a route if the new route has the same
    metric as the existing route; this would cause the route to bounce
    back and forth, which would generate an intolerable number of
    triggered updates.  However, if the existing route is showing signs
    of timing out, it may be better to switch to an equally-good
    alternative route immediately, rather than waiting for the timeout to
    happen.  Therefore, if the new metric is the same as the old one,
    examine the timeout for the existing route.  If it is at least
    halfway to the expiration point, switch to the new route.  This
    heuristic is optional, but highly recommended.

    Any entry that fails these tests is ignored, as it is no better than
    the current route.
    */