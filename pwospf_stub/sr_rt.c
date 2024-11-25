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


void *sr_rip_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    while (1) {
        sleep(5);
        pthread_mutex_lock(&(sr->rt_lock));
        sr_rt *cur_rt = sr->routing_table;
        sr_rt *prev_rt = NULL;
        sr_rt *del_rt = NULL;
        while (cur_rt) {
            if (time(NULL) - cur_rt->updated_time > 20) 
            {
                printf("Removing an entry from the routing table.\n");
                if(prev)
                {
                    prev->next = cur_rt->next;
                }
                else {
                    sr->routing_table = cur_rt->next;
                }
                del_rt = cur_rt;
                cur_rt = cur_rt->next;
                free(del_rt);
            }
            else {
                prev = cur_rt;
                cur_rt = cur_rt->next;
            }     
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
    uint8_t *p_packet = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
        + sizeof(sr_rip_pkt_t) + sizeof(sr_udp_hdr_t));
    sr_ethernet_hdr_t *p_ethernet_header = (sr_ethernet_hdr_t *)p_packet;
    sr_ip_hdr_t *p_ip_header = (sr_ip_hdr_t *)((p_packet + sizeof(sr_ethernet_hdr_t)));
    sr_rip_pkt_t *p_rip_packet = (sr_rip_pkt_t *)(p_packet + sizeof(sr_ethernet_hdr_t) 
        + sizeof(sr_ip_hdr_t));
    sr_udp_hdr_t *p_udp_header = (sr_udp_hdr_t *)(p_packet + sizeof(sr_ethernet_hdr_t) 
        + sizeof(sr_ip_hdr_t) + sizeof(sr_rip_pkt_t));

    struct sr_if *cur_if = sr->if_list;
    while(cur_if)
    {
        memset(p_ethernet_header->ether_dhost, 0xFFFFFF, ETHER_ADDR_LEN);
        memcpy(p_ethernet_header->ether_shost, cur_if->addr, ETHER_ADDR_LEN);
        p_ethernet_header->ether_type = ethertype_ip;

        p_ip_header->ip_tos = /* value */
        p_ip_header->ip_len = /* value */
        p_ip_header->ip_id = /* value */
        p_ip_header->ip_off = /* value */
        p_ip_header->ip_ttl = /* */
        p_ip_header->ip_p = ip_protocol_udp;
        p_ip_header->ip_sum = /* ugh we gotta do this shit */
        p_ip_header->ip_src = cur_if->ip;
        p_ip_header->ip_dst = /* */

        p_rip_packet->command = rip_command_request;
        p_rip_packet->version = 2;
        p_rip_packet->unused = /* actually do we even use this? lmao */

        p_udp_header->port_src = 520;
        p_udp_header->port_dst = 520;
        p_udp_header->udp_len = /* */
        p_udp_header->udp_sum = /* ugh */
        cur_if = cur_if->next;
    }


}

void send_rip_update(struct sr_instance *sr){
    pthread_mutex_lock(&(sr->rt_lock));
    /* Fill your code here */

    pthread_mutex_unlock(&(sr->rt_lock));
}

void update_route_table(struct sr_instance *sr, sr_ip_hdr_t* ip_packet ,sr_rip_pkt_t* rip_packet, char* iface){
    pthread_mutex_lock(&(sr->rt_lock));
    int i;
    for (i = 0; i < MAX_NUM_ENTRIES; i++)
    {
        struct entry *p_entry = rip_packet->entries[i];
        if(p_entry->metric < 1 || p_entry->metric > 16)
        {
            continue;
        }
        if(p_entry->address == 0 || p_entry->address == 127)
        {
            continue;
        }
        printf("Found a valid entry.");
        
        // MIN(p_entry->metric + cost, INFINITY);

        struct sr_rt *cur_rt = sr->routing_table;
        bool entry_found = false;
        bool change_made = false;
        while(cur_rt && (! entry_found))
        {
            if (cur_rt->dest.s_addr == p_entry->address) {
                entry_found = true;
                cur_rt->updated_time = time(NULL);
                if (cur_rt->metric > p_entry->metric + 1) {
                    /* probs deal with infinity here */
                    cur_rt->metric = p_entry->metric + 1;
                    cur_rt->gw.s_addr = p_entry->next_hop; /* R: uncertain about this one */
                    memcpy(cur_rt->interface, iface, sr_IFACE_NAMELEN);
                    change_made = true;
                }
            }
            cur_rt = cur_rt->next;
        }
        if (! entry_found && (p_entry->metric < INFINITY)) 
        {
            struct in_addr dest;
            dest.s_addr = p_entry->address;
            struct in_addr gw;
            dest.s_addr = p_entry->next_hop;
            struct in_addr mask;
            dest.s_addr = p_entry->mask;
            sr_add_rt_entry(sr, dest, gw, mask, p_entry->metric, iface);
        }
    }
    if(change_made)
    {
        send_rip_update(sr);
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

    send_rip_update(sr);
    
    pthread_mutex_unlock(&(sr->rt_lock));
}