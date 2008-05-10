/*
 * Copyright (C) 2006 BATMAN contributors:
 * Thomas Lopatic, Marek Lindner
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */

#ifndef _BATMAN_OS_H
#define _BATMAN_OS_H

#include "batman.h"


/* get_time functions MUST be called at least every 2*MAX_SELECT_TIMEOUT_MS to allow for properly working time-drift checks */

/* overlaps after approximately 138 years */
#define get_time_sec()  get_time( NO  ) 

/* overlaps after 49 days, 17 hours, 2 minutes, and 48 seconds */
#define get_time_msec() get_time( YES ) 
uint32_t get_time( uint8_t msec );
	
void fake_start_time( int32_t fake );

int32_t rand_num( uint32_t limit );

void addr_to_string( uint32_t addr, char *str, int32_t len );

void add_del_hna( struct orig_node *orig_node, struct ext_packet *hna_array, int16_t hna_array_len /*int8_t del*/ );
int8_t is_aborted();
void handler( int32_t sig );
void segmentation_fault( int32_t sig );
void restore_and_exit( uint8_t is_sigsegv );

/* route.c */
int  open_netlink_socket( void );
void close_netlink_socket( void );
int  open_ifevent_netlink_sk( void );
void close_ifevent_netlink_sk( void );
void recv_ifevent_netlink_sk( void );

void add_del_route( uint32_t dest, uint8_t netmask, uint32_t router, uint32_t source, int32_t ifi, char *dev, uint8_t rt_table, int8_t route_type, int8_t del );

void add_del_rule( uint32_t network, uint8_t netmask, uint8_t rt_table, uint32_t prio, char *iif, int8_t dst_rule, int8_t del );
int add_del_interface_rules( int8_t del, uint8_t setup_tunnel, uint8_t setup_networks );
int flush_routes_rules( int8_t rt_table );

/* tun.c */
int8_t probe_tun(uint8_t print_to_stderr);
int8_t del_dev_tun( int32_t fd );
int8_t add_dev_tun(  uint32_t dest_addr, char *tun_dev, size_t tun_dev_size, int32_t *fd, int32_t *ifi );
int8_t set_tun_addr( int32_t fd, uint32_t tun_addr, char *tun_dev );

/* init.c */

#define MAX_UNIX_RCV_SIZE 1501 
#define MAX_UNIX_REQ_SIZE 30 

void prepare_add_del_own_hna ( char *optarg_str, int8_t del, uint8_t atype );
void prepare_add_del_own_srv ( char *optarg_str, int8_t del );
void apply_init_args ( int argc, char *argv[] );
void init_interface ( struct batman_if *batman_if );
void deactivate_interface ( struct batman_if *batman_if );
void check_interfaces ();


void stop_gw_service ( void );
void start_gw_service ( void );


/* kernel.c */
void set_rp_filter( int32_t state, char* dev );
int32_t get_rp_filter( char *dev );
void set_send_redirects( int32_t state, char* dev );
int32_t get_send_redirects( char *dev );
void set_forwarding( int32_t state );
int32_t get_forwarding( void );
int8_t bind_to_iface( int32_t sock, char *dev );

/* posix.c */
void print_animation( void );
void   del_default_route();
int8_t add_default_route( struct gw_node *new_curr_gw );
int8_t receive_packet( uint32_t timeout );
int8_t send_udp_packet( unsigned char *packet_buff, int packet_buff_len, struct sockaddr_in *broad, int send_sock, struct batman_if *batman_if );
void restore_defaults();
void cleanup();

/* tunnel.c */
void *gw_listen( void *arg );
void *client_to_gw_tun( void *arg );

#define MAX_MTU 1500


#define TUNNEL_DATA 0x01
#define TUNNEL_IP_REQUEST 0x02
#define TUNNEL_IP_INVALID 0x03
#define TUNNEL_KEEPALIVE_REQUEST 0x04 /* unused */
#define TUNNEL_KEEPALIVE_REPLY 0x05   /* unused */
#define TUNNEL_IP_REPLY 0x06

#define GW_STATE_UNKNOWN  0x01
#define GW_STATE_VERIFIED 0x02

#define ONE_MINUTE                60000

#define GW_STATE_UNKNOWN_TIMEOUT  (1  * ONE_MINUTE)
#define GW_STATE_VERIFIED_TIMEOUT (5  * ONE_MINUTE)

#define IP_LEASE_TIMEOUT          (1 * ONE_MINUTE)

#define MAX_TUNNEL_IP_REQUESTS 60 /*12*/
#define TUNNEL_IP_REQUEST_TIMEOUT 1000 /* msec */

	
struct tun_request_type {
	uint32_t lease_ip;
	uint16_t lease_lt;
} __attribute__((packed));

struct tun_data_type {
	unsigned char ip_packet[MAX_MTU];
} __attribute__((packed));

struct tun_packet_start {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int type:4;
	unsigned int version:4;  /* should be the first field in the packet in network byte order */
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int version:4;
	unsigned int type:4;
#else
# error "Please fix <bits/endian.h>"
#endif
} __attribute__((packed));

struct tun_packet
{
	uint8_t  reserved1;
	uint8_t  reserved2;
	uint8_t  reserved3;

	struct tun_packet_start start;
#define TP_TYPE  start.type
#define TP_VERS  start.version	

	union
	{
		struct tun_request_type trt;
		struct tun_data_type tdt;
	}tt;
#define LEASE_IP  tt.trt.lease_ip
#define LEASE_LT  tt.trt.lease_lt
#define IP_PACKET tt.tdt.ip_packet
} __attribute__((packed));


#define TX_RP_SIZE (sizeof(struct tun_packet_start) + sizeof(struct tun_request_type))
#define TX_DP_SIZE (sizeof(struct tun_packet_start) + sizeof(struct tun_data_type))


/* unix_sokcet.c */
void *unix_listen( void *arg );
void internal_output(uint32_t sock);
void debug_output( int8_t debug_prio, char *format, ... );
void debug_log( char *format, ... );


#endif
