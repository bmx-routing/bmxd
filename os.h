/*
 * Copyright (C) 2006 BATMAN contributors:
 * Thomas Lopatic, Marek Lindner, Axel Neumann
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


/* get_time functions MUST be called at least every 2*MAX_SELECT_TIMEOUT_MS to allow for properly working time-drift checks */

/* overlaps after approximately 138 years */
//#define get_time_sec()  get_time( NO, NULL  ) 

/* overlaps after 49 days, 17 hours, 2 minutes, and 48 seconds */
//#define get_time_msec() get_time( YES, NULL ) 

# define timercpy(d, a) (d)->tv_sec = (a)->tv_sec; (d)->tv_usec = (a)->tv_usec; 


/* posix.c */

enum {
	CLEANUP_SUCCESS,
	CLEANUP_FAILURE,
	CLEANUP_MY_SIGSEV,
	CLEANUP_RETURN
};

void bat_wait( uint32_t sec, uint32_t msec );

#ifndef NOTRAILER
void print_animation( void );
#endif

int8_t send_udp_packet( unsigned char *packet_buff, int32_t packet_buff_len, struct sockaddr_in *dst, int32_t send_sock );

void cleanup_all( int status );

void update_batman_time( struct timeval *precise_tv );

char *get_human_uptime( uint32_t reference );

#ifndef NODEPRECATED
void fake_start_time( int32_t fake );
#endif


int32_t rand_num( uint32_t limit );


int8_t is_aborted();
//void handler( int32_t sig );
//void restore_and_exit( uint8_t is_sigsegv );

uint8_t get_set_bits( uint32_t v );




/* route.c */

#define DEV_LO "lo"
#define DEV_UNKNOWN "unknown"

#define	MIN_MASK	1
#define	MAX_MASK	32
#define ARG_MASK	"netmask"
#define ARG_NETW	"network"

extern int32_t base_port;
#define ARG_BASE_PORT "base_port"
#define DEF_BASE_PORT 4305
#define MIN_BASE_PORT 1025
#define MAX_BASE_PORT 60000




/***
 *
 * Things you should leave as is unless your know what you are doing !
 *
 * RT_TABLE_INTERFACES	routing table for announced (non-primary) interfaces IPs and other unique IP addresses
 * RT_TABLE_NETWORKS	routing table for announced networks
 * RT_TABLE_HOSTS	routing table for routes towards originators
 * RT_TABLE_TUNNEL	routing table for the tunnel towards the internet gateway
 * RT_PRIO_DEFAULT	standard priority for routing rules
 * RT_PRIO_UNREACH	standard priority for unreachable rules
 * RT_PRIO_TUNNEL	standard priority for tunnel routing rules
 *
 ***/



extern int32_t Rt_table;
#define ARG_RT_TABLE "rt_table_offset"
#define DEF_RT_TABLE 64
#define MIN_RT_TABLE 2
#define MAX_RT_TABLE 240

#define RT_TABLE_INTERFACES (Rt_table + 0)
#define RT_TABLE_NETWORKS   (Rt_table + 1)
#define RT_TABLE_HOSTS      (Rt_table + 2)
#define RT_TABLE_TUNNEL     (Rt_table + 4)


extern int32_t Rt_prio;
#define ARG_RT_PRIO "prio_rules_offset"
#define MIN_RT_PRIO 3
#define MAX_RT_PRIO 32765
#define DEF_RT_PRIO 6500

#define RT_PRIO_INTERFACES (Rt_prio + 0  )
#define RT_PRIO_HOSTS      (Rt_prio + 100)
#define RT_PRIO_NETWORKS   (Rt_prio + 199)
#define RT_PRIO_TUNNEL     (Rt_prio + 300)


extern int32_t prio_rules;
#define ARG_PRIO_RULES "prio_rules"


#define ARG_THROW_RULES "throw_rules"

#define ARG_NO_POLICY_RT "no_policy_routing"

#define ARG_PEDANTIC_CLEANUP "pedantic_cleanup"



extern uint8_t if_conf_soft_changed; // temporary enabled to trigger changed interface configuration
extern uint8_t if_conf_hard_changed; // temporary enabled to trigger changed interface configuration

extern int Mtu_min;


struct rules_node {
	struct list_head list;
	uint32_t network;
	uint8_t netmask;
	uint8_t rt_table;
	uint32_t prio;
	char *iif;
	int8_t rule_t;
	int8_t track_t;
};

 
struct routes_node {
	struct list_head list;
	uint32_t dest;
	uint8_t netmask;
	uint8_t rt_table;
	int8_t route_t;
	int8_t track_t;
};


/***
 *
 * route types: 0 = RTN_UNICAST, 1 = THROW, 2 = UNREACHABLE
 *
 ***/
#define RT_UNICAST	0
#define RT_THROW 	1
#define RT_UNREACH	2


//track types:
enum {
	TRACK_NO,
	TRACK_STANDARD,    //basic rules to interfaces, host, and networks routing tables
	TRACK_MY_HNA,
	TRACK_MY_NET,
	TRACK_OTHER_HOST,
	TRACK_OTHER_HNA, 
	TRACK_TUNNEL
};

void add_del_route( uint32_t dest, uint8_t netmask, uint32_t router, uint32_t source, int32_t ifi, char *dev, uint8_t rt_table, int8_t route_type, int8_t del, int8_t track );

/***
 *
 * rule types: 0 = RTA_SRC, 1 = RTA_DST, 2 = RTA_IIF
#define RTA_SRC 0
#define RTA_DST 1
#define RTA_IIF 2
 *
 ***/
 
void add_del_rule( uint32_t network, uint8_t netmask, uint8_t rt_table, uint32_t prio, char *iif, int8_t rule_type, int8_t del, int8_t track );

enum {
 IF_RULE_SET_TUNNEL,
 IF_RULE_CLR_TUNNEL,
 IF_RULE_SET_NETWORKS,
 IF_RULE_CLR_NETWORKS,
 IF_RULE_UPD_ALL,
 IF_RULE_CHK_IPS
};

int update_interface_rules( uint8_t cmd );


void check_kernel_config( struct batman_if *batman_if );

//int8_t bind_to_iface( int32_t sock, char *dev );

//int is_interface_up(char *dev);
void if_deactivate ( struct batman_if *batman_if );
void check_interfaces ();

void init_route( void );
void init_route_args( void );
void cleanup_route( void );


/* hna.c */

#define ARG_HNAS "hnas"


/* tunnel.c */

extern int32_t Gateway_class;
#define ARG_GWTUN_NETW "gateway_tunnel_network"
#define ARG_GATEWAYS "gateways"

#define ARG_RT_CLASS "routing_class"
#define ARG_GW_CLASS "gateway_class"

#ifndef	NOTUNNEL


#define ARG_UNRESP_GW_CHK "unresp_gateway_check"

#define ARG_TWO_WAY_TUNNEL "two_way_tunnel"

#define ARG_ONE_WAY_TUNNEL "one_way_tunnel"

#define ARG_GW_HYSTERESIS "gateway_hysteresis"



#define BATMAN_TUN_PREFIX "bat"
#define MAX_BATMAN_TUN_INDEX 20 

#define TUNNEL_DATA 0x01
#define TUNNEL_IP_REQUEST 0x02
#define TUNNEL_IP_INVALID 0x03
#define TUNNEL_IP_REPLY 0x06

#define GW_STATE_UNKNOWN  0x01
#define GW_STATE_VERIFIED 0x02

#define ONE_MINUTE                60000

#define GW_STATE_UNKNOWN_TIMEOUT  (1  * ONE_MINUTE)
#define GW_STATE_VERIFIED_TIMEOUT (5  * ONE_MINUTE)

#define IP_LEASE_TIMEOUT          (1 * ONE_MINUTE)

#define MAX_TUNNEL_IP_REQUESTS 60 //12
#define TUNNEL_IP_REQUEST_TIMEOUT 1000 // msec

	
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
	unsigned int version:4;  // should be the first field in the packet in network byte order
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


struct gwc_args {
	uint32_t gw_state_stamp;
	uint8_t gw_state;
	uint8_t prev_gw_state;
	uint32_t orig;
	struct gw_node *gw_node;	// pointer to gw node
	struct sockaddr_in gw_addr;	// gateway ip
	char  gw_str[ADDR_STR_LEN];	// string of gateway ip
	struct sockaddr_in my_addr; 	// primary_ip
	uint32_t my_tun_addr;		// ip used for bat0 tunnel interface
	char  my_tun_str[ADDR_STR_LEN];	// string of my_tun_addr
	int32_t mtu_min;
	uint8_t tunnel_type;
	int32_t udp_sock;
	int32_t tun_fd;
	int32_t tun_ifi;
	char tun_dev[IFNAMSIZ];		// was tun_if
	uint32_t tun_ip_request_stamp;
	uint32_t tun_ip_lease_stamp;
	uint32_t tun_ip_lease_duration;
	uint32_t send_tun_ip_requests;
	uint32_t pref_addr;
	//	uint32_t last_invalidip_warning;
};


struct gws_args
{
	int8_t netmask;
	int32_t port;
	int32_t owt;
	int32_t twt;
	int32_t lease_time;
	int mtu_min;
	uint32_t my_tun_ip;
	uint32_t my_tun_netmask;
	uint32_t my_tun_ip_h;
	uint32_t my_tun_suffix_mask_h;
	struct sockaddr_in  client_addr;
	struct gw_client **gw_client_list;
	int32_t sock;
	int32_t tun_fd;
	int32_t tun_ifi;
	char tun_dev[IFNAMSIZ];
};


#define DEF_GWTUN_NETW_PREFIX  "169.254.0.0" /* 0x0000FEA9 */

#define MIN_GWTUN_NETW_MASK 20
#define MAX_GWTUN_NETW_MASK 30
#define DEF_GWTUN_NETW_MASK 22

#define MIN_TUN_LTIME 60 /*seconds*/
#define MAX_TUN_LTIME 60000
#define DEF_TUN_LTIME 600
#define ARG_TUN_LTIME "tunnel_lease_time"


#define MIN_RT_CLASS 0
#define MAX_RT_CLASS 3

// field accessor and flags for gateway announcement extension packets
#define EXT_GW_FIELD_GWTYPES ext_related
#define EXT_GW_FIELD_GWFLAGS def8
#define EXT_GW_FIELD_GWPORT  d16.def16
#define EXT_GW_FIELD_GWADDR  d32.def32

// the flags for gw extension messsage gwtypes:
#define TWO_WAY_TUNNEL_FLAG   0x01
#define ONE_WAY_TUNNEL_FLAG   0x02

struct tun_orig_data {
	
	int16_t  tun_array_len;
	struct ext_packet tun_array[];
	
};

struct plugin_v1 *tun_get_plugin_v1( void );
#endif

#endif
