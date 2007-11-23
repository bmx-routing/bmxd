/*
 * Copyright (C) 2006 B.A.T.M.A.N. contributors:
 * Thomas Lopatic, Corinna 'Elektra' Aichele, Axel Neumann, Marek Lindner
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



#ifndef _BATMAN_BATMAN_H
#define _BATMAN_BATMAN_H

#include <sys/types.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/un.h>
#include <stdint.h>

#include "list-batman.h"
#include "bitarray.h"
#include "hash.h"
#include "allocate.h"
#include "profile.h"
#include "vis-types.h"



#define SOURCE_VERSION "0.3-alpha" //put exactly one distinct word inside the string like "0.3-pre-alpha" or "0.3-rc1" or "0.3"

#define COMPAT_VERSION 9


#define ADDR_STR_LEN 16

#define DEF_UNIX_PATH "/var/run/batmand.socket" //extended by .port where port is the base-port used by the daemon
extern char unix_path[]; 

#define VIS_COMPAT_VERSION 21


#define MAX_DBG_STR_SIZE 1023
#define OUT_SEQNO_OFFSET 2
#define YES 1
#define NO 0


/***
 *
 * Things you should enable via your make file:
 *
 * DEBUG_MALLOC   enables malloc() / free() wrapper functions to detect memory leaks / buffer overflows / etc
 * MEMORY_USAGE   allows you to monitor the internal memory usage (needs DEBUG_MALLOC to work)
 * PROFILE_DATA   allows you to monitor the cpu usage for each function
 *
 ***/


#ifndef REVISION_VERSION
#define REVISION_VERSION "0"
#endif



/*
 * No configuration files or fancy command line switches yet
 * To experiment with B.A.T.M.A.N. settings change them here
 * and recompile the code
 * Here is the stuff you may want to play with:
 */

#define JITTER 100
#define MAX_GW_UNAVAIL_FACTOR 2 /* 10 */
#define MAX_GW_UNAVAIL_TIMEOUT 30000 /* 10000 */
#define CHOOSE_GW_DELAY_DIVISOR 10 /* 1 */

#define PURGE_SAFETY_PERIOD 10000
#define PURGE_TIMEOUT (((originator_interval*sequence_range*dad_timeout)/50) + PURGE_SAFETY_PERIOD) /*=2*o*nbrf*dad/100=300s previously 400000*/   /* purge originators after time in ms if no valid packet comes in -> TODO: check influence on SEQ_RANGE */

#define WARNING_PERIOD 20000

#define BATMAN_TUN_PREFIX "bat"
#define MAX_BATMAN_TUN_INDEX 20 

#define TEST_SWITCH              "test"

#define MAX_PACKET_OUT_SIZE 300
	
extern int32_t aggregations_po;


#define AGGREGATIONS_SWITCH    "ogm-aggregation"
#define NO_AGGREGATIONS_SWITCH "no-ogm-aggregation"
#define AGGREGATIONS_PO_SWITCH "aggregations-per-interval"
#define MIN_AGGREGATIONS_PO 2
#define MAX_AGGREGATIONS_PO 20
#define DEF_AGGREGATIONS_PO NO
#define ENABLED_AGGREGATIONS_PO "4"

extern int32_t sequence_range;
#define FULL_SEQ_RANGE ((uint16_t)-1)
#define MAX_SEQ_RANGE 250      /* TBD: should not be larger until neigh_node.packet_count (and related variables) is only 8 bit */
#define MIN_SEQ_RANGE 1
#define DEFAULT_SEQ_RANGE 128  /* NBRF: NeighBor Ranking sequence Frame) sliding packet range of received orginator messages in squence numbers (should be a multiple of our word size) */
#define NBRFSIZE_SWITCH          "window-size"

#define MAX_NUM_WORDS (( MAX_SEQ_RANGE / WORD_BIT_SIZE ) + ( ( MAX_SEQ_RANGE % WORD_BIT_SIZE > 0)? 1 : 0 )) 

extern int32_t initial_seqno;
#define MIN_INITIAL_SEQNO 0
#define MAX_INITIAL_SEQNO FULL_SEQ_RANGE
#define DEF_INITIAL_SEQNO 0 /* causes initial_seqno to be randomized */
#define INITIAL_SEQNO_SWITCH "initial-seqno"

extern int16_t originator_interval;
#define DEFAULT_ORIGINATOR_INTERVAL 1000
#define MIN_ORIGINATOR_INTERVAL JITTER
#define MAX_ORIGINATOR_INTERVAL 10000 

extern int32_t dad_timeout;
#define DEFAULT_DAD_TIMEOUT 100
#define MIN_DAD_TIMEOUT 50 /* if this is changed, be careful with PURGE_TIMEOUT */
#define MAX_DAD_TIMEOUT 400
#define DAD_TIMEOUT_SWITCH "dad-timeout"


extern uint8_t mobile_device;
#define ASOCIAL_SWITCH           "asocial-device"

extern uint8_t no_unreachable_rule;
#define NO_UNREACHABLE_RULE_SWITCH  "no-unreachable-rule"

extern uint8_t no_forw_dupl_ttl_check;

extern uint8_t no_tun_persist;
#define NO_TUNPERSIST_SWITCH  "no-tunpersist"

extern int32_t bidirect_link_to;
#define DEFAULT_BIDIRECT_TIMEOUT 2  
#define MAX_BIDIRECT_TIMEOUT 100
#define MIN_BIDIRECT_TIMEOUT 1
#define BIDIRECT_TIMEOUT_SWITCH         "bi-link-timeout"
#define BIDIRECT_TIMEOUT_IF_SWITCH      'b'

extern int32_t ttl;
#define DEFAULT_TTL 50                /* Time To Live of broadcast messages */
#define MAX_TTL 63
#define MIN_TTL 1 /* Values smaller than two currently do not work */
#define TTL_SWITCH               "t"
#define TTL_IF_SWITCH		 't'

extern int32_t dup_ttl_limit;
#define DEF_DUP_TTL_LIMIT 0
#define MIN_DUP_TTL_LIMIT 0
#define MAX_DUP_TTL_LIMIT 10
#define DUP_TTL_LIMIT_SWITCH	 "dups-ttl"

extern int32_t dup_rate;
#define DEF_DUP_RATE 0
#define MIN_DUP_RATE 0
#define MAX_DUP_RATE 100
#define DUP_RATE_SWITCH	         "dups-rate"

extern int32_t dup_degrad;
#define DEF_DUP_DEGRAD 0
#define MIN_DUP_DEGRAD 0
#define MAX_DUP_DEGRAD 100
#define DUP_DEGRAD_SWITCH	  "dups-ttl-degradation"

extern int32_t send_clones; // useful for asymmetric-path and backup-path discovery
#define DEF_SEND_CLONES 100
#define MIN_SEND_CLONES 0
#define MAX_SEND_CLONES 300
#define SEND_CLONES_SWITCH   "send-clones"
#define SEND_CLONES_IF_SWITCH 'c'

#define WLAN_IF_SWITCH 'w'
#define DEF_WLAN_IF_CLONES 200

#define LAN_IF_SWITCH 'l'
#define DEF_LAN_IF_CLONES 100


extern int32_t asymmetric_weight;
#define DEF_ASYMMETRIC_WEIGHT 0
#define MIN_ASYMMETRIC_WEIGHT 0
#define MAX_ASYMMETRIC_WEIGHT 100
#define ASYMMETRIC_WEIGHT_SWITCH "asymmetric-weight"

extern int32_t asymmetric_exp;
#define DEF_ASYMMETRIC_EXP 0
#define MIN_ASYMMETRIC_EXP 0
#define MAX_ASYMMETRIC_EXP 3
#define ASYMMETRIC_EXP_SWITCH    "asymmetric-exp"

extern int32_t rebrc_delay;
#define DEF_REBRC_DELAY 0
#define MIN_REBRC_DELAY 0
#define MAX_REBRC_DELAY 100
#define REBRC_DELAY_SWITCH     "re-brc-delay"

extern int32_t penalty_min;
#define DEF_PENALTY_MIN 0
#define MIN_PENALTY_MIN 1
#define MAX_PENALTY_MIN (MAX_SEQ_RANGE/2) /* TBD: this must adapt to the configured value */
#define PENALTY_MIN_SWITCH       "penalty-min"

extern int32_t penalty_exceed;
#define DEF_PENALTY_EXCEED 2
#define MIN_PENALTY_EXCEED 1
#define MAX_PENALTY_EXCEED 10
#define PENALTY_EXCEED_SWITCH    "penalty-exceed"

//extern int8_t advanced_opts;
#define ADVANCED_SWITCH          "dangerous"
//#define DEF_ADVANCED_SWITCH NO;

extern int8_t resist_blocked_send;
#define RESIST_BLOCKED_SEND_SWITCH "resist-blocked-send"
#define DEF_RESIST_BLOCKED_SEND NO

//extern int8_t bmx_defaults;
//#define DEF_BMX_DEFAULTS          0
#define BMX_DEFAULTS_SWITCH      "bmx-defaults"
#define GENIII_DEFAULTS_SWITCH   "generation-III"
#define GRAZ07_DEFAULTS_SWITCH   "graz-2007"

//#define MIN_BMX_PARA_SET   0
#define PARA_SET_GENIII    1
#define PARA_SET_BMX       2
#define PARA_SET_GRAZ07    3
//#define MAX_BMX_PARA_SET   3

extern int32_t default_para_set;
#define DEF_BMX_PARA_SET PARA_SET_BMX

#define OGM_ONLY_VIA_OWNING_IF_SWITCH 'i'
#define MAKE_IP_HNA_IF_SWITCH 'a'
#define UNDO_IP_HNA_IF_SWITCH 'A'

extern int32_t base_port;
#define BASE_PORT_SWITCH "base-port"
#define DEF_BASE_PORT 4305
#define MIN_BASE_PORT 1025
#define MAX_BASE_PORT 60000

#define PORT base_port



/***
 *
 * Things you should leave as is unless your know what you are doing !
 *
 * BATMAN_RT_TABLE_INTERFACES	routing table for announced (non-primary) interfaces IPs and other unique IP addresses
 * BATMAN_RT_TABLE_NETWORKS	routing table for announced networks
 * BATMAN_RT_TABLE_HOSTS	routing table for routes towards originators
 * BATMAN_RT_TABLE_UNREACH	routing table for unreachable routing entry
 * BATMAN_RT_TABLE_TUNNEL	routing table for the tunnel towards the internet gateway
 * BATMAN_RT_PRIO_DEFAULT	standard priority for routing rules
 * BATMAN_RT_PRIO_UNREACH	standard priority for unreachable rules
 * BATMAN_RT_PRIO_TUNNEL	standard priority for tunnel routing rules
 *
 ***/



extern int32_t rt_table_offset;
#define RT_TABLE_OFFSET_SWITCH "rt-table-offset"
#define DEF_RT_TABLE_OFFSET 64
#define MIN_RT_TABLE_OFFSET 2
#define MAX_RT_TABLE_OFFSET 240

#define BATMAN_RT_TABLE_INTERFACES (rt_table_offset + 0)
#define BATMAN_RT_TABLE_NETWORKS   (rt_table_offset + 1)
#define BATMAN_RT_TABLE_HOSTS      (rt_table_offset + 2)
#define BATMAN_RT_TABLE_UNREACH    (rt_table_offset + 3)
#define BATMAN_RT_TABLE_TUNNEL     (rt_table_offset + 4)


extern int32_t rt_prio_offset;
#define RT_PRIO_OFFSET_SWITCH "prio-rules-offset"
#define MIN_RT_PRIO_OFFSET 3
#define MAX_RT_PRIO_OFFSET 32765
#define DEF_RT_PRIO_OFFSET 6500

#define BATMAN_RT_PRIO_INTERFACES (rt_prio_offset + 0  )
#define BATMAN_RT_PRIO_HOSTS      (rt_prio_offset + 100)
#define BATMAN_RT_PRIO_NETWORKS   (rt_prio_offset + 199)
#define BATMAN_RT_PRIO_UNREACH    (rt_prio_offset + 200)
#define BATMAN_RT_PRIO_TUNNEL     (rt_prio_offset + 300)

extern int32_t more_rules;
#define MORE_RULES_SWITCH "more-rules"
#define DEF_MORE_RULES NO

extern int32_t no_prio_rules;
#define NO_PRIO_RULES_SWITCH "no-prio-rules"
#define DEF_NO_PRIO_RULES NO

extern int32_t no_throw_rules;
#define NO_THROW_RULES_SWITCH "no-throw-rules"
#define DEF_NO_THROW_RULES NO

extern int32_t no_unresponsive_check;
#define NO_UNRESP_CHECK_SWITCH "no-unresp-gw-check"
#define DEF_NO_UNRESP_CHECK NO

extern int32_t two_way_tunnel;
#define TWO_WAY_TUNNEL_SWITCH "two-way-tunnel"
#define DEF_TWO_WAY_TUNNEL 2
#define MIN_TWO_WAY_TUNNEL 0
#define MAX_TWO_WAY_TUNNEL 4

extern int32_t one_way_tunnel;
#define ONE_WAY_TUNNEL_SWITCH "one-way-tunnel"
#define DEF_ONE_WAY_TUNNEL 0
#define MIN_ONE_WAY_TUNNEL 0
#define MAX_ONE_WAY_TUNNEL 4

extern int32_t gw_change_hysteresis;
#define GW_CHANGE_HYSTERESIS_SWITCH "gw-change-hysteresis"
#define DEF_GW_CHANGE_HYSTERESIS 1
#define MIN_GW_CHANGE_HYSTERESIS 1
#define MAX_GW_CHANGE_HYSTERESIS ((sequence_range / 2) + 1) /*TBD: what if sequence range is decreased after setting this? */

extern uint32_t gw_tunnel_prefix;
extern uint8_t  gw_tunnel_netmask;
#define DEF_GW_TUNNEL_PREFIX_STR  "169.254.0.0" /* 0x0000FEA9 */
#define MIN_GW_TUNNEL_NETMASK 20
#define MAX_GW_TUNNEL_NETMASK 30
#define DEF_GW_TUNNEL_NETMASK 22
#define GW_TUNNEL_NETW_SWITCH "gw-tunnel-network"

extern int32_t tunnel_ip_lease_time;
#define MIN_TUNNEL_IP_LEASE_TIME 60 /*seconds*/
#define MAX_TUNNEL_IP_LEASE_TIME 60000
#define DEF_TUNNEL_IP_LEASE_TIME 60
#define TUNNEL_IP_LEASE_TIME_SWITCH "tunnel-lease-time"

#define PARALLEL_BAT_NETA_SWITCH "neta"
#define PARALLEL_BAT_NETB_SWITCH "netb"
#define PARALLEL_BAT_NETC_SWITCH "netc"

extern uint8_t routing_class;

extern uint8_t gateway_class;



/***
 *
 * ports which are to ignored by the blackhole check
 *
 ***/

#define BH_UDP_PORTS {4307, 162} /* vis, SNMP-TRAP */





extern char *prog_name;
extern uint8_t debug_level;
//extern uint8_t debug_level_max;
#define debug_level_max 8
#define DBGL_SYSTEM     0
#define DBGL_ROUTES     1
#define DBGL_GATEWAYS   2
#define DBGL_CHANGES    3
#define DBGL_ALL        4
#define DBGL_PROFILE    5
#define DBGL_DETAILS    8



extern struct ext_packet *my_hna_ext_array;
extern uint16_t my_hna_ext_array_len;

extern struct ext_packet *my_gw_ext_array;
extern uint16_t my_gw_ext_array_len;

extern uint16_t hna_list_size;


extern int16_t num_words;

extern uint32_t pref_gateway;

extern int8_t stop;

extern struct gw_listen_arg gw_listen_arg;

extern struct gw_node *curr_gateway;
extern pthread_t curr_gateway_thread_id;

extern uint8_t found_ifs;
extern int32_t receive_max_sock;
extern fd_set receive_wait_set;

extern uint8_t unix_client;

extern struct hashtable_t *orig_hash;
extern struct hashtable_t *hna_hash;

extern struct list_head_first if_list;
extern struct list_head_first hna_list;
extern struct list_head_first gw_list;
extern struct list_head_first forw_list;
extern struct vis_if vis_if;
extern struct unix_if unix_if;
extern struct debug_clients debug_clients;

/* the bat_packet flags: */
#define UNIDIRECTIONAL_FLAG 0x02 /* set when re-broadcasting a received OGM via a curretnly not bi-directional link and only together with IDF */
#define DIRECTLINK_FLAG     0x04 /* set when re-broadcasting a received OGM with identical OG IP and NB IP on the interface link as received */
#define CLONED_FLAG         0x08 /* set when (re-)broadcasting a OGM not-for-the-first time or re-broadcasting a OGM with this flag */

#define EXTENSION_FLAG       0x01 /* unset for OGM, set for OGM related extensions like HNA,... */



/* the flags for bat_packet gwtypes: */
#define TWO_WAY_TUNNEL_FLAG   0x01
#define ONE_WAY_TUNNEL_FLAG   0x02


struct bat_packet
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int flags:4;    /* 0x08: UNIDIRECTIONAL link, 0x04: DIRECTLINK flag, ... */
	unsigned int version:4;  /* should be the first field in the packet in network byte order */
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int version:4;
	unsigned int flags:4;
#else
# error "Please fix <bits/endian.h>"
#endif
	uint8_t  ttl;
	uint16_t seqno;
	uint32_t orig;
	uint32_t prev_hop;
	
} __attribute__((packed));

struct orig_node                 /* structure for orig_list maintaining nodes of mesh */
{
	uint32_t orig;          /* this must be the first four bytes! otherwise the hash functionality does not work */
	struct neigh_node *router;   /* the neighbor which is the currently best_next_hop */
	struct batman_if *batman_if; /* TBD: can this be removed? This equals router->if_incoming ?! the interface to route towards the currently best next hop */
	uint16_t *bidirect_link;    /* if node is a bidrectional neighbour, when my originator packet was broadcasted (replied) by this node and received by me */
	uint32_t last_valid;              /* when last packet from this node was received */
	uint32_t first_valid_sec;
	uint8_t  gwflags;                 /* flags related to gateway functions: gateway class */
	uint8_t  gwtypes;                 /* flags related to offered gateway tunnel types */
	struct ext_packet *hna_array;
	int16_t  hna_array_len;
	uint16_t last_seqno;              /* last and best known squence number */
	
	uint8_t last_seqno_largest_ttl;	  /* largest (best) TTL received with last sequence number */
	
	TYPE_OF_WORD *bi_link_bits;       /* for bidirect-link statistics */
	uint16_t *last_bi_link_seqno;     /* for bidirect-link statistics */
	
	TYPE_OF_WORD *lq_bits;            /* for link-quality (lq) statistics */
	uint16_t last_lq_seqno;           /* for link-quality (lq) statistics */
	
//	TYPE_OF_WORD send_old_seq_bits[ MAX_NUM_WORDS ]; /* just for debugging, indicates the re-broadcasted (non-unidirectional and non-quickest) OGMs for this foreign OG */
	
	TYPE_OF_WORD *dbg_rcvd_bits;
	uint16_t last_dbg_rcvd_seqno;
	
	
	struct list_head_first neigh_list;
};

struct neigh_node
{
	struct list_head list;
	uint32_t addr;
	uint16_t last_considered_seqno;
	uint8_t packet_count;
	uint8_t penalty_count;
	uint8_t  last_ttl;         /* ttl of last received packet */
	uint32_t last_valid;            /* when last packet via this neighbour was received */
	TYPE_OF_WORD seq_bits[ MAX_NUM_WORDS ];
	struct batman_if *if_incoming;
};

#define A_TYPE_INTERFACE 0x00
#define A_TYPE_NETWORK   0x01
#define A_TYPE_MAX       0x01

struct hna_netmask_type
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int anetmask:6;
	unsigned int atype:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int atype:2;
	unsigned int anetmask:6;
#else
# error "Please fix <bits/endian.h>"
#endif
} __attribute__((packed));



#define EXT_HNA_TYPE    et.hna.nt.atype
#define EXT_HNA_NETMASK et.hna.nt.anetmask
#define EXT_HNA_ADDR    et.hna.addr

struct ext_type_hna
{
	struct hna_netmask_type nt;
	uint32_t addr;
} __attribute__((packed));


#define EXT_GW_TYPES et.gw.gwtypes
#define EXT_GW_FLAGS et.gw.gwflags

struct ext_type_gw
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int gwtypes:4;  /* to let a gw announce its offered gateway types */
	unsigned int reserved:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int reserved:4;
	unsigned int gwtypes:4;
#else
# error "Please fix <bits/endian.h>"
#endif
	
	uint8_t  gwflags;     /* flags related to gateway functions: gateway class */
	
	uint8_t  reserved2;
	uint8_t  reserved3;
	uint8_t  reserved4;

} __attribute__((packed));

#define EXT_TYPE_GW  0x00
#define EXT_TYPE_HNA 0x01

struct ext_packet
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ext_flag:1;
	unsigned int ext_type:3;
	unsigned int ext_reserved:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int ext_reserved:4;
	unsigned int ext_type:3;
	unsigned int ext_flag:1;
#else
# error "Please fix <bits/endian.h>"
#endif

	union
	{
		struct ext_type_gw  gw;
		struct ext_type_hna hna;
	}et;

} __attribute__((packed));


#define KEY_ATYPE    nt.atype
#define KEY_ANETMASK nt.anetmask

struct hna_key
{
	uint32_t addr;
	struct hna_netmask_type nt;
} __attribute__((packed));	

struct hna_node
{
	struct list_head list;
	struct hna_key key;
};


#define  HNA_HASH_NODE_EMPTY 0x00
#define  HNA_HASH_NODE_MYONE 0x01
#define  HNA_HASH_NODE_OTHER 0x02

struct hna_hash_node
{
	struct hna_key key;

	struct orig_node *orig;
	uint8_t status;

};

struct forw_node                 /* structure for forw_list maintaining packets to be send/forwarded */
{
	struct list_head list;
	uint32_t send_time;
	uint8_t  own;
	unsigned char *pack_buff;
	int32_t  pack_buff_len;
	struct batman_if *if_outgoing;
};

struct gw_node
{
	struct list_head list;
	struct orig_node *orig_node;
	uint16_t unavail_factor;
	uint32_t last_failure;
	uint32_t deleted;
};

struct batman_if
{
	struct list_head list;
	char *dev;
	int32_t udp_send_sock;
	int32_t udp_recv_sock;
	int32_t udp_tunnel_sock;
	int32_t if_index;
	int16_t if_num;
	uint8_t if_rp_filter_old;
	uint8_t if_send_redirects_old;
	pthread_t listen_thread_id;
	struct sockaddr_in addr;
	struct sockaddr_in broad;
	struct bat_packet out;
	uint32_t netaddr;
	uint8_t netmask;
	uint8_t if_ttl;
	uint8_t if_bidirect_link_to;
	uint8_t send_ogm_only_via_owning_if;
	int16_t if_send_clones;
	int16_t packet_out_len;
	unsigned char packet_out[MAX_PACKET_OUT_SIZE + 1];
	uint8_t send_own;
};

struct gw_listen_arg
{
	struct batman_if *batman_if;
	struct gw_client **gw_client_list; 
};
	

struct gw_client
{
	uint32_t addr;
	uint32_t last_keep_alive;
};

struct vis_if {
	int32_t sock;
	struct sockaddr_in addr;
};

struct unix_if {
	int32_t unix_sock;
	pthread_t listen_thread_id;
	struct sockaddr_un addr;
	struct list_head_first client_list;
};

struct unix_client {
	struct list_head list;
	int32_t sock;
	uint8_t debug_level;
};

struct debug_clients {
	void **fd_list;
	int16_t *clients_num;
	pthread_mutex_t **mutex;
};

struct debug_level_info {
	struct list_head list;
	int32_t fd;
};

struct curr_gw_data {
	unsigned int orig;
	struct gw_node *gw_node;
	struct batman_if *batman_if;
};


struct data_packet {
	struct list_head list;
	uint8_t header_buff[80];	/* IP header max (60) + TCP (20) / UDP (8) */
};


int8_t batman( void );
void usage( void );
void verbose_usage( void );
void print_advanced_opts ( int verbose );
int is_batman_if( char *dev, struct batman_if **batman_if );
void update_routes( struct orig_node *orig_node, struct neigh_node *neigh_node, struct ext_packet *hna_array, int16_t hna_array_len );
void update_gw_list( struct orig_node *orig_node, uint8_t new_gwflags, uint8_t new_gwtypes );
void get_gw_speeds( unsigned char class, int *down, int *up );
unsigned char get_gw_class( int down, int up );
void choose_gw();
struct hna_hash_node *get_hna_node( struct hna_key *hk );


#endif
