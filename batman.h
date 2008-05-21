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

#define COMPAT_VERSION 10 /* set me back to 10 !!!!!!!!!!!!!!!!!!!!!!!*/


#define ADDR_STR_LEN 16

#define DEF_UNIX_PATH "/var/run/batmand.socket" //extended by .port where port is the base-port used by the daemon
extern char unix_path[]; 


#define VIS_COMPAT_VERSION 21


#define MAX_DBG_STR_SIZE 1023
#define OUT_SEQNO_OFFSET 2
#define YES 1
#define NO 0

#define DEBUG_RCVD_ALL_BITS YES

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
#define MAX_GW_UNAVAIL_FACTOR 10 /* 10 */
#define GW_UNAVAIL_TIMEOUT 10000
#define CHOOSE_GW_DELAY_DIVISOR 10 /* 1 */

#define MAX_SELECT_TIMEOUT_MS 200 /* MUST be smaller than (1000/2) to fit into max tv_usec */


#define TP32 4294967296
#define OV32 2147483647
#define TP16 65536
#define OV16 32767
#define TP8  256
#define OV8  127

#define LESS_U8( a, b )  ( ((uint8_t)( (a) - (b) ) ) >  OV8 )
#define LSEQ_U8( a, b )  ( ((uint8_t)( (b) - (a) ) ) <= OV8 )
#define GREAT_U8( a, b ) ( ((uint8_t)( (b) - (a) ) ) >  OV8 )
#define GRTEQ_U8( a, b ) ( ((uint8_t)( (a) - (b) ) ) <= OV8 )

#define LESS_U16( a, b )  ( ((uint16_t)( (a) - (b) ) ) >  OV16 )
#define LSEQ_U16( a, b )  ( ((uint16_t)( (b) - (a) ) ) <= OV16 )
#define GREAT_U16( a, b ) ( ((uint16_t)( (b) - (a) ) ) >  OV16 )
#define GRTEQ_U16( a, b ) ( ((uint16_t)( (a) - (b) ) ) <= OV16 )
	
#define LESS_U32( a, b )  ( ((uint32_t)( (a) - (b) ) ) >  OV32 )
#define LSEQ_U32( a, b )  ( ((uint32_t)( (b) - (a) ) ) <= OV32 )
#define GREAT_U32( a, b ) ( ((uint32_t)( (b) - (a) ) ) >  OV32 )
#define GRTEQ_U32( a, b ) ( ((uint32_t)( (a) - (b) ) ) <= OV32 )


#define WARNING_PERIOD 20000

#define BATMAN_TUN_PREFIX "bat"
#define MAX_BATMAN_TUN_INDEX 20 

#define TEST_SWITCH            "test"

#define MAX_PACKET_OUT_SIZE 256
#define MAX_AGGREGATION_INTERVAL_MS 250


enum {
 REQ_RESET,
 REQ_DEBUG,
 REQ_RT_CLASS,
 REQ_PREF_GW,
 REQ_GW_CLASS,
 REQ_1WT,
 REQ_2WT,
 REQ_PWS,
 REQ_LWS,
 REQ_DTD,
 REQ_OGI,
 REQ_CHANGE_HNA,
 REQ_CHANGE_SRV,
 REQ_INFO,
 REQ_FAKE_TIME,
 REQ_DEFAULT
};

extern int32_t aggregations_po;

#define AGGREGATIONS_SWITCH    "ogm-aggregation"
#define NO_AGGREGATIONS_SWITCH "no-ogm-aggregation"
#define AGGREGATIONS_PO_SWITCH "aggregations-per-interval"
#define MIN_AGGREGATIONS_PO 2
#define MAX_AGGREGATIONS_PO 20
#define DEF_AGGREGATIONS_PO 5

extern int32_t my_ws;
#define FULL_SEQ_RANGE ((uint16_t)-1)
#define MAX_SEQ_RANGE 250      /* TBD: should not be larger until ogm->ws and neigh_node.packet_count (and related variables) is only 8 bit */
#define MIN_SEQ_RANGE 1
#define DEF_SEQ_RANGE 100  /* NBRF: NeighBor Ranking sequence Frame) sliding packet range of received orginator messages in squence numbers (should be a multiple of our word size) */
#define NBRFSIZE_SWITCH          "window-size"

#define MAX_NUM_WORDS (( MAX_SEQ_RANGE / WORD_BIT_SIZE ) + ( ( MAX_SEQ_RANGE % WORD_BIT_SIZE > 0)? 1 : 0 )) 

extern int32_t initial_seqno;
#define MIN_INITIAL_SEQNO 0
#define MAX_INITIAL_SEQNO FULL_SEQ_RANGE
#define DEF_INITIAL_SEQNO 0 /* causes initial_seqno to be randomized */
#define INITIAL_SEQNO_SWITCH "initial-seqno"


extern int32_t fake_uptime;
#define MIN_FAKE_UPTIME 0
#define MAX_FAKE_UPTIME 4292967
#define DEF_FAKE_UPTIME 0 
#define FAKE_UPTIME_SWITCH "fake-uptime"


extern int16_t my_ogi;
#define DEFAULT_ORIGINATOR_INTERVAL 1000 //1000
#define MIN_ORIGINATOR_INTERVAL JITTER
#define MAX_ORIGINATOR_INTERVAL 10000 

extern int32_t dad_timeout;
#define DEFAULT_DAD_TIMEOUT 100 //100
#define MIN_DAD_TIMEOUT 50 /* if this is changed, be careful with PURGE_TIMEOUT */
#define MAX_DAD_TIMEOUT 400
#define DAD_TIMEOUT_SWITCH "dad-timeout"

#define PURGE_SAFETY_PERIOD 25000 //25000
#define MY_PURGE_TIMEOUT (((((DEFAULT_ORIGINATOR_INTERVAL)*(my_ws)*(dad_timeout))/50) + PURGE_SAFETY_PERIOD)/1000)


extern uint8_t mobile_device;
#define ASOCIAL_SWITCH           "asocial-device"

extern uint8_t no_unreachable_rule;
#define NO_UNREACHABLE_RULE_SWITCH  "no-unreachable-rule"

extern uint8_t no_forw_dupl_ttl_check;

extern uint8_t no_tun_persist;
#define NO_TUNPERSIST_SWITCH  "no-tunpersist"

extern int32_t bidirect_link_to;
#define DEF_BIDIRECT_TIMEOUT 50 //100, 30 for 24C3
#define MAX_BIDIRECT_TIMEOUT 250
#define MIN_BIDIRECT_TIMEOUT 1
#define BIDIRECT_TIMEOUT_SWITCH         "link-window-size"
//#define BIDIRECT_TIMEOUT_IF_SWITCH      'b'

extern int32_t ttl;
#define DEFAULT_TTL 50                /* Time To Live of broadcast messages */
#define MAX_TTL 63
#define MIN_TTL 1 /* Values smaller than two currently do not work */
#define TTL_SWITCH               "t"
#define TTL_IF_SWITCH		 't'

extern int32_t dup_ttl_limit;
#define DEF_DUP_TTL_LIMIT 5
#define MIN_DUP_TTL_LIMIT 0
#define MAX_DUP_TTL_LIMIT 10
#define DUP_TTL_LIMIT_SWITCH	 "dups-ttl"

extern int32_t dup_rate;
#define DEF_DUP_RATE 99
#define MIN_DUP_RATE 0
#define MAX_DUP_RATE 100
#define DUP_RATE_SWITCH	         "dups-rate"

extern int32_t dup_degrad;
#define DEF_DUP_DEGRAD 2 /* FIXME: set me back to 2 ?? !!!!!!!!! */
#define MIN_DUP_DEGRAD 0
#define MAX_DUP_DEGRAD 100
#define DUP_DEGRAD_SWITCH	  "dups-ttl-degradation"

extern int32_t wl_clones;
#define DEF_WL_CLONES 200
#define MIN_WL_CLONES 0
#define MAX_WL_CLONES 400
#define WL_CLONES_SWITCH   "send-clones"

#define CLONES_IF_SWITCH 'c'

#define WLAN_IF_SWITCH 'w'
//#define DEF_WLAN_IF_CLONES send_clones

#define LAN_IF_SWITCH 'l'
#define DEF_LAN_CLONES 100


extern int32_t asymmetric_weight;
#define DEF_ASYMMETRIC_WEIGHT 100
#define MIN_ASYMMETRIC_WEIGHT 0
#define MAX_ASYMMETRIC_WEIGHT 100
#define ASYMMETRIC_WEIGHT_SWITCH "asymmetric-weight"

extern int32_t asymmetric_exp;
#define DEF_ASYMMETRIC_EXP 1
#define MIN_ASYMMETRIC_EXP 0
#define MAX_ASYMMETRIC_EXP 3
#define ASYMMETRIC_EXP_SWITCH    "asymmetric-exp"

extern int32_t rebrc_delay;
#define DEF_REBRC_DELAY 0
#define MIN_REBRC_DELAY 0
#define MAX_REBRC_DELAY 100
#define REBRC_DELAY_SWITCH     "re-brc-delay"


//extern int8_t advanced_opts;
#define ADVANCED_SWITCH          "dangerous"
//#define DEF_ADVANCED_SWITCH NO;


#define ADD_SRV_SWITCH "add-service"

#define DEL_SRV_SWITCH "del-service"


extern int8_t resist_blocked_send;
#define RESIST_BLOCKED_SEND_SWITCH "resist-blocked-send"
#define DEF_RESIST_BLOCKED_SEND NO

#define BMX_DEFAULTS_SWITCH      "bmx-defaults"
#define GENIII_DEFAULTS_SWITCH   "generation-III"
#define GRAZ07_DEFAULTS_SWITCH   "graz-2007"

#define PARA_SET_GENIII    1
#define PARA_SET_BMX       2
#define PARA_SET_GRAZ07    3

extern int32_t default_para_set;
#define DEF_PARA_SET PARA_SET_BMX

#define OGM_ONLY_VIA_OWNING_IF_SWITCH 'i'
#define MAKE_IP_HNA_IF_SWITCH 'a'
#define UNDO_IP_HNA_IF_SWITCH 'A'

extern int32_t ogm_port;
#define BASE_PORT_SWITCH "base-port"
#define DEF_BASE_PORT 4305
#define MIN_BASE_PORT 1025
#define MAX_BASE_PORT 60000

extern int32_t my_gw_port;
#define DEF_GW_PORT 0 /* use ogm_port + 1 */

extern uint32_t my_gw_addr;
#define DEF_GW_ADDR 0 /* use primary interface addr */

extern int32_t vis_port;
#define DEF_VIS_PORT 4307

//#define PORT base_port




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

extern int32_t no_lo_rule;
#define NO_LO_RULE_SWITCH "no-lo-rule"
#define DEF_NO_LO_RULE NO

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
#define DEF_ONE_WAY_TUNNEL 1
#define MIN_ONE_WAY_TUNNEL 0
#define MAX_ONE_WAY_TUNNEL 4

extern int32_t gw_change_hysteresis;
#define GW_CHANGE_HYSTERESIS_SWITCH "gw-change-hysteresis"
#define DEF_GW_CHANGE_HYSTERESIS 2
#define MIN_GW_CHANGE_HYSTERESIS 1
#define MAX_GW_CHANGE_HYSTERESIS ((my_ws / 2) + 1) /*TBD: what if sequence range is decreased after setting this? */

extern uint32_t gw_tunnel_prefix;
extern uint8_t  gw_tunnel_netmask;
#define DEF_GW_TUNNEL_PREFIX_STR  "169.254.0.0" /* 0x0000FEA9 */
#define MIN_GW_TUNNEL_NETMASK 20
#define MAX_GW_TUNNEL_NETMASK 30
#define DEF_GW_TUNNEL_NETMASK 22
#define GW_TUNNEL_NETW_SWITCH "gw-tunnel-network"

#define NO_TUNNEL_RULE_SWITCH "no-tunnel-rule"


extern int32_t tunnel_ip_lease_time;
#define MIN_TUNNEL_IP_LEASE_TIME 60 /*seconds*/
#define MAX_TUNNEL_IP_LEASE_TIME 60000
#define DEF_TUNNEL_IP_LEASE_TIME 600
#define TUNNEL_IP_LEASE_TIME_SWITCH "tunnel-lease-time"

#define PARALLEL_BAT_NETA_SWITCH "neta"
#define PARALLEL_BAT_NETB_SWITCH "netb"
#define PARALLEL_BAT_NETC_SWITCH "netc"

#define PARALLEL_BAT_24C3_SWITCH "24c3"

extern uint8_t routing_class;

extern uint8_t gateway_class;






extern char *prog_name;
extern uint8_t debug_level;
#define DBGL_SYSTEM     0
#define DBGL_ROUTES     1
#define DBGL_GATEWAYS   2
#define DBGL_CHANGES    3
#define DBGL_ALL        4
#define DBGL_PROFILE    5
#define DBGL_STATISTICS 6
#define DBGL_SERVICES   7
#define DBGL_DETAILS    8
#define DBGL_HNAS       9
#define debug_level_max 9


// my HNA extension messages (attached to all primary OGMs)
extern struct ext_packet *my_hna_ext_array;
extern uint16_t my_hna_ext_array_len;
extern uint16_t my_hna_list_enabled;

// my service extension messages (attached to all primary OGMs)
extern struct ext_packet *my_srv_ext_array;
extern uint16_t my_srv_ext_array_len;
extern uint16_t my_srv_list_enabled;

// my gw extension message (attached to all primary OGMs)
extern struct ext_packet *my_gw_ext_array;
extern uint16_t my_gw_ext_array_len;

// primary IP extension message (attached to all non-primary OGMs)
extern struct ext_packet *my_pip_ext_array;
extern uint16_t my_pip_ext_array_len;



extern uint32_t pref_gateway;

extern uint8_t no_policy_routing;


extern int8_t stop;

//extern struct gw_listen_arg gw_listen_arg;

extern struct gw_node *curr_gateway;
extern pthread_t curr_gateway_thread_id;

extern uint8_t found_ifs;
extern uint8_t active_ifs;
extern int32_t receive_max_sock;
extern fd_set receive_wait_set;

extern uint8_t conn_client;

extern uint8_t log_facility_active;

extern int ifevent_sk;

extern int g_argc;
extern char **g_argv;


extern struct bat_packet **received_ogm;
extern uint32_t           *received_neigh;
extern struct batman_if  **received_if_incoming;
extern uint32_t           *received_batman_time;

extern struct ext_packet **received_gw_array;
extern int16_t            *received_gw_pos;
extern struct ext_packet **received_hna_array;
extern int16_t            *received_hna_pos;
extern struct ext_packet **received_srv_array;
extern int16_t            *received_srv_pos;
extern struct ext_packet **received_vis_array;
extern int16_t            *received_vis_pos;
extern struct ext_packet **received_pip_array;
extern int16_t            *received_pip_pos;


extern struct hashtable_t *orig_hash;
extern struct hashtable_t *hna_hash;

extern pthread_mutex_t *todo_mutex;

extern struct list_head_first if_list;
extern struct list_head_first forw_list;
extern struct list_head_first todo_list;
extern struct list_head_first my_hna_list;
extern struct list_head_first my_srv_list;
extern struct list_head_first gw_list;
extern struct list_head_first notun_list;
extern struct list_head_first link_list;
extern struct list_head_first pifnb_list;

extern struct vis_if vis_if;
extern struct unix_if unix_if;

extern pthread_t gw_thread_id;

extern int gw_thread_finish;


extern struct debug_clients debug_clients;


extern int s_returned_select;
extern int s_received_aggregations;
extern int s_broadcasted_aggregations;
extern int s_broadcasted_cp_aggregations;
extern int s_received_ogms;
extern int s_accepted_ogms;
extern int s_broadcasted_ogms;
extern int s_pog_route_changes;
extern int s_curr_avg_cpu_load;

/* the bat_packet flags: */
#define UNIDIRECTIONAL_FLAG 0x01 /* set when re-broadcasting a received OGM via a curretnly not bi-directional link and only together with IDF */
#define DIRECTLINK_FLAG     0x02 /* set when re-broadcasting a received OGM with identical OG IP and NB IP on the interface link as received */
#define CLONED_FLAG         0x04 /* set when (re-)broadcasting a OGM not-for-the-first time or re-broadcasting a OGM with this flag */

//#define EXTENSION_MSG       0x01 /* ext_flag unset for OGM, set for OGM related extensions like HNA,... */



struct bat_header
{
	uint8_t  version;
	uint8_t  reserved1;
	uint8_t  reserved2;
	uint8_t  size; // the relevant data size in 4 oktets blocks of the packet (including the bat_header)
} __attribute__((packed));


#define BAT_TYPE_OGM 0x00

struct bat_packet_common
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int reserved1:4;
	unsigned int bat_type:3;
	unsigned int ext_msg:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int ext_msg:1;
	unsigned int bat_type:3;
	unsigned int reserved1:4;
#else
# error "Please fix <bits/endian.h>"
#endif
	
	uint8_t size; //in 4 bytes steps
	
	uint16_t reserved2;
	
} __attribute__((packed));


struct bat_packet
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int flags:4;    /* 0x08: UNIDIRECTIONAL link, 0x04: DIRECTLINK flag, ... */
	unsigned int bat_type:3;
	unsigned int ext_msg:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int ext_msg:1;
	unsigned int bat_type:3;
	unsigned int flags:4;
#else
# error "Please fix <bits/endian.h>"
#endif
	uint8_t size; //in 4 bytes steps
	
	uint8_t ws; //in 1 bit steps 
	uint8_t reserved_someting;
	
	uint8_t ttl;
	uint8_t prev_hop_id;
	uint16_t seqno;
	
	uint32_t orig;
//	uint32_t prev_hop;
	
} __attribute__((packed));

struct orig_node                 /* structure for orig_list maintaining nodes of mesh */
{
	uint32_t orig;          /* this must be the first four bytes! otherwise the hash functionality does not work */
	struct orig_node *primary_orig_node;
	struct neigh_node *router;   /* the neighbor which is the currently best_next_hop */
	
	struct batman_if *batman_if; /* TBD: can this be removed? This equals router->if_incoming ?! the interface to route towards the currently best next hop */
	struct list_head_first neigh_list;
	
	uint32_t last_valid;              /* when last valid ogm from this node was received */
	uint32_t last_aware;              /* when last valid ogm via  this node was received */
	uint32_t first_valid_sec;         	/* only used for debugging purposes */
	uint16_t last_valid_seqno;              /* last and best known squence number */
	uint16_t last_rcvd_seqno;
	uint8_t  last_valid_largest_ttl;  /* largest (best) TTL received with last sequence number */
	uint8_t  last_path_ttl;
	
	uint32_t last_new_valid;
	uint8_t  ws;
	uint8_t  last_reserved_someting;
	uint32_t ca10ogis;
	uint32_t rt_changes;
	
	struct ext_packet *gw_msg;
	
	struct ext_packet *hna_array;
	int16_t  hna_array_len;
	
	struct ext_packet *srv_array;
	int16_t  srv_array_len;
	
	TYPE_OF_WORD *dbg_rcvd_bits;
	
	uint32_t last_link; /* when the last time a direct OGM has been received via any of this OGs' interfaces */
	uint16_t id4him;    /* a NB ID from this node for the neighboring node, when last_link expired id4him must be reset */
#define MAX_ID4HIM 255	
	uint16_t id4me;     /* the ID given by the neighboring node to me */
	
	struct link_node *link_node; /*contains additional information about links to neighboring nodes */
	
};

/* list element to store all the disabled tunnel rule netmasks */
struct notun_node
{
	struct list_head list;
	uint32_t addr;
	uint8_t  netmask;
	uint8_t  match_found;
};

/* list element for fast access to all neighboring nodes' primary interface originators */
struct pifnb_node
{
	struct list_head list;
	struct orig_node *pog;
};


/* MUST be allocated and initiated all or nothing !
 * MUST be initiated with any unidirectional received OGM
 * from a direct link NB */
struct link_node
{
	struct list_head list;
	
	struct orig_node *orig_node;
	
	uint16_t *bidirect_link;    /* if node is a bidrectional neighbour, when my OGM was broadcasted (replied) by this node and received by me */
	
	TYPE_OF_WORD *bi_link_bits;       /* for bidirect-link statistics */
	uint16_t *last_bi_link_seqno;     /* for bidirect-link statistics */
	uint8_t *rcvd_bi_link_packets;
	
	TYPE_OF_WORD *lq_bits;            /* for link-quality (lq) statistics */
	uint16_t last_lq_seqno;           /* for link-quality (lq) statistics */
};

struct neigh_node
{
	struct list_head list;
	uint32_t addr;
	uint32_t last_aware;            /* when last packet via this neighbour was received */
	uint16_t last_considered_seqno;
	uint8_t packet_count;
	//uint8_t penalty_count;
	//uint8_t  last_ttl;         /* ttl of last received packet */
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



#define EXT_HNA_FIELD_TYPE    et.hna.nt.atype
#define EXT_HNA_FIELD_NETMASK et.hna.nt.anetmask
#define EXT_HNA_FIELD_ADDR    et.hna.addr

struct ext_type_hna
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ext_related:2;   // may be used by the related message type
	unsigned int ext_type:5;      // identifies the extension message size, type and content
	unsigned int ext_msg:1;       // MUST be set to one for extension messages
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int ext_msg:1;
	unsigned int ext_type:5;
	unsigned int ext_related:2;
#else
# error "Please fix <bits/endian.h>"
#endif
	struct hna_netmask_type nt;
	
	uint16_t reserved;
	
	uint32_t addr;

} __attribute__((packed));



struct ext_type_def
{

#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ext_related:2;   // may be used by the related message type
	unsigned int ext_type:5;      // identifies the extension message size, type and content
	unsigned int ext_msg:1;       // MUST be set to one for extension messages
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int ext_msg:1;
	unsigned int ext_type:5;
	unsigned int ext_related:2;
#else
# error "Please fix <bits/endian.h>"
#endif
	
	uint8_t  def8;
	uint16_t def16;
	uint32_t def32;

} __attribute__((packed));



struct ext_packet
{

#define EXT_TYPE_GW  0x00
#define EXT_TYPE_HNA 0x01
#define EXT_TYPE_PIP 0x02
#define EXT_TYPE_SRV 0x03
#define EXT_TYPE_VIS 0x04
#define EXT_TYPE_MAX 0x04

#define EXT_FIELD_RELATED et.def.ext_related
#define EXT_FIELD_TYPE    et.def.ext_type
#define EXT_FIELD_MSG     et.def.ext_msg

		
// field accessor and flags for gateway announcement extension packets
//#define EXT_GW_TYPES et.gw.gwtypes
#define EXT_GW_FIELD_GWTYPES et.def.ext_related
#define EXT_GW_FIELD_GWFLAGS et.def.def8
#define EXT_GW_FIELD_GWPORT  et.def.def16
#define EXT_GW_FIELD_GWADDR  et.def.def32
// the flags for gw extension messsage gwtypes:
#define TWO_WAY_TUNNEL_FLAG   0x01
#define ONE_WAY_TUNNEL_FLAG   0x02
		
// field accessor for service announcement extension packets
#define EXT_SRV_FIELD_SEQNO  et.def.def8
#define EXT_SRV_FIELD_PORT   et.def.def16
#define EXT_SRV_FIELD_ADDR   et.def.def32

// field accessor for vis announcement extension packets
#define EXT_VIS_FIELD_RES1   et.def.def8
#define EXT_VIS_FIELD_PORT   et.def.def16
#define EXT_VIS_FIELD_ADDR   et.def.def32

// field accessor for primary interface announcement extension packets
#define EXT_PIP_FIELD_RES1   et.def.def8
#define EXT_PIP_FIELD_RES2   et.def.def16
#define EXT_PIP_FIELD_ADDR   et.def.def32

	
	union
	{
		struct ext_type_def def;
//		struct ext_type_gw  gw;
		struct ext_type_hna hna;
//		struct ext_type_srv srv;
	}et;

} __attribute__((packed));


#define KEY_FIELD_ATYPE    nt.atype
#define KEY_FIELD_ANETMASK nt.anetmask

struct hna_key
{
	uint32_t addr;
	struct hna_netmask_type nt;
} __attribute__((packed));	

struct hna_node
{
	struct list_head list;
	struct hna_key key;
	uint8_t enabled;
};

struct todo_node
{
	struct list_head list;
	uint8_t todo_type;
	uint8_t add;
	struct hna_key key;
	uint32_t def32;
	uint16_t def16;
	uint8_t  def8;
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


struct srv_node
{
	struct list_head list;
	uint32_t srv_addr;
	uint16_t srv_port;
	uint8_t  srv_seqno;
	uint8_t enabled;
};


struct forw_node                 /* structure for forw_list maintaining packets to be send/forwarded */
{
	struct list_head list;
	uint32_t send_time;
	int16_t  send_bucket;
	uint8_t  iteration;
	uint8_t  send;
	uint8_t  done;
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
	int32_t if_index;
	int16_t if_num;
	uint8_t if_active;
	int8_t if_rp_filter_old;
	int8_t if_send_redirects_old;
	struct sockaddr_in addr;
	struct sockaddr_in broad;
	struct bat_packet out;
	uint32_t netaddr;
	uint8_t netmask;
	uint8_t if_ttl;
	//uint8_t if_bidirect_link_to; // not really used yet..
	uint8_t send_ogm_only_via_owning_if;
	uint8_t is_wlan;
	int16_t if_send_clones;
	int16_t packet_out_len;
	unsigned char packet_out[MAX_PACKET_OUT_SIZE + 1];
	uint8_t send_own;
	int8_t make_ip_hna_if_conf;
	int8_t dont_make_ip_hna_if_conf;
	int16_t if_ttl_conf;
	int8_t if_send_clones_conf;
	int8_t send_ogm_only_via_owning_if_conf;
};

struct gw_listen_arg
{
	struct gw_client **gw_client_list;
	int32_t sock;
	uint32_t prefix;
	int8_t netmask;
	int32_t port;
	int32_t owt;
	int32_t twt;
	int32_t lease_time;
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

int calc_ogm_if_size( int if_num );
uint32_t purge_timeout ( struct orig_node *orig_node );
int is_batman_if( char *dev, struct batman_if **batman_if );
void update_routes( struct orig_node *orig_node, struct neigh_node *neigh_node, struct ext_packet *hna_array, int16_t hna_array_len );
void update_gw_list( struct orig_node *orig_node, int16_t gw_array_len, struct ext_packet *gw_array );
void get_gw_speeds( unsigned char class, int *down, int *up );
unsigned char get_gw_class( int down, int up );
void choose_gw();
struct hna_hash_node *get_hna_node( struct hna_key *hk );
void add_del_other_hna( struct orig_node *orig_node, struct ext_packet *hna_array, int16_t hna_array_len /*int8_t del*/ );
void add_del_other_srv( struct orig_node *orig_node, struct ext_packet *srv_array, int16_t srv_array_len /*int8_t del*/ );
void add_del_own_hna( uint8_t purge );

//void add_del_own_srv( uint8_t purge );
//void purge_empty_hna_nodes( void );

#endif
