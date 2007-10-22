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

#define COMPAT_VERSION 5


#define UNIDIRECTIONAL_FLAG 0x80 /* set when re-broadcasting a received OGM via a curretnly not bi-directional link and only together with IDF */
#define DIRECTLINK_FLAG     0x40 /* set when re-broadcasting a received OGM with identical OG IP and NB IP on the interface link as received */
#define CLONED_FLAG         0x20 /* set when (re-)broadcasting a OGM not-for-the-first time or re-broadcasting a OGM with this flag */

#define ADDR_STR_LEN 16

#define DEF_UNIX_PATH "/var/run/batmand.socket"
char unix_path[sizeof(DEF_UNIX_PATH)+10];

#define VIS_COMPAT_VERSION 20


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

#define PURGE_TIMEOUT 400000   /* purge originators after time in ms if no valid packet comes in -> TODO: check influence on SEQ_RANGE */

#define WARNING_PERIOD 20000

#define BATMAN_TUN_PREFIX "bat"
#define MAX_BATMAN_TUN_INDEX 20 

#define TEST_SWITCH              "test"

extern int32_t sequence_range;
#define FULL_SEQ_RANGE ((uint16_t)-1)
#define MAX_SEQ_RANGE 250      /* TBD: should not be larger until neigh_node.packet_count (and related variables) is only 8 bit */
#define MIN_SEQ_RANGE 1
#define DEFAULT_SEQ_RANGE 128  /* NBRF: NeighBor Ranking sequence Frame) sliding packet range of received orginator messages in squence numbers (should be a multiple of our word size) */
#define NBRFSIZE_SWITCH          "window-size"

#define MAX_NUM_WORDS (( MAX_SEQ_RANGE / WORD_BIT_SIZE ) + ( ( MAX_SEQ_RANGE % WORD_BIT_SIZE > 0)? 1 : 0 )) 


extern int16_t originator_interval;
#define DEFAULT_ORIGINATOR_INTERVAL 1000
#define MIN_ORIGINATOR_INTERVAL JITTER
#define MAX_ORIGINATOR_INTERVAL 10000 
	
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
 * BATMAN_RT_TABLE_NETWORKS	routing table for announced networks
 * BATMAN_RT_TABLE_HOSTS	routing table for routes towards originators
 * BATMAN_RT_TABLE_UNREACH	routing table for unreachable routing entry
 * BATMAN_RT_TABLE_TUNNEL	routing table for the tunnel towards the internet gateway
 * BATMAN_RT_PRIO_DEFAULT	standard priority for routing rules
 * BATMAN_RT_PRIO_UNREACH	standard priority for unreachable rules
 * BATMAN_RT_PRIO_TUNNEL	standard priority for tunnel routing rules
 *
 ***/


#define RT_TABLE_NETWORKS_OFFSET 0 /* 65 */
#define RT_TABLE_HOSTS_OFFSET    1 /* 66 */
#define RT_TABLE_UNREACH_OFFSET  2 /* 67 */
#define RT_TABLE_TUNNEL_OFFSET   3 /* 68 */

extern int32_t rt_table_offset;
#define RT_TABLE_OFFSET_SWITCH "rt-table-offset"
#define DEF_RT_TABLE_OFFSET 65
#define MIN_RT_TABLE_OFFSET 2
#define MAX_RT_TABLE_OFFSET 250


#define BATMAN_RT_TABLE_NETWORKS (rt_table_offset + RT_TABLE_NETWORKS_OFFSET)
#define BATMAN_RT_TABLE_HOSTS    (rt_table_offset + RT_TABLE_HOSTS_OFFSET)
#define BATMAN_RT_TABLE_UNREACH  (rt_table_offset + RT_TABLE_UNREACH_OFFSET)
#define BATMAN_RT_TABLE_TUNNEL   (rt_table_offset + RT_TABLE_TUNNEL_OFFSET)


extern int32_t rt_prio_default;
#define RT_PRIO_DEFAULT_SWITCH "prio-rules-offset"
#define DEF_RT_PRIO_DEFAULT 6600
#define MIN_RT_PRIO_DEFAULT 3
#define MAX_RT_PRIO_DEFAULT 32765

#define BATMAN_RT_PRIO_DEFAULT rt_prio_default
#define BATMAN_RT_PRIO_UNREACH BATMAN_RT_PRIO_DEFAULT + 100
#define BATMAN_RT_PRIO_TUNNEL BATMAN_RT_PRIO_UNREACH + 100

extern int32_t no_prio_rules;
#define NO_PRIO_RULES_SWITCH "no-prio-rules"
#define DEF_NO_PRIO_RULES NO

extern int32_t no_throw_rules;
#define NO_THROW_RULES_SWITCH "no-throw-rules"
#define DEF_NO_THROW_RULES NO

extern int32_t no_unresponsive_check;
#define NO_UNRESP_CHECK_SWITCH "no-unresp-gw-check"
#define DEF_NO_UNRESP_CHECK NO

extern int32_t gw_change_hysteresis;
#define GW_CHANGE_HYSTERESIS_SWITCH "gw-change-hysteresis"
#define DEF_GW_CHANGE_HYSTERESIS 1
#define MIN_GW_CHANGE_HYSTERESIS 1
#define MAX_GW_CHANGE_HYSTERESIS ((sequence_range / 2) + 1) /*TBD: what if sequence range is decreased after setting this? */

extern uint32_t gw_tunnel_prefix;
extern uint8_t  gw_tunnel_netmask;
#define DEF_GW_TUNNEL_PREFIX  0x0000FEA9 /* 169.254.0.0 */
#define DEF_GW_TUNNEL_NETMASK 16
#define GW_TUNNEL_NETW_SWITCH "gw-tunnel-network"

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
extern uint8_t debug_level_max;
extern uint8_t num_hna;

extern int16_t num_words;

extern uint32_t pref_gateway;

extern int8_t stop;

extern unsigned char *hna_buff;

extern struct gw_node *curr_gateway;
extern pthread_t curr_gateway_thread_id;

extern uint8_t found_ifs;
extern int32_t receive_max_sock;
extern fd_set receive_wait_set;

extern uint8_t unix_client;

extern struct hashtable_t *orig_hash;

extern struct list_head_first if_list;
extern struct list_head_first hna_list;
extern struct list_head_first gw_list;
extern struct list_head_first forw_list;
extern struct vis_if vis_if;
extern struct unix_if unix_if;
extern struct debug_clients debug_clients;


struct bat_packet
{
	uint32_t orig;
	uint8_t  flags;    /* 0x80: UNIDIRECTIONAL link, 0x40: DIRECTLINK flag, ... */
	uint8_t  ttl;
	uint16_t seqno;
	uint8_t  gwflags;  /* flags related to gateway functions: gateway class */
	uint8_t  version;  /* batman version field */
} __attribute__((packed));

struct orig_node                 /* structure for orig_list maintaining nodes of mesh */
{
	uint32_t orig;
	struct neigh_node *router;
	struct batman_if *batman_if;
	uint16_t *bidirect_link;    /* if node is a bidrectional neighbour, when my originator packet was broadcasted (replied) by this node and received by me */
	uint32_t last_valid;              /* when last packet from this node was received */
	uint8_t  gwflags;                 /* flags related to gateway functions: gateway class */
	unsigned char *hna_buff;
	int16_t  hna_buff_len;
	uint16_t last_seqno;              /* last and best known squence number */
	
	uint8_t last_seqno_largest_ttl;	  /* largest (best) TTL received with last sequence number */
	
	TYPE_OF_WORD *bi_link_bits;       /* for bidirect-link statistics */
	uint16_t *last_bi_link_seqno;     /* for bidirect-link statistics */
	
	TYPE_OF_WORD *lq_bits;            /* for link-quality (lq) statistics */
	uint16_t last_lq_seqno;           /* for link-quality (lq) statistics */
	
	TYPE_OF_WORD send_old_seq_bits[ MAX_NUM_WORDS ]; /* just for debugging, indicates the re-broadcasted (non-unidirectional and non-quickest) OGMs for this foreign OG */
	
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

struct hna_node
{
	struct list_head list;
	uint32_t addr;
	uint8_t netmask;
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
	int16_t if_num;
	int32_t if_index;
	uint8_t if_rp_filter_old;
	uint8_t if_send_redirects_old;
	pthread_t listen_thread_id;
	struct sockaddr_in addr;
	struct sockaddr_in broad;
	uint32_t netaddr;
	uint8_t netmask;
	struct bat_packet out;
	uint8_t if_ttl;
	uint8_t if_bidirect_link_to;
	uint8_t send_ogm_only_via_owning_if;
	int16_t if_send_clones;
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
void update_routes( struct orig_node *orig_node, struct neigh_node *neigh_node, unsigned char *hna_recv_buff, int16_t hna_buff_len );
void update_gw_list( struct orig_node *orig_node, uint8_t new_gwflags );
void get_gw_speeds( unsigned char class, int *down, int *up );
unsigned char get_gw_class( int down, int up );
void choose_gw();


#endif
