/*
 * Copyright (C) 2006 B.A.T.M.A.N. contributors:
 * Thomas Lopatic, Corinna 'Elektra' Aichele, Axel Neumann,
 * Felix Fietkau, Marek Lindner
 *
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



#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>



#include "os.h"
#include "batman.h"
#include "originator.h"
#include "dispatch.h"
#include "metrics.h"
#include "control.h"




int32_t debug_level = -1;


char *prog_name;

char unix_path[sizeof(DEF_UNIX_PATH)+10]; //initialized in init.c: apply_init_args()


/*
 * "-g" is the command line switch for the gateway class,
 */

uint8_t gateway_class = 0;

/* "-r" is the command line switch for the routing class,
 * 0 set no default route
 * 1 use fast internet connection
 * 2 use stable internet connection
 * 3 use use best statistic (olsr style)
 * this option is used to set the routing behaviour
 */

int32_t routing_class = 0;

//uint8_t compat_version = DEF_COMPAT_VERSION;

int32_t my_ogi = DEFAULT_ORIGINATOR_INTERVAL;   /* orginator message interval in miliseconds */

int32_t dad_timeout = DEFAULT_DAD_TIMEOUT;

uint32_t outgoing_src = 0;




/* bidirectional link timeout in number+1 of maximum acceptable missed (not received by this node)
of last send own OGMs rebroadcasted from neighbors */
int32_t my_lws = DEF_BIDIRECT_TIMEOUT;

int32_t aggregations_per_ogi = DEF_AGGREGATIONS_PER_OGI;

int32_t my_pws = DEF_SEQ_RANGE;

int32_t initial_seqno = DEF_INITIAL_SEQNO;

int32_t fake_uptime = DEF_FAKE_UPTIME;

int32_t ttl = DEFAULT_TTL;

uint8_t asocial_device = NO;
uint8_t no_tun_persist = NO;
int32_t magic_switch = 0;
uint8_t no_forw_dupl_ttl_check = NO;
int32_t dup_ttl_limit = DEF_DUP_TTL_LIMIT;
int32_t dup_rate =  DEF_DUP_RATE;
int32_t ttl_degrade = DEF_TTL_DEGRADE;

int32_t unicast_probes_num  = DEF_UNI_PROBES_N;
int32_t unicast_probes_ival = DEF_UNI_PROBES_IVAL;
int32_t unicast_probes_size = DEF_UNI_PROBES_SIZE;
int32_t unicast_probes_ws   = DEF_UNI_PROBES_WS;

int32_t wl_clones = DEF_WL_CLONES;

int32_t asymmetric_weight = DEF_ASYMMETRIC_WEIGHT;

int32_t asymmetric_exp = DEF_ASYMMETRIC_EXP;

int32_t nonprimary_hna = DEF_NONRPIMARY_HNA;


int32_t ogm_port = DEF_BASE_PORT;
int32_t my_gw_port = DEF_GW_PORT;
uint32_t my_gw_addr = DEF_GW_ADDR;
int32_t vis_port = DEF_VIS_PORT;

int32_t rt_table_offset   = DEF_RT_TABLE_OFFSET;

int32_t rt_prio_offset = DEF_RT_PRIO_OFFSET;

int32_t no_prio_rules = DEF_NO_PRIO_RULES;

int32_t no_lo_rule = DEF_NO_LO_RULE;

int32_t no_throw_rules = DEF_NO_THROW_RULES;

int32_t no_unresponsive_check = DEF_NO_UNRESP_CHECK;

int32_t one_way_tunnel = DEF_ONE_WAY_TUNNEL;

int32_t two_way_tunnel = DEF_TWO_WAY_TUNNEL;

int32_t gw_change_hysteresis = DEF_GW_CHANGE_HYSTERESIS;

uint32_t gw_tunnel_prefix; //= DEF_GW_TUNNEL_PREFIX; //initialized in init.c: apply_init_args()

uint8_t  gw_tunnel_netmask = DEF_GW_TUNNEL_NETMASK;

int32_t tunnel_ip_lease_time = DEF_TUNNEL_IP_LEASE_TIME;

struct gw_node *curr_gateway = NULL;
pthread_t curr_gateway_thread_id = 0;

uint32_t pref_gateway = 0;

uint8_t no_policy_routing = 0;


struct ext_packet *my_hna_ext_array = NULL;
uint16_t my_hna_ext_array_len = 0;
uint16_t my_hna_list_enabled = 0;

struct ext_packet *my_srv_ext_array = NULL;
uint16_t my_srv_ext_array_len = 0;
uint16_t my_srv_list_enabled = 0;

struct ext_packet my_gw_extension_packet; //currently only one gw_extension_packet considered
struct ext_packet *my_gw_ext_array = &my_gw_extension_packet;
uint16_t my_gw_ext_array_len = 0;

struct ext_packet my_pip_extension_packet; //currently only one gw_extension_packet considered
struct ext_packet *my_pip_ext_array = &my_pip_extension_packet;
uint16_t my_pip_ext_array_len = 0;

uint8_t found_ifs = 0;
uint8_t active_ifs = 0;
int32_t receive_max_sock = 0;
fd_set receive_wait_set;

uint8_t client_mode = 0;

uint8_t log_facility_active = NO;

uint16_t changed_readfds = 1;


struct msg_buff b;

uint32_t batman_time = 0;



struct hashtable_t *orig_hash = NULL;
struct hashtable_t *hna_hash = NULL;

SIMPEL_LIST( if_list );
SIMPEL_LIST( gw_list );
SIMPEL_LIST( notun_list );
SIMPEL_LIST( my_hna_list );
SIMPEL_LIST( my_srv_list );


struct vis_if *vis_if = NULL;

pthread_t gw_thread_id = 0;

int gw_thread_finish = 0;


unsigned char *vis_packet = NULL;
uint16_t vis_packet_size = 0;

int s_returned_select = 0;
int s_received_aggregations = 0;
int s_broadcasted_aggregations = 0;
int s_received_ogms = 0; 
int s_accepted_ogms = 0;
int s_broadcasted_ogms = 0;
int s_pog_route_changes = 0;
int s_curr_avg_cpu_load = 0;
int curr_statistic_period_ms;

void print_advanced_opts ( int verbose ) {
	
	fprintf( stderr, "\n\n Advanced and dangerous options (only touch if you know what you are doing):\n" );
	fprintf( stderr, "\n For more background informations see: http://open-mesh.net/batman/doc/BMX/\n" );
	
	
	
	fprintf( stderr, "\n\n Network adaption:\n" );

	fprintf( stderr, "\n       --%s : does not set the default priority rules.\n", NO_PRIO_RULES_SWITCH );
	
	fprintf( stderr, "\n       --%s : does not set the default throw rules.\n", NO_THROW_RULES_SWITCH );
		
	fprintf( stderr, "\n       --%s <value> : set base udp port used by batmand.\n", BASE_PORT_SWITCH );
	fprintf( stderr, "          <value> for OGMs, <value+1> for GW tunnels, <value+2> for visualization server.\n");
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d \n", DEF_BASE_PORT, MIN_BASE_PORT, MAX_BASE_PORT  );
	
	fprintf( stderr, "\n       --%s <value> : set base routing table used by batmand.\n", RT_TABLE_OFFSET_SWITCH );
	fprintf( stderr, "          Configures table <value> to be used for HNA routes, <value+1> for host routes, \n");
	fprintf( stderr, "          <value+2> for unreachable routes, and <value+3> for the default tunnel route.\n");
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d \n", DEF_RT_TABLE_OFFSET, MIN_RT_TABLE_OFFSET, MAX_RT_TABLE_OFFSET  );
	
	fprintf( stderr, "\n       --%s <value> : set base ip-rules priority used by batmand.\n", RT_PRIO_OFFSET_SWITCH );
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d \n", DEF_RT_PRIO_OFFSET, MIN_RT_PRIO_OFFSET, MAX_RT_PRIO_OFFSET  );
	
	
	
	
	
	
	fprintf( stderr, "\n\n Gateway and tunneling options:\n" );
	
	fprintf( stderr, "\n       --%s <value> : set preference for %s mode.\n", ONE_WAY_TUNNEL_SWITCH, ONE_WAY_TUNNEL_SWITCH );
	fprintf( stderr, "         For GW-nodes:  0 disables this tunnel mode, a larger value enables this tunnel mode.\n" );
	fprintf( stderr, "         For GW-cliets: 0 disables this tunnel mode, a larger value sets the preference for this mode.\n" );
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d \n", DEF_ONE_WAY_TUNNEL, MIN_ONE_WAY_TUNNEL, MAX_ONE_WAY_TUNNEL  );

	fprintf( stderr, "\n       --%s <value> : set preference for %s mode.\n", TWO_WAY_TUNNEL_SWITCH, TWO_WAY_TUNNEL_SWITCH );
	fprintf( stderr, "         For GW-nodes:  0 disables this tunnel mode, a larger value enables this tunnel mode.\n" );
	fprintf( stderr, "         For GW-cliets: 0 disables this tunnel mode, a larger value sets the preference for this mode.\n" );
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d \n", DEF_TWO_WAY_TUNNEL, MIN_TWO_WAY_TUNNEL, MAX_TWO_WAY_TUNNEL  );
	
	
	fprintf( stderr, "\n       --%s <ip-address/netmask> : set tunnel IP-address range leased out by GW nodes.\n", GW_TUNNEL_NETW_SWITCH );
	fprintf( stderr, "         Only relevant for GW-nodes in %s mode\n", TWO_WAY_TUNNEL_SWITCH );
	if ( verbose )
		fprintf( stderr, "          default: %s/%d, allowed netmask values: %d <= value <= %d \n", DEF_GW_TUNNEL_PREFIX_STR, DEF_GW_TUNNEL_NETMASK, MIN_GW_TUNNEL_NETMASK, MAX_GW_TUNNEL_NETMASK );
	
	
	fprintf( stderr, "\n       --%s <value> : set lease time in seconds of virtual two-way tunnel IPs.\n", TUNNEL_IP_LEASE_TIME_SWITCH );
	fprintf( stderr, "         Only relevant for GW-nodes in %s mode\n", TWO_WAY_TUNNEL_SWITCH );
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d \n", DEF_TUNNEL_IP_LEASE_TIME, MIN_TUNNEL_IP_LEASE_TIME, MAX_TUNNEL_IP_LEASE_TIME  );
	
	
	fprintf( stderr, "\n       --%s <ip-address/netmask> : do NOT route packets from ip-address range into batman tunnel.\n", NO_TUNNEL_RULE_SWITCH );
	fprintf( stderr, "         Only relevant for GW-client nodes\n" );
	
	
	fprintf( stderr, "\n       --%s : disables the unresponsive-GW check.\n", NO_UNRESP_CHECK_SWITCH );
	fprintf( stderr, "         Only relevant for GW-client nodes in %s mode\n", TWO_WAY_TUNNEL_SWITCH );
	
	fprintf( stderr, "\n       --%s <vlue>: Use hysteresis for fast-switch gw connections (-r 3).\n", GW_CHANGE_HYSTERESIS_SWITCH );
	fprintf( stderr, "          <value> for number additional rcvd OGMs before changing to more stable GW.\n");
	fprintf( stderr, "         Only relevant for GW-client nodes in %s mode\n", TWO_WAY_TUNNEL_SWITCH );
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d \n", DEF_GW_CHANGE_HYSTERESIS, MIN_GW_CHANGE_HYSTERESIS, MAX_GW_CHANGE_HYSTERESIS  );
		
	
	
	
	
	
	fprintf( stderr, "\n\n Service announcement:\n" );
	
	fprintf( stderr, "\n       --%s <ip-address:port:seqno> : announce the given ip and port with seqno (0-255) to other nodes.\n", ADD_SRV_SWITCH );
	
	fprintf( stderr, "\n       --%s <ip-address:port> : stop announcing the given ip and port to other nodes.\n", DEL_SRV_SWITCH );
	
	
	
	
	fprintf( stderr, "\n\n Core routing protocol options:\n" );
	
	fprintf( stderr, "\n       --%s <value>: Set number of aggregations per originator interval manually.\n", AGGREGATIONS_PER_OGI_SWITCH );
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d \n", DEF_AGGREGATIONS_PER_OGI, MIN_AGGREGATIONS_PER_OGI, MAX_AGGREGATIONS_PER_OGI  );

	fprintf( stderr, "\n       --%s <value> : change default TTL of originator packets.\n", TTL_SWITCH );
	fprintf( stderr, "        /%c <value> : attached after an interface name\n", TTL_IF_SWITCH );
	fprintf( stderr, "          to change the TTL only for the OGMs representing a specific interface\n");
	if ( verbose ) {
		fprintf( stderr, "          default for primary interface : %d,    allowed values: %d <= value <= %d\n", DEFAULT_TTL, MIN_TTL, MAX_TTL  );
		fprintf( stderr, "          default for non-primary interface: %d, allowed values: %d <= value <= %d\n", 1, MIN_TTL, MAX_TTL  );
	}
		
	fprintf( stderr, "\n        /%c : attached after an interface name\n", OGM_ONLY_VIA_OWNING_IF_SWITCH );
	fprintf( stderr, "          to broadcast the OGMs representing this interface only via this interface,\n");
	fprintf( stderr, "          also reduces the TTL for OGMs representing this interface to 1.\n");
	if ( verbose ) {
		fprintf( stderr, "          default for primary interface : %d,    allowed values: %d <= value <= %d\n", 0, 0, 1  );
		fprintf( stderr, "          default for non-primary interface: %d, allowed values: %d <= value <= %d\n", 1, 0, 1  );
	}
	

	fprintf( stderr, "\n       --%s <value> : add IPs of nonprimary interfaces to the HNA list\n", NONPRIMARY_HNA_SWITCH );
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d\n", DEF_NONRPIMARY_HNA, MIN_NONPRIMARY_HNA, MAX_NONPRIMARY_HNA  );
	
	fprintf( stderr, "\n        /%c : attached after a non-primary interface name\n", HNA_IF_SWITCH );
	fprintf( stderr, "          to add the IP address of this interface to the HNA list.\n");
	
	fprintf( stderr, "\n        /%c : attached after a non-primary interface name\n", NO_HNA_IF_SWITCH );
	fprintf( stderr, "          to remove the IP address of this interface from the HNA list.\n");
	
	
	fprintf( stderr, "\n       --%s <ip-address> : set preferred src addr for all interfaces and do HNA\n", SRC_ADDR_SWITCH );

	
	fprintf( stderr, "\n       --%s <value> : set window size for path statistic\n", NBRFSIZE_SWITCH );
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d\n", DEF_SEQ_RANGE, MIN_SEQ_RANGE, MAX_SEQ_RANGE  );
	
	fprintf( stderr, "\n       --%s <value> : set window size for link statistic\n", BIDIRECT_TIMEOUT_SWITCH );
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d\n", DEF_BIDIRECT_TIMEOUT, MIN_BIDIRECT_TIMEOUT, MAX_BIDIRECT_TIMEOUT  );
	
	fprintf( stderr, "\n       --%s <value> : set initial seqno for this nodes OGMs\n", INITIAL_SEQNO_SWITCH );
	if ( verbose )
		fprintf( stderr, "          default: %d, (0 = random) allowed values: %d <= value <= %d\n", DEF_INITIAL_SEQNO, MIN_INITIAL_SEQNO, MAX_INITIAL_SEQNO  );
	
	
	fprintf( stderr, "\n       --%s <value> : (re-)broadcast OGMs via wlan IFs with given probability\n", WL_CLONES_SWITCH );
	fprintf( stderr, "        /%c <value> : attached after an interface name\n", CLONES_IF_SWITCH );
	fprintf( stderr, "          to specify an individual re-broadcast probability for this interface.\n");
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed probability values in percent: %d <= value <= %d\n", DEF_WL_CLONES, MIN_WL_CLONES, MAX_WL_CLONES  );
	
	fprintf( stderr, "\n       --%s <value> : ignore rcvd OGMs to respect asymmetric-links.\n", ASYMMETRIC_EXP_SWITCH );
	fprintf( stderr, "          Ignore with probability TQ^<value>.\n");	
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed exponent values: %d <= value <= %d\n", DEF_ASYMMETRIC_EXP, MIN_ASYMMETRIC_EXP, MAX_ASYMMETRIC_EXP  );
	
	fprintf( stderr, "\n       --%s <value> : ignore rcvd OGMs to respect asymmetric-links.\n", ASYMMETRIC_WEIGHT_SWITCH );
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed probability values in percent: %d <= value <= %d\n", DEF_ASYMMETRIC_WEIGHT, MIN_ASYMMETRIC_WEIGHT, MAX_ASYMMETRIC_WEIGHT  );
	
	fprintf( stderr, "\n       --%s <value> : accept non-quickest OGMs to relieve preference for shortest path. \n", DUP_TTL_LIMIT_SWITCH );
	fprintf( stderr, "          (< value > - 1) defines how much smaller the TTL of a non-first OGM can be compared to \n");
	fprintf( stderr, "          the largest TTL received so fare (with the same originator IP and sequencenumber).\n");	
	if ( verbose )
		fprintf( stderr, "          default: %d (0=disabled), allowed values: %d <= value <= %d\n", DEF_DUP_TTL_LIMIT, MIN_DUP_TTL_LIMIT, MAX_DUP_TTL_LIMIT );
	
	fprintf( stderr, "\n       --%s <value> : accept non-quickest OGMs to relieve preference for shortest path. \n", DUP_RATE_SWITCH );
	fprintf( stderr, "          < value > defines the probability with which non-quickest OGMs are accepted. \n");
	if ( verbose )
		fprintf( stderr, "          default: %d (0=disabled), allowed values in percent: %d <= value <= %d\n", DEF_DUP_RATE, MIN_DUP_RATE, MAX_DUP_RATE );
	
	fprintf( stderr, "\n       --%s <value> : accept non-quickest OGMs to relieve preference for shortest path. \n", TTL_DEGRADE_SWITCH );
	fprintf( stderr, "          < value > defines the probability degradation for each additional hop (compared \n");
	fprintf( stderr, "          to previous received OGMs) with which non-quickest OGMs are accepted. \n");
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values in percent: %d <= value <= %d\n", DEF_TTL_DEGRADE, MIN_TTL_DEGRADE, MAX_TTL_DEGRADE );
	
	fprintf( stderr, "\n       --%s : mobile device mode reluctant to help others.\n", ASOCIAL_SWITCH );
	
}

void usage( void ) {

	fprintf( stderr, "Usage: batman [options] interface [interface interface]\n" );
	fprintf( stderr, "       -a announce network\n" );
	fprintf( stderr, "       -d debug level\n" );
	fprintf( stderr, "       -g gateway class\n" );
	fprintf( stderr, "       -h this help\n" );
	fprintf( stderr, "       -H verbose help\n" );
	fprintf( stderr, "       -i internal options output\n" );
	fprintf( stderr, "       -o originator interval in ms\n" );
	fprintf( stderr, "       -p preferred gateway\n" );
	fprintf( stderr, "       -r routing class\n" );
	fprintf( stderr, "       -s visualization server\n" );
	fprintf( stderr, "       -v print version\n" );
	fprintf( stderr, "\n");
	fprintf( stderr, "       -c connect to daemon via unix socket\n\n" );
	fprintf( stderr, "       -b run connection to deamon in batch mode. DEPRECATED - batch mode is default now!\n" );
	fprintf( stderr, "       -l run connection to daemon in loop mode\n" );
	fprintf( stderr, "\n");
	
	fprintf( stderr, "       --dangerous : show advanced and dangerous options \n" );


}


void verbose_usage( void ) {

	fprintf( stderr, "Usage: batman [options] interface [interface interface]\n\n" );
	fprintf( stderr, "       -a announce network\n" );
	fprintf( stderr, "          network/netmask is expected\n" );
	fprintf( stderr, "       -d debug level\n" );
	fprintf( stderr, "          default:         0 -> debug disabled\n" );
	fprintf( stderr, "          allowed values:  1 -> list originators\n" );
	fprintf( stderr, "                           2 -> list gateways\n" );
	fprintf( stderr, "                           3 -> observe batman\n" );
	fprintf( stderr, "                           4 -> observe batman (very verbose)\n" );
	fprintf( stderr, "                           5 -> memory debug / cpu usage (only if compiled with -DDEBUG_MALLOC -DMEMORY_USAGE -DPROFILE_DATA)\n" );
	fprintf( stderr, "                           %d -> list details\n", DBGL_DETAILS );
	fprintf( stderr, "\n" );

	fprintf( stderr, "       -g gateway class\n" );
	fprintf( stderr, "          default:         0 -> gateway disabled\n" );
	fprintf( stderr, "          allowed values:  download speed/upload in kbit (default) or mbit\n" );
	fprintf( stderr, "          note:            batmand will choose the nearest gateway class representing your speeds\n" );
	fprintf( stderr, "                           and therefore accepts all given values\n" );
	fprintf( stderr, "                           e.g. 5000\n" );
	fprintf( stderr, "                                5000kbit\n" );
	fprintf( stderr, "                                5mbit\n" );
	fprintf( stderr, "                                5mbit/1024\n" );
	fprintf( stderr, "                                5mbit/1024kbit\n" );
	fprintf( stderr, "                                5mbit/1mbit\n" );
	fprintf( stderr, "       -h shorter help\n" );
	fprintf( stderr, "       -H this help\n" );
	fprintf( stderr, "       -i gives information about all internal options\n" );
	fprintf( stderr, "       -o originator interval in ms\n" );
	fprintf( stderr, "          default: %d, allowed values: >0\n\n", DEFAULT_ORIGINATOR_INTERVAL );
	fprintf( stderr, "       -p preferred gateway\n" );
	fprintf( stderr, "          default: none, allowed values: IP\n\n" );
	fprintf( stderr, "       -r routing class (only needed if gateway class = 0)\n" );
	fprintf( stderr, "          default:         0 -> set no default route\n" );
	fprintf( stderr, "          allowed values:  1 -> use fast internet connection (gw_flags * packet count)\n" );
	fprintf( stderr, "                           2 -> use stable internet connection (packet count)\n" );
	fprintf( stderr, "                           3 -> use fast-switch internet connection (packet count but change as soon as a better gateway appears)\n\n" );
	fprintf( stderr, "       -s visualization server\n" );
	fprintf( stderr, "          default: none, allowed values: IP\n" );
	fprintf( stderr, "       -v print version\n" );
	fprintf( stderr, "\n");
	fprintf( stderr, "       -c connect to daemon via unix socket\n\n" );
	fprintf( stderr, "       -b run connection to deamon in batch mode. DEPRECATED - batch mode is default now!\n" );
	fprintf( stderr, "       -l run connection to daemon in loop mode\n" );
	fprintf( stderr, "\n");
	
	fprintf( stderr, "\n       --dangerous : show advanced and dangerous options \n" );

}


int is_batman_if( char *dev, struct batman_if **batman_if ) {

	struct list_head *if_pos = NULL;


	list_for_each( if_pos, &if_list ) {

		(*batman_if) = list_entry( if_pos, struct batman_if, list );

		if ( strcmp( (*batman_if)->dev, dev ) == 0 )
			return 1;

	}

	return 0;

}



void purge_empty_hna_nodes( void ) {
	
//	prof_start( PROF_purge_empty_hna_nodes );
	struct hash_it_t *hashit = NULL;
	struct hna_hash_node *hash_node;
	

	/* for all hna_hash_nodes... */
	while ( hna_hash  &&  (hashit = hash_iterate( hna_hash, hashit )) ) {

		hash_node = hashit->bucket->data;
		
		if ( hash_node->status == HNA_HASH_NODE_EMPTY ) {
			
			hash_remove_bucket( hna_hash, hashit );
			debugFree( hash_node, 1401 );
			
		}

		
	}

//	prof_stop( PROF_purge_empty_hna_nodes );
	
}


/* this function finds or, if it does not exits, creates an hna entry for the given hna address, anetmask, and atype */
struct hna_hash_node *get_hna_node( struct hna_key *hk /*, struct orig_node *orig_node*/ ) {

//	prof_start( PROF_get_hna_node );
	struct hna_hash_node *hash_node;
	struct hashtable_t *swaphash;
	static char hna_str[ADDR_STR_LEN];

	hash_node = ((struct hna_hash_node *)hash_find( hna_hash, hk ));

	if ( hash_node != NULL ) {

//		prof_stop( PROF_get_hna_node );
		return hash_node;

	}


	addr_to_string( hk->addr, hna_str, ADDR_STR_LEN );
	debug_all( "  creating new and empty hna_hash_node: %s/%d, type %d \n", hna_str, hk->KEY_FIELD_ANETMASK, hk->KEY_FIELD_ATYPE );

	hash_node = debugMalloc( sizeof(struct hna_hash_node), 401 );
	memset(hash_node, 0, sizeof(struct hna_hash_node));

	hash_node->key.addr = hk->addr;
	hash_node->key.KEY_FIELD_ATYPE = hk->KEY_FIELD_ATYPE;
	hash_node->key.KEY_FIELD_ANETMASK = hk->KEY_FIELD_ANETMASK;
	hash_node->orig = NULL; //orig_node;
	hash_node->status = HNA_HASH_NODE_EMPTY;
	
	hash_add( hna_hash, hash_node );

	if ( hna_hash->elements * 4 > hna_hash->size ) {

		swaphash = hash_resize( hna_hash, hna_hash->size * 2 );

		if ( swaphash == NULL ) {

			debug_output( 0, "Couldn't resize hna hash table \n" );
			cleanup_all( CLEANUP_FAILURE );


		}

		hna_hash = swaphash;

	}

//	prof_stop( PROF_get_hna_node );
	return hash_node;

}

/*
 * updates hna information maintained for other orig_node
 * updates are made according to given hna_array and hna_array_len arguments
 */
void add_del_other_hna( struct orig_node *orig_node, struct ext_packet *hna_array, int16_t hna_array_len /*int8_t del*/ ) {

	uint16_t hna_count = 0;
	struct hna_key key;
	struct hna_hash_node *hash_node;
	uint8_t rt_table;
	int8_t del = (hna_array_len == 0 ? 1 : 0);
	static char hna_str[ADDR_STR_LEN];
	
	if ( orig_node == NULL || 
		    (hna_array_len != 0 && (hna_array == NULL || orig_node->hna_array_len != 0 )) || 
		    (hna_array_len == 0 && (hna_array != NULL || orig_node->hna_array_len == 0 || orig_node->hna_array == NULL  ) ) ) {
		debug_output( 0, "Error - add_del_other_hna(): invalid hna information !\n");
		cleanup_all( CLEANUP_FAILURE );
	}
	
	if ( hna_array_len > 0 ) {
		
		orig_node->hna_array = debugMalloc( hna_array_len * sizeof(struct ext_packet), 101 );
		orig_node->hna_array_len = hna_array_len;
	
		memcpy( orig_node->hna_array, hna_array, hna_array_len * sizeof(struct ext_packet) );
		
	}
	
	while ( hna_count < orig_node->hna_array_len ) {
		
		key.addr     = orig_node->hna_array[hna_count].EXT_HNA_FIELD_ADDR;
		key.KEY_FIELD_ANETMASK = orig_node->hna_array[hna_count].EXT_HNA_FIELD_NETMASK;
		key.KEY_FIELD_ATYPE    = orig_node->hna_array[hna_count].EXT_HNA_FIELD_TYPE;
		
		rt_table = ( key.KEY_FIELD_ATYPE == A_TYPE_INTERFACE ? BATMAN_RT_TABLE_INTERFACES : (key.KEY_FIELD_ATYPE == A_TYPE_NETWORK ? BATMAN_RT_TABLE_NETWORKS : 0 ) );
		
		hash_node = get_hna_node( &key );
		
		if ( ( key.KEY_FIELD_ANETMASK > 0 ) && ( key.KEY_FIELD_ANETMASK <= 32 ) && rt_table ) {
			
			/* when to be deleted check if HNA has been accepted during assignement 
			 * when to be created check if HNA is not blocked by other OG */
			if ( del && hash_node->status == HNA_HASH_NODE_OTHER && hash_node->orig == orig_node ) {
				
				add_del_route( key.addr, key.KEY_FIELD_ANETMASK, 
						orig_node->router->addr,
						outgoing_src ? outgoing_src : ((struct batman_if *)if_list.next)->addr.sin_addr.s_addr,
					//	orig_node->router->if_incoming->addr.sin_addr.s_addr,
						orig_node->router->if_incoming->if_index,
						orig_node->router->if_incoming->dev,
						rt_table, 0, del, NO/*no track*/ );
				
				hash_node->status = HNA_HASH_NODE_EMPTY;
				hash_node->orig = NULL;
				
			} else if ( !del && hash_node->status == HNA_HASH_NODE_EMPTY && hash_node->orig == NULL ) {
				
				add_del_route( key.addr, key.KEY_FIELD_ANETMASK, 
						orig_node->router->addr,
						outgoing_src ? outgoing_src : ((struct batman_if *)if_list.next)->addr.sin_addr.s_addr,
						orig_node->router->if_incoming->if_index, 
						orig_node->router->if_incoming->dev, 
						rt_table, 0, del, NO/*no track*/ );
				
				hash_node->status = HNA_HASH_NODE_OTHER;
				hash_node->orig = orig_node;
				
			} else {
				
				addr_to_string( key.addr, hna_str, ADDR_STR_LEN );
				debug_output( 3, "add_del_other_hna(): NOT %s HNA %s/%d type %d ! HNA %s blocked \n",
					    (del?"removing":"adding"), hna_str, key.KEY_FIELD_ANETMASK, key.KEY_FIELD_ATYPE, (del?"was":"is") );
				
			}
			
		}

		hna_count++;

	}

	if ( hna_array_len == 0 ) {

		debugFree( orig_node->hna_array, 1101 );
		orig_node->hna_array_len = 0;
		orig_node->hna_array = NULL;
		
	}

}

/*
 * updates service announcement information maintained for other orig_node
 * updates are made according to given srv_array and srv_array_len arguments
 */
void add_del_other_srv( struct orig_node *orig_node, struct ext_packet *srv_array, int16_t srv_array_len /*int8_t del*/ ) {

	if ( orig_node == NULL || 
		    (srv_array_len != 0 && (srv_array == NULL || orig_node->srv_array_len != 0 )) || 
		    (srv_array_len == 0 && (srv_array != NULL || orig_node->srv_array_len == 0 || orig_node->srv_array == NULL  ) ) ) 
	{
		
		debug_output( 0, "Error - add_del_other_srv(): invalid srv information !\n");
		cleanup_all( CLEANUP_FAILURE );
		
	}
		    
	if ( srv_array_len > 0 ) {
		
		orig_node->srv_array = debugMalloc( srv_array_len * sizeof(struct ext_packet), 121 );
		orig_node->srv_array_len = srv_array_len;

		memcpy( orig_node->srv_array, srv_array, srv_array_len * sizeof(struct ext_packet) );
		
		debug_output( 3, "adding service announcement \n");

	} else {

		debugFree( orig_node->srv_array, 1121 );
		orig_node->srv_array_len = 0;
		orig_node->srv_array = NULL;
		debug_output( 3, "removing service announcement \n");

	}

}



void add_del_own_hna( uint8_t purge ) {
	
	struct list_head *list_pos, *hna_pos_tmp, *prev_list_head;
	struct hna_node *hna_node;
	struct hna_hash_node *hash_node;
	static char str[ADDR_STR_LEN], str2[ADDR_STR_LEN];
	
	prev_list_head = (struct list_head *)&my_hna_list;
	
	list_for_each_safe( list_pos, hna_pos_tmp, &my_hna_list ) {

		hna_node = list_entry( list_pos, struct hna_node, list );
		
		//remove the corresponding hna_hash entry so that its not blocked for others
		hash_node = get_hna_node( &hna_node->key );
			
			
		if ( hash_node->status == HNA_HASH_NODE_MYONE ) {
			
			/* del throw routing entries for own hna */
			add_del_route( hna_node->key.addr, hna_node->key.KEY_FIELD_ANETMASK, 0, 0, 0, "unknown", BATMAN_RT_TABLE_INTERFACES, 1, 1, YES/*track*/ );
			add_del_route( hna_node->key.addr, hna_node->key.KEY_FIELD_ANETMASK, 0, 0, 0, "unknown", BATMAN_RT_TABLE_NETWORKS,   1, 1, YES/*track*/ );
			add_del_route( hna_node->key.addr, hna_node->key.KEY_FIELD_ANETMASK, 0, 0, 0, "unknown", BATMAN_RT_TABLE_HOSTS,      1, 1, YES/*track*/ );
			add_del_route( hna_node->key.addr, hna_node->key.KEY_FIELD_ANETMASK, 0, 0, 0, "unknown", BATMAN_RT_TABLE_TUNNEL,     1, 1, YES/*track*/ );
			
			hash_node->status = HNA_HASH_NODE_EMPTY;
		}
		
		if ( purge ) { 
				
			hash_remove( hna_hash, hash_node );
			debugFree( hash_node, 1401 );
			debugFree( hna_node, 1103 );
			list_del( prev_list_head, list_pos, &my_hna_list );
		}

	}

	if ( my_hna_ext_array != NULL )
		debugFree( my_hna_ext_array, 1115 );
		
	my_hna_ext_array = NULL;
	my_hna_ext_array_len = 0;

	
	
	if ( ! purge  &&  !( list_empty( &my_hna_list ) )  &&  my_hna_list_enabled ) {
		
		my_hna_ext_array = debugMalloc( my_hna_list_enabled * sizeof(struct ext_packet), 115 );
		memset( my_hna_ext_array, 0, my_hna_list_enabled * sizeof(struct ext_packet) );

		list_for_each( list_pos, &my_hna_list ) {
			

			hna_node = list_entry( list_pos, struct hna_node, list );

			if ( hna_node->enabled ) {
				
				// create a corresponding hna_hash entry so that its blocked for others
				hash_node = get_hna_node( &hna_node->key );
				
				
				if ( hash_node->status == HNA_HASH_NODE_EMPTY ) {
					
					hash_node->status = HNA_HASH_NODE_MYONE;
					hash_node->orig = NULL;
					
					my_hna_ext_array[my_hna_ext_array_len].EXT_FIELD_MSG  = YES;
					my_hna_ext_array[my_hna_ext_array_len].EXT_FIELD_TYPE = EXT_TYPE_HNA;
		
					my_hna_ext_array[my_hna_ext_array_len].EXT_HNA_FIELD_ADDR    = hna_node->key.addr;
					my_hna_ext_array[my_hna_ext_array_len].EXT_HNA_FIELD_NETMASK = hna_node->key.KEY_FIELD_ANETMASK;
					my_hna_ext_array[my_hna_ext_array_len].EXT_HNA_FIELD_TYPE    = hna_node->key.KEY_FIELD_ATYPE;
					
					my_hna_ext_array_len++;
					
					/* add throw routing entries for own hna */  
					add_del_route( hna_node->key.addr, hna_node->key.KEY_FIELD_ANETMASK, 0,0,0, "unknown", BATMAN_RT_TABLE_INTERFACES, 1, 0, YES/*track*/ );
					add_del_route( hna_node->key.addr, hna_node->key.KEY_FIELD_ANETMASK, 0,0,0, "unknown", BATMAN_RT_TABLE_NETWORKS,   1, 0, YES/*track*/ );
					add_del_route( hna_node->key.addr, hna_node->key.KEY_FIELD_ANETMASK, 0,0,0, "unknown", BATMAN_RT_TABLE_HOSTS,      1, 0, YES/*track*/ );
					add_del_route( hna_node->key.addr, hna_node->key.KEY_FIELD_ANETMASK, 0,0,0, "unknown", BATMAN_RT_TABLE_TUNNEL,     1, 0, YES/*track*/ );
					
				} else {
					
					addr_to_string( hna_node->key.addr, str, ADDR_STR_LEN );
					addr_to_string( hash_node->orig->orig, str2, ADDR_STR_LEN );
					debug_output( DBGL_SYSTEM, "Error - Could not announce network %s/%d, atype %d. Blocked by Originator %s. Disabling request! \n", str, hna_node->key.KEY_FIELD_ANETMASK, hna_node->key.KEY_FIELD_ATYPE, str2);
					hna_node->enabled = NO;
					
				}
					
			}
		}
	
	}

	if ( if_list.next != if_list.prev )
		((struct batman_if *)if_list.next)->out.size = (calc_ogm_if_size( 0 ))/4;
	
}



void add_del_own_srv( uint8_t purge ) {
	struct list_head *list_pos, *srv_pos_tmp;
	struct srv_node *srv_node;
	
	if ( purge ) { 
				
		list_for_each_safe( list_pos, srv_pos_tmp, &my_srv_list ) {

			srv_node = list_entry( list_pos, struct srv_node, list );
			
			list_del( (struct list_head*)&my_srv_list, list_pos, &my_srv_list );
			debugFree( srv_node, 1123 );

		}
	}

	if ( my_srv_ext_array != NULL )
		debugFree( my_srv_ext_array, 1124 );
	
	my_srv_ext_array = NULL;
		
	my_srv_ext_array_len = 0;
	
	
	if ( ! purge  &&  !( list_empty( &my_srv_list ) )  ) {
		
		my_srv_ext_array = debugMalloc( my_srv_list_enabled * sizeof(struct ext_packet), 125 );
		memset( my_srv_ext_array, 0, my_srv_list_enabled * sizeof(struct ext_packet) );

		list_for_each( list_pos, &my_srv_list ) {

			srv_node = list_entry( list_pos, struct srv_node, list );

			if ( srv_node->enabled ) {
					
				my_srv_ext_array[my_srv_ext_array_len].EXT_FIELD_MSG  = YES;
				my_srv_ext_array[my_srv_ext_array_len].EXT_FIELD_TYPE = EXT_TYPE_SRV;
	
				my_srv_ext_array[my_srv_ext_array_len].EXT_SRV_FIELD_ADDR  = srv_node->srv_addr;
				my_srv_ext_array[my_srv_ext_array_len].EXT_SRV_FIELD_PORT  = htons( srv_node->srv_port );
				my_srv_ext_array[my_srv_ext_array_len].EXT_SRV_FIELD_SEQNO = srv_node->srv_seqno;
				
				my_srv_ext_array_len++;
					
			}
		}
	
	}
	
	if ( if_list.next != if_list.prev )
		((struct batman_if *)if_list.next)->out.size = (calc_ogm_if_size( 0 ))/4;
		
}


void choose_gw() {

	prof_start( PROF_choose_gw );
	struct list_head *pos;
	struct gw_node *gw_node, *tmp_curr_gw = NULL;
	/* TBD: check the calculations of this variables for overflows */
	uint8_t max_gw_class = 0;
	uint32_t norm1000_max_packets = 0;  
	uint32_t max_gw_factor = 0, tmp_gw_factor = 0;  
	int download_speed, upload_speed; 
	static char orig_str[ADDR_STR_LEN];


	if ( ( routing_class == 0 ) || 
	     ((routing_class == 1 || routing_class == 2 ) && ( LESS_U32( batman_time, (my_ogi * my_pws / CHOOSE_GW_DELAY_DIVISOR) ) )) ) {

		prof_stop( PROF_choose_gw );
		return;

	}

	if ( curr_gateway == NULL && curr_gateway_thread_id != 0 )
		del_default_route();

	
	if ( list_empty( &gw_list ) ) {

		if ( curr_gateway != NULL ) {

			debug_output( 3, "Removing default route - no gateway in range\n" );

			del_default_route();

		}

		prof_stop( PROF_choose_gw );
		return;

	}


	list_for_each( pos, &gw_list ) {

		gw_node = list_entry( pos, struct gw_node, list );

		if( gw_node->unavail_factor > MAX_GW_UNAVAIL_FACTOR )
			gw_node->unavail_factor = MAX_GW_UNAVAIL_FACTOR;
		
		/* ignore this gateway if recent connection attempts were unsuccessful */
		if ( GREAT_U32( ((gw_node->unavail_factor * gw_node->unavail_factor * GW_UNAVAIL_TIMEOUT) + gw_node->last_failure), batman_time ) )
			continue;

		if ( gw_node->orig_node->router == NULL || gw_node->deleted || gw_node->orig_node->gw_msg == NULL )
			continue;
		
		if ( !( gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWTYPES & ( (two_way_tunnel?TWO_WAY_TUNNEL_FLAG:0) | (one_way_tunnel?ONE_WAY_TUNNEL_FLAG:0) ) ) )
			continue;
			
		switch ( routing_class ) {

			case 1:   /* fast connection */
				get_gw_speeds( gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWFLAGS, &download_speed, &upload_speed );

				// is this voodoo ???
				tmp_gw_factor = ( ( ( ( gw_node->orig_node->router->accepted_sqr.vcnt * 1000 ) / gw_node->orig_node->pws ) *
						    ( ( gw_node->orig_node->router->accepted_sqr.vcnt * 1000 ) / gw_node->orig_node->pws ) ) / 100 ) * 
						( download_speed / 64 ) ;
				
				if ( ( tmp_gw_factor > max_gw_factor ) || 
				     ( ( tmp_gw_factor == max_gw_factor ) && 
					( ((gw_node->orig_node->router->accepted_sqr.vcnt * 1000) / gw_node->orig_node->pws) > norm1000_max_packets ) ) )
					tmp_curr_gw = gw_node;
				
				break;

			case 2:   /* stable connection (use best statistic) */
				if ( ((gw_node->orig_node->router->accepted_sqr.vcnt * 1000) / gw_node->orig_node->pws) > norm1000_max_packets )
				//if ( gw_node->orig_node->router->packet_count > max_packets )
					tmp_curr_gw = gw_node;
				break;

			default:  /* fast-switch (use best statistic but change as soon as a better gateway appears) */
				if ( ((gw_node->orig_node->router->accepted_sqr.vcnt * 1000) / gw_node->orig_node->pws) > norm1000_max_packets )
				//if ( gw_node->orig_node->router->packet_count > max_packets )
					tmp_curr_gw = gw_node;
				break;

		}

		if ( gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWFLAGS > max_gw_class )
			max_gw_class = gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWFLAGS;

		if ( ((gw_node->orig_node->router->accepted_sqr.vcnt * 1000) / gw_node->orig_node->pws) > norm1000_max_packets )
		//if ( gw_node->orig_node->router->packet_count > max_packets )
			norm1000_max_packets = ((gw_node->orig_node->router->accepted_sqr.vcnt * 1000) / gw_node->orig_node->pws);

		if ( tmp_gw_factor > max_gw_factor )
			max_gw_factor = tmp_gw_factor;
		
		if ( ( pref_gateway != 0 ) && ( pref_gateway == gw_node->orig_node->orig ) ) {

			tmp_curr_gw = gw_node;

			addr_to_string( tmp_curr_gw->orig_node->orig, orig_str, ADDR_STR_LEN );
			debug_output( DBGL_SYSTEM, "Preferred gateway found: %s (gw_flags: %i, packet_count: %i, ws: %i, gw_product: %i)\n", orig_str, gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWFLAGS, gw_node->orig_node->router->accepted_sqr.vcnt, gw_node->orig_node->pws, tmp_gw_factor );
			
			break;

		}

	}


	if ( curr_gateway != tmp_curr_gw ) {

		if ( curr_gateway != NULL ) {

			if ( tmp_curr_gw != NULL )
				debug_output( 3, "removing default route - better gateway found\n" );
			else
				debug_output( 3, "removing default route - no gateway in range\n" );

			del_default_route();

		}

		/* may be the last gateway is now gone */
		if ( ( tmp_curr_gw != NULL ) && ( !is_aborted() ) ) {

			addr_to_string( tmp_curr_gw->orig_node->orig, orig_str, ADDR_STR_LEN );
			debug_output( DBGL_SYSTEM, "using default tunnel to GW %s (gw_flags: %i, packet_count: %i, gw_product: %i)\n", 
				      orig_str, max_gw_class, norm1000_max_packets, max_gw_factor );
			add_default_route( tmp_curr_gw );

		}

	}

	prof_stop( PROF_choose_gw );

}



void update_routes( struct orig_node *orig_node, struct neigh_node *neigh_node, struct ext_packet *hna_array, int16_t hna_array_len ) {

	prof_start( PROF_update_routes );
	static char orig_str[ADDR_STR_LEN], old_nh_str[ADDR_STR_LEN], new_nh_str[ADDR_STR_LEN];

	addr_to_string( orig_node->orig, orig_str, ADDR_STR_LEN );
	addr_to_string( (neigh_node        ?        neigh_node->addr : 0 ), new_nh_str, ADDR_STR_LEN );
	addr_to_string( (orig_node->router ? orig_node->router->addr : 0 ), old_nh_str, ADDR_STR_LEN );

	/* update routing table and check for changed hna announcements */
	if ( orig_node->router != neigh_node )
		debug_output( 3, "change route to %-15s via %-15s %3d / %3d (prev. via %-15s %3d)\n", orig_str, 
			      new_nh_str, (neigh_node ? neigh_node->accepted_sqr.vcnt : 0), orig_node->pws, 
					   old_nh_str, (orig_node->router ? orig_node->router->accepted_sqr.vcnt : 0) );
		


	debug_all( "update_routes() \n" );


	if (  orig_node->router != neigh_node  ) {

		if (  neigh_node != NULL  ) {
			debug_all( "Route to %s via %s\n", orig_str, new_nh_str );
		}

		/* route altered or deleted */
		if ( ( ( orig_node->router != NULL ) && ( neigh_node != NULL ) ) || ( neigh_node == NULL ) ) {

			if ( neigh_node == NULL ) {
				debug_all( "Deleting previous route\n" );
			} else {
				debug_all( "Route changed\n" );
			}

			/* remove old announced network(s) */
			if ( orig_node->hna_array_len > 0 )
				add_del_other_hna( orig_node, NULL, 0 );

			add_del_route( orig_node->orig, 32, orig_node->router->addr, 0, orig_node->router->if_incoming->if_index, orig_node->router->if_incoming->dev, BATMAN_RT_TABLE_HOSTS, 0, 1, NO/*no track*/ );

		}

		/* route altered or new route added */
		if ( ( ( orig_node->router != NULL ) && ( neigh_node != NULL ) ) || ( orig_node->router == NULL ) ) {

			if ( orig_node->router == NULL ) {
				debug_all( "Adding new route\n" );
			} else {
				debug_all( "Route changed\n" );
			}

			s_pog_route_changes++;
			orig_node->rt_changes++;
			
			add_del_route( orig_node->orig, 32, 
					neigh_node->addr, 
					outgoing_src ? outgoing_src : ((struct batman_if *)if_list.next)->addr.sin_addr.s_addr,
				//	neigh_node->if_incoming->addr.sin_addr.s_addr, 
					neigh_node->if_incoming->if_index, 
					neigh_node->if_incoming->dev, 
					BATMAN_RT_TABLE_HOSTS, 0, 0, NO/*no track*/ );

//			orig_node->batman_if = neigh_node->if_incoming;
			orig_node->router = neigh_node;

			/* add new announced network(s) */
			if ( ( hna_array_len > 0 ) && ( hna_array != NULL ) ) {

				add_del_other_hna( orig_node, hna_array, hna_array_len );

			}

			
			
		}

		orig_node->router = neigh_node;

		
	/* may be just HNA changed */
	} else if ( ( hna_array_len != orig_node->hna_array_len ) || ( ( hna_array_len > 0 ) && ( orig_node->hna_array_len > 0 )  && 
			( memcmp( orig_node->hna_array, hna_array, hna_array_len * sizeof(struct ext_packet) ) != 0 ) ) ) {

		if ( orig_node->hna_array_len > 0 )
			add_del_other_hna( orig_node, NULL, 0 );

		if ( ( hna_array_len > 0 ) && ( hna_array != NULL ) )
			add_del_other_hna( orig_node, hna_array, hna_array_len );

	}

	prof_stop( PROF_update_routes );

}



void update_gw_list( struct orig_node *orig_node, int16_t gw_array_len, struct ext_packet *gw_array ) {

	prof_start( PROF_update_gw_list );
	struct list_head *gw_pos, *gw_pos_tmp;
	struct gw_node *gw_node;
	static char orig_str[ADDR_STR_LEN], gw_str[ADDR_STR_LEN];
	int download_speed, upload_speed;

	list_for_each_safe( gw_pos, gw_pos_tmp, &gw_list ) {

		gw_node = list_entry(gw_pos, struct gw_node, list);

		if ( gw_node->orig_node == orig_node ) {

			addr_to_string( gw_node->orig_node->orig, orig_str, ADDR_STR_LEN );
			addr_to_string( (gw_array ? gw_array->EXT_GW_FIELD_GWADDR : 0), gw_str, ADDR_STR_LEN );
			
			debug_output( 3, "Gateway class of originator %s changed from %i to %i, port %d, addr %s, new supported tunnel types %s, %s\n", orig_str,
			    gw_node->orig_node->gw_msg ? gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWFLAGS : 0 ,
			    gw_array ?   gw_array->EXT_GW_FIELD_GWFLAGS : 0 , 
			    gw_array ?   ntohs( gw_array->EXT_GW_FIELD_GWPORT ) : 0 , 
       			    gw_str,
			    gw_array ? ((gw_array->EXT_GW_FIELD_GWTYPES & TWO_WAY_TUNNEL_FLAG)?"TWT":"-") : "-",
			    gw_array ? ((gw_array->EXT_GW_FIELD_GWTYPES & ONE_WAY_TUNNEL_FLAG)?"OWT":"-") : "-" );

			if ( gw_array_len > 0 && gw_array != NULL )  {

				gw_node->deleted = 0;
				if ( gw_node->orig_node->gw_msg == NULL )
					gw_node->orig_node->gw_msg = debugMalloc( sizeof( struct ext_packet ), 123 );
				
				memcpy( gw_node->orig_node->gw_msg, gw_array, sizeof( struct ext_packet ) );

				if( gw_node == curr_gateway )
					choose_gw();

			} else {

				gw_node->deleted = batman_time;
				
				if ( gw_node->orig_node->gw_msg != NULL )
					memset( gw_node->orig_node->gw_msg, 0, sizeof( struct ext_packet ) );
				
				debug_output( 3, "Gateway %s removed from gateway list\n", orig_str );

				if( gw_node == curr_gateway )
					choose_gw();

			}

			prof_stop( PROF_update_gw_list );
			return;

		}

	}

	if ( gw_array_len > 0 && gw_array != NULL ) {
	
		addr_to_string( orig_node->orig, orig_str, ADDR_STR_LEN );
		addr_to_string( gw_array->EXT_GW_FIELD_GWADDR, gw_str, ADDR_STR_LEN );
		get_gw_speeds( gw_array->EXT_GW_FIELD_GWFLAGS, &download_speed, &upload_speed );
	
		debug_output( 3, "found new gateway %s, announced by %s -> class: %i - %i%s/%i%s, new supported tunnel types %s, %s\n", 
			gw_str, orig_str, 
			gw_array->EXT_GW_FIELD_GWFLAGS, 
			( download_speed > 2048 ? download_speed / 1024 : download_speed ),
			( download_speed > 2048 ? "MBit" : "KBit" ),
			( upload_speed > 2048 ? upload_speed / 1024 : upload_speed ), 
			( upload_speed > 2048 ? "MBit" : "KBit" ), 
			((gw_array->EXT_GW_FIELD_GWTYPES & TWO_WAY_TUNNEL_FLAG)?"TWT":"-"), 
			((gw_array->EXT_GW_FIELD_GWTYPES & ONE_WAY_TUNNEL_FLAG)?"OWT":"-" ) );
	
		gw_node = debugMalloc( sizeof(struct gw_node), 103 );
		memset( gw_node, 0, sizeof(struct gw_node) );
		INIT_LIST_HEAD( &gw_node->list );
	
		gw_node->orig_node = orig_node;
		
		if ( orig_node->gw_msg == NULL )
			orig_node->gw_msg = debugMalloc( sizeof( struct ext_packet ), 123 );
		
		memcpy( orig_node->gw_msg, gw_array, sizeof( struct ext_packet ) );
		
		gw_node->unavail_factor = 0;
		gw_node->last_failure = batman_time;
	
		list_add_tail( &gw_node->list, &gw_list );
	
	}
	
	prof_stop( PROF_update_gw_list );

}



/* returns the up and downspeeds in kbit, calculated from the class */
void get_gw_speeds( unsigned char class, int *down, int *up ) {

	char sbit    = (class&0x80)>>7;
	char dpart   = (class&0x7C)>>3;
	char upart   = (class&0x07);

	*down= 32*(sbit+2)*(1<<dpart);
	*up=   ((upart+1)*(*down))/8;

}



/* calculates the gateway class from kbit */
unsigned char get_gw_class( int down, int up ) {

	int mdown = 0, tdown, tup, difference = 0x0FFFFFFF;
	unsigned char class = 0, sbit, part;


	/* test all downspeeds */
	for ( sbit = 0; sbit < 2; sbit++ ) {

		for ( part = 0; part < 16; part++ ) {

			tdown = 32 * ( sbit + 2 ) * ( 1<<part );

			if ( abs( tdown - down ) < difference ) {

				class = ( sbit<<7 ) + ( part<<3 );
				difference = abs( tdown - down );
				mdown = tdown;

			}

		}

	}

	/* test all upspeeds */
	difference = 0x0FFFFFFF;

	for ( part = 0; part < 8; part++ ) {

		tup = ( ( part+1 ) * ( mdown ) ) / 8;

		if ( abs( tup - up ) < difference ) {

			class = ( class&0xF8 ) | part;
			difference = abs( tup - up );

		}

	}

	return class;

}

void cleanup_vis( void ) {
	
	if ( vis_if == NULL )
		return;
	
	if ( vis_if->sock )
		close( vis_if->sock );
	
	debugFree( vis_if, 1731 );
	vis_if = NULL;
	
	if ( vis_packet != NULL )
		debugFree( vis_packet, 1108 );
	
	vis_packet = NULL;

}

void init_vis( uint32_t server ) {
	
	if ( vis_if )
		return;
	
	vis_if = debugMalloc( sizeof( struct vis_if ), 731 );
	
	memset( vis_if, 0, sizeof( struct vis_if ) );

	vis_if->addr.sin_family = AF_INET;
	vis_if->addr.sin_port = htons( vis_port );
	vis_if->addr.sin_addr.s_addr = server;
	vis_if->sock = socket( PF_INET, SOCK_DGRAM, 0 );
	
}

void send_vis_packet( struct vis_if *vis ) {
	
	struct vis_data *vis_data;
	struct list_head *list_pos;
	struct batman_if *batman_if;
	struct hna_node *hna_node;
	
	struct link_node *link_node;
	struct list_head *link_pos;

	struct neigh_node *neigh_node;
	struct list_head  *neigh_pos;
	
	int q, q_max;
			
	if( vis == NULL || vis->sock == 0 )
		return;
	
	if ( vis_packet != NULL ) {

		debugFree( vis_packet, 1102 );
		vis_packet = NULL;
		vis_packet_size = 0;

	}

	vis_packet_size = sizeof(struct vis_packet);
	vis_packet = debugMalloc( vis_packet_size, 104 );
	
	//TBD: Why memcpy this uint32_t assignement ???
	memcpy( &((struct vis_packet *)vis_packet)->sender_ip, (unsigned char *)&(((struct batman_if *)if_list.next)->addr.sin_addr.s_addr), 4 );

	((struct vis_packet *)vis_packet)->version = VIS_COMPAT_VERSION;
	((struct vis_packet *)vis_packet)->gw_class = gateway_class;
	((struct vis_packet *)vis_packet)->seq_range = my_lws;  

	
	/* neighbor list */
	
	list_for_each( link_pos, &link_list ) {

		link_node = list_entry(link_pos, struct link_node, list);
		
		if ( link_node->orig_node->router == NULL )
			continue;
		
		list_for_each( neigh_pos, &link_node->orig_node->neigh_list ) {
			
			q_max = 0;
			
			neigh_node = list_entry( neigh_pos, struct neigh_node, list );

			if( neigh_node->addr == link_node->orig_node->orig ) {
					
				q = link_node->lndev[ neigh_node->if_incoming->if_num ].rq_sqr.vcnt;

				q_max = ( q > q_max ? q : q_max );
				
			}
			
			if ( q_max > 0 ) {
			
				vis_packet_size += sizeof(struct vis_data);
		
				vis_packet = debugRealloc( vis_packet, vis_packet_size, 105 );
		
				vis_data = (struct vis_data *)(vis_packet + vis_packet_size - sizeof(struct vis_data));
		
				//TBD: Why memcpy this uint32_t assignement ???
				memcpy( &vis_data->ip, (unsigned char *)&link_node->orig_node->orig, 4 );
		
				vis_data->data = q_max;
				vis_data->type = DATA_TYPE_NEIGH;
			
			}
		}
	}

	
	/* secondary interfaces */
	if ( found_ifs > 1 ) {

		list_for_each( list_pos, &if_list ) {

			batman_if = list_entry( list_pos, struct batman_if, list );

			if ( ((struct vis_packet *)vis_packet)->sender_ip == batman_if->addr.sin_addr.s_addr )
				continue;

			vis_packet_size += sizeof(struct vis_data);

			vis_packet = debugRealloc( vis_packet, vis_packet_size, 106 );

			vis_data = (struct vis_data *)(vis_packet + vis_packet_size - sizeof(struct vis_data));

			//TBD: Why memcpy this uint32_t assignement ???
			memcpy( &vis_data->ip, (unsigned char *)&batman_if->addr.sin_addr.s_addr, 4 );

			vis_data->data = 0;
			vis_data->type = DATA_TYPE_SEC_IF;

		}

	}

	/* hna announcements */
	if ( !( list_empty( &my_hna_list ) ) ) {

		list_for_each( list_pos, &my_hna_list ) {

			hna_node = list_entry( list_pos, struct hna_node, list );

			vis_packet_size += sizeof(struct vis_data);

			vis_packet = debugRealloc( vis_packet, vis_packet_size, 107 );

			vis_data = (struct vis_data *)(vis_packet + vis_packet_size - sizeof(struct vis_data));

			//TBD: why not simply assign: vis_data->ip = hna_node->addr; ???
			memcpy( &vis_data->ip, (unsigned char *)&hna_node->key.addr, 4 );
			
			vis_data->data = hna_node->key.KEY_FIELD_ANETMASK;
			vis_data->type = DATA_TYPE_HNA;

		}

	}


	if ( vis_packet_size == sizeof(struct vis_packet) ) {

		debugFree( vis_packet, 1107 );
		vis_packet = NULL;
		vis_packet_size = 0;

	}

	if ( vis_packet != NULL )
		send_udp_packet( vis_packet, vis_packet_size, &vis->addr, vis->sock );

}



int calc_ogm_if_size( int if_num ) {
	
	if ( if_num == 0 )
		return ( sizeof(struct bat_packet_ogm) + ((my_gw_ext_array_len + my_hna_ext_array_len + my_srv_ext_array_len) * sizeof(struct ext_packet)) );
	else
		return ( sizeof(struct bat_packet_ogm) + sizeof(struct ext_packet) );
}

/*
uint32_t whats_next(  ) {

	static uint32_t next = 0;
	
	next++;
	
	next = next % 3;
	
	return next;
}


static int32_t test_func( void *para ) {
	
	static int32_t called = 0;
	debug_output(DBGL_TEST, "test_func() called with int val pointer %d \n", *((uint32_t*)para) );
	
	return called++;
	
}
*/

void batman( void ) {

	struct list_head *list_pos;
	struct batman_if *batman_if;
	uint32_t debug_timeout, statistic_timeout, vis_timeout, select_timeout, aggregation_time, probing_time;

	uint16_t aggr_interval;
	
	uint32_t s_last_cpu_time = 0, s_curr_cpu_time = 0;
	
	batman_time = debug_timeout = statistic_timeout = vis_timeout = get_time_msec();
		
	aggregation_time = probing_time = batman_time + 50 + rand_num( 100 );

	if ( NULL == ( orig_hash = hash_new( 128, compare_key, choose_key, 4 ) ) )
		cleanup_all( CLEANUP_FAILURE );
	
	if ( NULL == ( hna_hash = hash_new( 128, compare_key, choose_key, 5 ) ) )
		cleanup_all( CLEANUP_FAILURE );
	
	
	add_del_own_srv( NO /*do not purge*/ );	
	
	add_del_own_hna( NO /*do not purge*/ );	
	
	
	
	list_for_each( list_pos, &if_list ) {
		
		batman_if = list_entry( list_pos, struct batman_if, list );
		schedule_own_ogm( batman_if, batman_time );

	}
	

	prof_start( PROF_all );
	
	while ( !is_aborted() ) {
		
		prof_stop( PROF_all );
		prof_start( PROF_all );

		debug_output( DBGL_ALL, " \n \n" );

		
		
		if ( GREAT_U32( aggregation_time, batman_time ) ) {
		
			select_timeout = aggregation_time - batman_time ;
			
			if ( select_timeout > MAX_SELECT_TIMEOUT_MS )
				select_timeout = MAX_SELECT_TIMEOUT_MS;
			
			wait4Event( select_timeout );
			
		} 

		
		if ( LSEQ_U32( aggregation_time, batman_time ) ) {
				
			aggr_interval = (my_ogi/aggregations_per_ogi > MAX_AGGREGATION_INTERVAL_MS) ? MAX_AGGREGATION_INTERVAL_MS :  (my_ogi/aggregations_per_ogi);

			send_outstanding_ogms();
			
			aggregation_time = (batman_time + aggr_interval + rand_num( aggr_interval/2 )) - (aggr_interval/4);
			
		}
		
		if ( unicast_probes_num && LSEQ_U32( probing_time, batman_time ) ) {
			
			probing_time = batman_time + send_unicast_probes();
			
		}
		

		if ( LESS_U32( debug_timeout + 1000,  batman_time ) ) {
	
			
			purge_orig( batman_time );
			
			purge_empty_hna_nodes( );
			
	
			list_for_each( list_pos, &dbgl_clients[DBGL_ALL] ) {
				
				debug_orig( DBGL_ALL, (list_entry( list_pos, struct client_node, list ))->fd );
				
			}
			
		
			
			if ( ( routing_class != 0 ) && ( curr_gateway == NULL ) )
				choose_gw();
	
			
			if ( vis_if && vis_if->sock && LESS_U32( vis_timeout + 10000, batman_time  ) ) {
	
				vis_timeout = batman_time;
				
				send_vis_packet( vis_if );
	
			}
			
			
			if ( LESS_U32( statistic_timeout + 5000, batman_time ) ) {
			
				// check if corrupted memory..
				checkIntegrity();
				
				
				// check for changed kernel konfigurations...
				check_kernel_config( NULL, NO );
				// check for changed interface konfigurations...
				list_for_each( list_pos, &if_list ) {
					
					batman_if = list_entry( list_pos, struct batman_if, list );

					if ( batman_if->if_active )
						check_kernel_config( batman_if, NO );
					
				}
				
				
				
				/* generating cpu load statistics... */
				s_curr_cpu_time = (uint32_t)clock();
				
				curr_statistic_period_ms = ( batman_time - statistic_timeout ) ;
				
				if ( curr_statistic_period_ms > 0 ) {
					
					s_curr_avg_cpu_load = ( (s_curr_cpu_time - s_last_cpu_time) / curr_statistic_period_ms );
					debug_output( DBGL_STATISTICS, "stats: load %2d  sched. %3d, Agg. rcvd %3d, brc %3d, OGMs rcvd %3d, accept %3d, brc %3d, rt %3d \n",
					s_curr_avg_cpu_load,
					s_returned_select * 1000 / curr_statistic_period_ms,
					s_received_aggregations * 1000 / curr_statistic_period_ms,
					s_broadcasted_aggregations * 1000 / curr_statistic_period_ms,
					s_received_ogms * 1000 / curr_statistic_period_ms,
					s_accepted_ogms * 1000 / curr_statistic_period_ms,
					s_broadcasted_ogms * 1000 / curr_statistic_period_ms,
					s_pog_route_changes * 1000 / curr_statistic_period_ms );

					
					if ( s_curr_avg_cpu_load < 255 )
						(list_entry( (&if_list)->next, struct batman_if, list ))->out.reserved_someting = s_curr_avg_cpu_load;
					else 
						(list_entry( (&if_list)->next, struct batman_if, list ))->out.reserved_someting = 255;
				
				
				}
				
				s_returned_select = s_received_aggregations = s_broadcasted_aggregations = s_received_ogms = s_accepted_ogms = s_broadcasted_ogms = s_pog_route_changes = 0; 
			
				
				s_last_cpu_time = s_curr_cpu_time;
			
				statistic_timeout = batman_time;
			}
			
			/* preparing the next debug_timeout */
			debug_timeout = batman_time;
			
		}
			
		
	}

	prof_stop( PROF_all );


}
