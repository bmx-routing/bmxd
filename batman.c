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



#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>


#include "os.h"
#include "batman.h"
#include "originator.h"
#include "schedule.h"



uint8_t debug_level = 0;


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

uint8_t routing_class = 0;

//uint8_t compat_version = DEF_COMPAT_VERSION;

int16_t my_ogi = DEFAULT_ORIGINATOR_INTERVAL;   /* orginator message interval in miliseconds */

int32_t dad_timeout = DEFAULT_DAD_TIMEOUT;


//int8_t advanced_opts = DEF_ADVANCED_SWITCH;

int8_t resist_blocked_send = DEF_RESIST_BLOCKED_SEND;



/* bidirectional link timeout in number+1 of maximum acceptable missed (not received by this node)
of last send own OGMs rebroadcasted from neighbors */
int32_t bidirect_link_to = DEF_BIDIRECT_TIMEOUT;

int32_t aggregations_po = DEF_AGGREGATIONS_PO;

int32_t my_ws = DEF_SEQ_RANGE;

int32_t initial_seqno = DEF_INITIAL_SEQNO;

int32_t fake_uptime = DEF_FAKE_UPTIME;

int32_t ttl = DEFAULT_TTL;

uint8_t mobile_device = NO;
uint8_t no_unreachable_rule = NO;
uint8_t no_tun_persist = NO;
uint8_t no_forw_dupl_ttl_check = NO;
int32_t dup_ttl_limit = DEF_DUP_TTL_LIMIT;
int32_t dup_rate =  DEF_DUP_RATE;
int32_t dup_degrad = DEF_DUP_DEGRAD;

int32_t wl_clones = DEF_WL_CLONES;

int32_t asymmetric_weight = DEF_ASYMMETRIC_WEIGHT;

int32_t asymmetric_exp = DEF_ASYMMETRIC_EXP;

int32_t rebrc_delay = DEF_REBRC_DELAY;

int32_t default_para_set =  DEF_PARA_SET;

int32_t ogm_port = DEF_BASE_PORT;
int32_t my_gw_port = DEF_GW_PORT;
uint32_t my_gw_addr = DEF_GW_ADDR;
int32_t vis_port = DEF_VIS_PORT;

int32_t rt_table_offset   = DEF_RT_TABLE_OFFSET;

int32_t rt_prio_offset = DEF_RT_PRIO_OFFSET;

int32_t more_rules = DEF_MORE_RULES;

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

uint8_t conn_client = 0;

uint8_t log_facility_active = NO;

int g_argc;
char **g_argv;

struct bat_packet **received_ogm;
uint32_t           *received_neigh;
struct batman_if  **received_if_incoming;
uint32_t           *received_batman_time;

struct ext_packet **received_gw_array;
int16_t            *received_gw_pos;
struct ext_packet **received_hna_array;
int16_t            *received_hna_pos;
struct ext_packet **received_srv_array;
int16_t            *received_srv_pos;
struct ext_packet **received_vis_array;
int16_t            *received_vis_pos;
struct ext_packet **received_pip_array;
int16_t            *received_pip_pos;

struct hashtable_t *orig_hash;
struct hashtable_t *hna_hash;

struct list_head_first forw_list;
struct list_head_first if_list;
struct list_head_first gw_list;
struct list_head_first notun_list;
struct list_head_first my_hna_list;
struct list_head_first my_srv_list;
struct list_head_first link_list;
struct list_head_first pifnb_list;

struct list_head_first todo_list;
pthread_mutex_t *todo_mutex = NULL;

struct vis_if vis_if;
struct unix_if unix_if;

pthread_t gw_thread_id = 0;

int gw_thread_finish = 0;

struct debug_clients debug_clients;

unsigned char *vis_packet = NULL;
uint16_t vis_packet_size = 0;

int s_returned_select = 0;
int s_received_aggregations = 0;
int s_broadcasted_aggregations = 0;
int s_broadcasted_cp_aggregations = 0;
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

	fprintf( stderr, "\n       --%s : does not set the unreachable rule for host routes.\n", NO_UNREACHABLE_RULE_SWITCH );
	
	fprintf( stderr, "\n       --%s : does not set the default priority rules.\n", NO_PRIO_RULES_SWITCH );
	
	fprintf( stderr, "\n       --%s : does not set the default throw rules.\n", NO_THROW_RULES_SWITCH );
	
	fprintf( stderr, "\n       --%s : Set unreachable rule. Limits scope of batman routing table. \n", MORE_RULES_SWITCH);
	
	fprintf( stderr, "\n       --%s : Deprecated! Now daemon'll always survive blocked sending.\n", RESIST_BLOCKED_SEND_SWITCH );
	
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
	
	fprintf( stderr, "\n       --%s : Disable OGM aggregation \n", NO_AGGREGATIONS_SWITCH);
	
	fprintf( stderr, "\n       --%s : Send aggregated OGMs every 1/%dth of the originator inteval. \n", AGGREGATIONS_SWITCH, DEF_AGGREGATIONS_PO);

	fprintf( stderr, "\n       --%s <value>: Set number of aggregations per originator interval manually.\n", AGGREGATIONS_PO_SWITCH );
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d \n", DEF_AGGREGATIONS_PO, MIN_AGGREGATIONS_PO, MAX_AGGREGATIONS_PO  );

	fprintf( stderr, "\n       --%s <value> : change default TTL of originator packets.\n", TTL_SWITCH );
	fprintf( stderr, "        /%c <value> : attached after an interface name\n", TTL_IF_SWITCH );
	fprintf( stderr, "          to change the TTL only for the OGMs representing a specific interface\n");
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d\n", DEFAULT_TTL, MIN_TTL, MAX_TTL  );
	
	fprintf( stderr, "\n        /%c : attached after an interface name\n", OGM_ONLY_VIA_OWNING_IF_SWITCH );
	fprintf( stderr, "          to broadcast the OGMs representing this interface only via this interface,\n");
	fprintf( stderr, "          also reduces the TTL for OGMs representing this interface to 1.\n");
	
	fprintf( stderr, "\n        /%c : attached after an interface name\n", MAKE_IP_HNA_IF_SWITCH );
	fprintf( stderr, "          to add the IP address of this interface to the HNA list. Also\n");
	fprintf( stderr, "          reduces the TTL for OGMs representing this interface to 1 and\n");
	fprintf( stderr, "          broadcasts the OGMs representing this interface only via this interface\n");

	fprintf( stderr, "\n        /%c : attached after an interface name\n", UNDO_IP_HNA_IF_SWITCH );
	fprintf( stderr, "          to remove the IP address of this interface from the HNA list.\n");
	
	/*
	fprintf( stderr, "\n       --%s <value> : set bidirectional timeout value\n", BIDIRECT_TIMEOUT_SWITCH );
	fprintf( stderr, "        /%c <value> : attached after an interface name\n", BIDIRECT_TIMEOUT_IF_SWITCH );
	fprintf( stderr, "          to set individual bidirectionl-timeout value this interface.\n");
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d \n", DEF_BIDIRECT_TIMEOUT, MIN_BIDIRECT_TIMEOUT, MAX_BIDIRECT_TIMEOUT  );
	*/
	
	fprintf( stderr, "\n       --%s <value> : set window size for path statistic\n", NBRFSIZE_SWITCH );
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d\n", DEF_SEQ_RANGE, MIN_SEQ_RANGE, MAX_SEQ_RANGE  );
	
	fprintf( stderr, "\n       --%s <value> : set window size for link statistic\n", BIDIRECT_TIMEOUT_SWITCH );
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d\n", DEF_BIDIRECT_TIMEOUT, MIN_BIDIRECT_TIMEOUT, MAX_BIDIRECT_TIMEOUT  );
	
	fprintf( stderr, "\n       --%s <value> : set initial seqno for this nodes OGMs\n", INITIAL_SEQNO_SWITCH );
	if ( verbose )
		fprintf( stderr, "          default: %d, (0 = random) allowed values: %d <= value <= %d\n", DEF_INITIAL_SEQNO, MIN_INITIAL_SEQNO, MAX_INITIAL_SEQNO  );
	
	fprintf( stderr, "\n       --%s <value> : set maximum of random re-broadcast delay \n", REBRC_DELAY_SWITCH );
	fprintf( stderr, "          only evaluated with %s, otherwhise re-broadcast delay is randomized anyway\n", NO_AGGREGATIONS_SWITCH);
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d\n", DEF_REBRC_DELAY, MIN_REBRC_DELAY, MAX_REBRC_DELAY  );
	
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
	
	fprintf( stderr, "\n       --%s <value> : accept non-quickest OGMs to relieve preference for shortest path. \n", DUP_DEGRAD_SWITCH );
	fprintf( stderr, "          < value > defines the probability degradation for each additional hop (compared \n");
	fprintf( stderr, "          to the OGM arrived via the shortest path) with which non-quickest OGMs are accepted. \n");
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values in percent: %d <= value <= %d\n", DEF_DUP_DEGRAD, MIN_DUP_DEGRAD, MAX_DUP_DEGRAD );
	
	fprintf( stderr, "\n       --%s : mobile device mode reluctant to help others.\n", ASOCIAL_SWITCH );
	
}

void usage( void ) {

	fprintf( stderr, "Usage: batman [options] interface [interface interface]\n" );
	fprintf( stderr, "       -a announce network(s)\n" );
	fprintf( stderr, "       -b run connection in batch mode\n" );
	fprintf( stderr, "       -c connect via unix socket\n" );
	fprintf( stderr, "       -d debug level\n" );
	fprintf( stderr, "       -g gateway class\n" );
	fprintf( stderr, "       -h this help\n" );
	fprintf( stderr, "       -H verbose help\n" );
	fprintf( stderr, "       -i internal options output\n" );
	fprintf( stderr, "       -o originator interval in ms\n" );
	fprintf( stderr, "       -p preferred gateway\n" );
	fprintf( stderr, "       -r routing class\n" );
	fprintf( stderr, "       -s visualization server\n" );
	fprintf( stderr, "       -v print version\n\n" );
	
	fprintf( stderr, "       --%s : parametrize the routing algorithm to the best of BMX knowledge! DEFAULT !\n", BMX_DEFAULTS_SWITCH );
	fprintf( stderr, "       --%s : parametrize the routing algorithm according to the WCW Graz 2007 experiments!\n\n", GRAZ07_DEFAULTS_SWITCH );
	
	
	fprintf( stderr, "       --dangerous : show advanced and dangerous options \n" );


}


void verbose_usage( void ) {

	fprintf( stderr, "Usage: batman [options] interface [interface interface]\n\n" );
	fprintf( stderr, "       -a announce network(s)\n" );
	fprintf( stderr, "          network/netmask is expected\n" );
	fprintf( stderr, "       -b run connection in batch mode\n" );
	fprintf( stderr, "       -c connect to running batmand via unix socket\n" );
	fprintf( stderr, "       -d debug level\n" );
	fprintf( stderr, "          default:         0 -> debug disabled\n" );
	fprintf( stderr, "          allowed values:  1 -> list originators\n" );
	fprintf( stderr, "                           2 -> list gateways\n" );
	fprintf( stderr, "                           3 -> observe batman\n" );
	fprintf( stderr, "                           4 -> observe batman (very verbose)\n" );
//	if ( debug_level_max == 5  )
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
	fprintf( stderr, "       -v print version\n\n" );
	
	fprintf( stderr, "       --%s : parametrize the routing algorithm to the best of BMX knowledge! DEFAULT !\n", BMX_DEFAULTS_SWITCH );
	fprintf( stderr, "       --%s : parametrize the routing algorithm according to the WCW Graz 2007 experiments!\n\n", GRAZ07_DEFAULTS_SWITCH );
	
	fprintf( stderr, "\n       --dangerous : show advanced and dangerous options \n" );

}

uint32_t purge_timeout ( struct orig_node *orig_node ) {
	/* purge originators after time in ms if no valid packet comes in -> TODO: check influence on SEQ_RANGE */
	
	/*=2*o*ws*dad/100=300s previously 400000*/
	return ((((DEFAULT_ORIGINATOR_INTERVAL)*(orig_node->ws)*dad_timeout)/50) + PURGE_SAFETY_PERIOD);
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
	while ( NULL != ( hashit = hash_iterate( hna_hash, hashit ) ) ) {

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
	debug_output( 4, "  creating new and empty hna_hash_node: %s/%d, type %d \n", hna_str, hk->KEY_FIELD_ANETMASK, hk->KEY_FIELD_ATYPE );

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
			restore_and_exit(0);

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
		restore_and_exit(0);
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
				
				add_del_route( key.addr, key.KEY_FIELD_ANETMASK, orig_node->router->addr, orig_node->router->if_incoming->addr.sin_addr.s_addr, orig_node->batman_if->if_index, orig_node->batman_if->dev, rt_table, 0, del );
				
				hash_node->status = HNA_HASH_NODE_EMPTY;
				hash_node->orig = NULL;
				
			} else if ( !del && hash_node->status == HNA_HASH_NODE_EMPTY && hash_node->orig == NULL ) {
				
				add_del_route( key.addr, key.KEY_FIELD_ANETMASK, orig_node->router->addr, orig_node->router->if_incoming->addr.sin_addr.s_addr, orig_node->batman_if->if_index, orig_node->batman_if->dev, rt_table, 0, del );
				
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
		restore_and_exit(0);
		
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
			add_del_route( hna_node->key.addr, hna_node->key.KEY_FIELD_ANETMASK, 0, 0, 0, "unknown", BATMAN_RT_TABLE_INTERFACES, 1, 1 );
			add_del_route( hna_node->key.addr, hna_node->key.KEY_FIELD_ANETMASK, 0, 0, 0, "unknown", BATMAN_RT_TABLE_NETWORKS,   1, 1 );
			add_del_route( hna_node->key.addr, hna_node->key.KEY_FIELD_ANETMASK, 0, 0, 0, "unknown", BATMAN_RT_TABLE_HOSTS,      1, 1 );
			add_del_route( hna_node->key.addr, hna_node->key.KEY_FIELD_ANETMASK, 0, 0, 0, "unknown", BATMAN_RT_TABLE_UNREACH,    1, 1 );
			add_del_route( hna_node->key.addr, hna_node->key.KEY_FIELD_ANETMASK, 0, 0, 0, "unknown", BATMAN_RT_TABLE_TUNNEL,     1, 1 );
			
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
		debugFree( my_hna_ext_array, 1104 );
		
	my_hna_ext_array_len = 0;

	
	
	if ( ! purge  &&  !( list_empty( &my_hna_list ) )  ) {
		
		my_hna_ext_array = debugMalloc( my_hna_list_enabled * sizeof(struct ext_packet), 15 );
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
					add_del_route( hna_node->key.addr, hna_node->key.KEY_FIELD_ANETMASK, 0,0,0, "unknown", BATMAN_RT_TABLE_INTERFACES, 1, 0 );
					add_del_route( hna_node->key.addr, hna_node->key.KEY_FIELD_ANETMASK, 0,0,0, "unknown", BATMAN_RT_TABLE_NETWORKS,   1, 0 );
					add_del_route( hna_node->key.addr, hna_node->key.KEY_FIELD_ANETMASK, 0,0,0, "unknown", BATMAN_RT_TABLE_HOSTS,      1, 0 );
					add_del_route( hna_node->key.addr, hna_node->key.KEY_FIELD_ANETMASK, 0,0,0, "unknown", BATMAN_RT_TABLE_UNREACH,    1, 0 ); 
					add_del_route( hna_node->key.addr, hna_node->key.KEY_FIELD_ANETMASK, 0,0,0, "unknown", BATMAN_RT_TABLE_TUNNEL,     1, 0 );
					
				} else {
					
					addr_to_string( hna_node->key.addr, str, ADDR_STR_LEN );
					addr_to_string( hash_node->orig->orig, str2, ADDR_STR_LEN );
					debug_output( DBGL_SYSTEM, "Error - Could not announce network %s/%d, atype %d. Blocked by Originator %s. Disabling request! \n", str, hna_node->key.KEY_FIELD_ANETMASK, hna_node->key.KEY_FIELD_ATYPE, str2);
					hna_node->enabled = NO;
					
				}
					
			}
		}
	
	}
	
	((struct batman_if *)if_list.next)->out.size = (calc_ogm_if_size( 0 ))/4;
		
}



void add_del_own_srv( uint8_t purge ) {
	struct list_head *list_pos, *srv_pos_tmp;
	struct srv_node *srv_node;
	
	if ( purge ) { 
				
		list_for_each_safe( list_pos, srv_pos_tmp, &my_srv_list ) {

		srv_node = list_entry( list_pos, struct srv_node, list );
		
		debugFree( srv_node, 1123 );

		}
	}

	if ( my_srv_ext_array != NULL )
		debugFree( my_srv_ext_array, 1124 );
		
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
	
	((struct batman_if *)if_list.next)->out.size = (calc_ogm_if_size( 0 ))/4;
		
}


void choose_gw() {

	prof_start( PROF_choose_gw );
	struct list_head *pos;
	struct gw_node *gw_node, *tmp_curr_gw = NULL;
	/* TBD: check the calculations of this variables for overflows */
	uint8_t max_gw_class = 0;
	uint32_t norm1000_max_packets = 0;  
	uint32_t current_time, max_gw_factor = 0, tmp_gw_factor = 0;  
	int download_speed, upload_speed; 
	static char orig_str[ADDR_STR_LEN];


	if ( ( routing_class == 0 ) || ( ( current_time = *received_batman_time ) < my_ogi * my_ws / CHOOSE_GW_DELAY_DIVISOR ) ) {

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
		if ( ( gw_node->unavail_factor * gw_node->unavail_factor * GW_UNAVAIL_TIMEOUT ) + gw_node->last_failure > current_time )
			continue;

		if ( gw_node->orig_node->router == NULL || gw_node->deleted || gw_node->orig_node->gw_msg == NULL )
			continue;
		
		if ( !( gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWTYPES & ( (two_way_tunnel?TWO_WAY_TUNNEL_FLAG:0) | (one_way_tunnel?ONE_WAY_TUNNEL_FLAG:0) ) ) )
			continue;
			
		switch ( routing_class ) {

			case 1:   /* fast connection */
				get_gw_speeds( gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWFLAGS, &download_speed, &upload_speed );

				// is this voodoo ???
				tmp_gw_factor = ( ( ( ( gw_node->orig_node->router->packet_count * 1000 ) / gw_node->orig_node->ws ) *
						    ( ( gw_node->orig_node->router->packet_count * 1000 ) / gw_node->orig_node->ws ) ) / 100 ) * 
						( download_speed / 64 ) ;
				
				if ( ( tmp_gw_factor > max_gw_factor ) || 
				     ( ( tmp_gw_factor == max_gw_factor ) && ( ((gw_node->orig_node->router->packet_count * 1000) / gw_node->orig_node->ws) > norm1000_max_packets ) ) )
					tmp_curr_gw = gw_node;
				
				break;

			case 2:   /* stable connection (use best statistic) */
				if ( ((gw_node->orig_node->router->packet_count * 1000) / gw_node->orig_node->ws) > norm1000_max_packets )
				//if ( gw_node->orig_node->router->packet_count > max_packets )
					tmp_curr_gw = gw_node;
				break;

			default:  /* fast-switch (use best statistic but change as soon as a better gateway appears) */
				if ( ((gw_node->orig_node->router->packet_count * 1000) / gw_node->orig_node->ws) > norm1000_max_packets )
				//if ( gw_node->orig_node->router->packet_count > max_packets )
					tmp_curr_gw = gw_node;
				break;

		}

		if ( gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWFLAGS > max_gw_class )
			max_gw_class = gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWFLAGS;

		if ( ((gw_node->orig_node->router->packet_count * 1000) / gw_node->orig_node->ws) > norm1000_max_packets )
		//if ( gw_node->orig_node->router->packet_count > max_packets )
			norm1000_max_packets = ((gw_node->orig_node->router->packet_count * 1000) / gw_node->orig_node->ws);

		if ( tmp_gw_factor > max_gw_factor )
			max_gw_factor = tmp_gw_factor;
		
		if ( ( pref_gateway != 0 ) && ( pref_gateway == gw_node->orig_node->orig ) ) {

			tmp_curr_gw = gw_node;

			addr_to_string( tmp_curr_gw->orig_node->orig, orig_str, ADDR_STR_LEN );
			debug_output( 3, "Preferred gateway found: %s (gw_flags: %i, packet_count: %i, ws: %i, gw_product: %i)\n", orig_str, gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWFLAGS, gw_node->orig_node->router->packet_count, gw_node->orig_node->ws, tmp_gw_factor );
			
			break;

		}

	}


	if ( curr_gateway != tmp_curr_gw ) {

		if ( curr_gateway != NULL ) {

			if ( tmp_curr_gw != NULL )
				debug_output( 3, "Removing default route - better gateway found\n" );
			else
				debug_output( 3, "Removing default route - no gateway in range\n" );

			del_default_route();

		}

		/* may be the last gateway is now gone */
		if ( ( tmp_curr_gw != NULL ) && ( !is_aborted() ) ) {

			addr_to_string( tmp_curr_gw->orig_node->orig, orig_str, ADDR_STR_LEN );
			debug_output( 3, "Adding default route to %s (gw_flags: %i, packet_count: %i, gw_product: %i)\n", 
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
		debug_output( 3, "change OG (& HNA) routes of %15s via %15s %3d / %3d (prev. via %15s %3d)\n", orig_str, 
			      new_nh_str, (neigh_node ? neigh_node->packet_count : 0), orig_node->ws, 
			      old_nh_str, (orig_node->router ? orig_node->router->packet_count : 0) );
		


	debug_output( 4, "update_routes() \n" );


	if (  orig_node->router != neigh_node  ) {

		if (  neigh_node != NULL  ) {
			debug_output( 4, "Route to %s via %s\n", orig_str, new_nh_str );
		}

		/* route altered or deleted */
		if ( ( ( orig_node->router != NULL ) && ( neigh_node != NULL ) ) || ( neigh_node == NULL ) ) {

			if ( neigh_node == NULL ) {
				debug_output( 4, "Deleting previous route\n" );
			} else {
				debug_output( 4, "Route changed\n" );
			}

			/* remove old announced network(s) */
			if ( orig_node->hna_array_len > 0 )
				add_del_other_hna( orig_node, NULL, 0 );

			add_del_route( orig_node->orig, 32, orig_node->router->addr, 0, orig_node->batman_if->if_index, orig_node->batman_if->dev, BATMAN_RT_TABLE_HOSTS, 0, 1 );

		}

		/* route altered or new route added */
		if ( ( ( orig_node->router != NULL ) && ( neigh_node != NULL ) ) || ( orig_node->router == NULL ) ) {

			if ( orig_node->router == NULL ) {
				debug_output( 4, "Adding new route\n" );
			} else {
				debug_output( 4, "Route changed\n" );
			}

			s_pog_route_changes++;
			orig_node->rt_changes++;
			
			add_del_route( orig_node->orig, 32, neigh_node->addr, neigh_node->if_incoming->addr.sin_addr.s_addr, neigh_node->if_incoming->if_index, neigh_node->if_incoming->dev, BATMAN_RT_TABLE_HOSTS, 0, 0 );

			orig_node->batman_if = neigh_node->if_incoming;
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



void update_gw_list( struct orig_node *orig_node, int16_t gw_array_len, struct ext_packet *gw_array /*,uint8_t new_gwflags, uint8_t new_gwtypes*/ ) {

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

				gw_node->deleted = *received_batman_time;
				
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
	
		debug_output( 3, "Found new gateway %s, announced by %s -> class: %i - %i%s/%i%s, new supported tunnel types %s, %s\n", 
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
		gw_node->last_failure = *received_batman_time;
	
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



uint8_t alreadyConsidered( struct orig_node *orig_node, uint16_t seqno, uint32_t neigh, struct batman_if *if_incoming ) {

	struct list_head *neigh_pos;
	struct neigh_node *neigh_node;

	list_for_each( neigh_pos, &orig_node->neigh_list ) {

		neigh_node = list_entry( neigh_pos, struct neigh_node, list );

		if ( neigh == neigh_node->addr && if_incoming == neigh_node->if_incoming ) {
			
			neigh_node->last_aware = *received_batman_time;

			if ( seqno == neigh_node->last_considered_seqno ) { 
				
				return YES;
				
			/* remove this else branch: */	
			} else if ( ( seqno - neigh_node->last_considered_seqno ) > ( FULL_SEQ_RANGE - orig_node->ws ) ) {

				debug_output( 0, "alreadyConsidered(): This should not happen, we only acceppt current packets anyway !!!!!!!\n");
				return YES;
				
				
			} else {
		
				neigh_node->last_considered_seqno = seqno;
				return NO;
			}
			
		}

	}

	debug_output( 4, "Creating new last-hop neighbour of originator\n" );

	neigh_node = debugMalloc( sizeof (struct neigh_node), 403 );
	memset( neigh_node, 0, sizeof(struct neigh_node) );
	INIT_LIST_HEAD( &neigh_node->list );

	neigh_node->addr = neigh;
	neigh_node->if_incoming = if_incoming;
	neigh_node->last_considered_seqno = seqno;
	neigh_node->last_aware = *received_batman_time;
		
	list_add_tail( &neigh_node->list, &orig_node->neigh_list );

	return NO;

}


void generate_vis_packet() {

	struct vis_data *vis_data;
	struct list_head *list_pos;
	struct batman_if *batman_if;
	struct hna_node *hna_node;
	
	struct link_node *link_node;
	struct list_head *link_pos;

	struct neigh_node *neigh_node;
	struct list_head  *neigh_pos;
	
	int q, q_max;
			

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
	((struct vis_packet *)vis_packet)->seq_range = bidirect_link_to;  

	
	/* neighbor list */
	
	list_for_each( link_pos, &link_list ) {

		link_node = list_entry(link_pos, struct link_node, list);
		
		if ( link_node->orig_node->router == NULL )
			continue;
		
		list_for_each( neigh_pos, &link_node->orig_node->neigh_list ) {
			
			q_max = 0;
			
			neigh_node = list_entry( neigh_pos, struct neigh_node, list );

			if( neigh_node->addr == link_node->orig_node->orig ) {
					
				q = get_lq_bits( link_node, neigh_node->if_incoming, bidirect_link_to );
				//  q = tq_rate( link_node->orig_node, neigh_node->if_incoming, bidirect_link_to );

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

}


void send_vis_packet() {

	generate_vis_packet();

	if ( vis_packet != NULL )
		send_udp_packet( vis_packet, vis_packet_size, &vis_if.addr, vis_if.sock, NULL );

}

void check_todos() {
	struct list_head *todo_pos, *todo_pos_tmp;
	struct todo_node *todo_node;
	char fake_arg[ADDR_STR_LEN + 12], addr_str[ADDR_STR_LEN];

	if ( pthread_mutex_trylock( (pthread_mutex_t *)todo_mutex ) != 0 ) {
		debug_output( 0, "Error - could not trylock todo_mutex: %s \n", strerror( errno ) );
	} else {
	
		list_for_each_safe( todo_pos, todo_pos_tmp, &todo_list) {
			
			todo_node = list_entry( todo_pos, struct todo_node, list );
			
			
			
			if ( todo_node->todo_type == REQ_PREF_GW ) {
			
				pref_gateway = todo_node->def32;

				if ( curr_gateway != NULL )
					del_default_route();

			} else if ( todo_node->todo_type == REQ_1WT ) {
				
				// if there is a gw-client thread: stop it now, it restarts automatically
				del_default_route(); 
									
				// if there is a gw thread: stop it now
				stop_gw_service();
									
				one_way_tunnel = todo_node->def8;
																	
				debug_output( 3, " changing rt_class: %d owt: %d twt: %d gw_class %d \n", 
					      routing_class, one_way_tunnel, two_way_tunnel, gateway_class );
									
				if ( gateway_class  &&  (one_way_tunnel || two_way_tunnel)  &&  probe_tun(0) )
					start_gw_service();

			} else if ( todo_node->todo_type == REQ_2WT ) {
				
				// if there is a gw-client thread: stop it now, it restarts automatically
				del_default_route(); 
									
				// if there is a gw thread: stop it now
				stop_gw_service();
									
				two_way_tunnel = todo_node->def8;
																	
				debug_output( 3, " changing rt_class: %d owt: %d twt: %d gw_class %d \n", 
					      routing_class, one_way_tunnel, two_way_tunnel, gateway_class );
									
				if ( gateway_class  &&  (one_way_tunnel || two_way_tunnel)  &&  probe_tun(0) )
					start_gw_service();

				
			} else if ( todo_node->todo_type == REQ_GW_CLASS ) {
				
				gateway_class = todo_node->def8;
										
				stop_gw_service();
									
				if ( gateway_class  &&  (one_way_tunnel || two_way_tunnel)  &&  probe_tun(0) ) {

					if ( routing_class > 0 ) {

						routing_class = 0;
		
						del_default_route();
									
						add_del_interface_rules( YES/*del*/, YES/*tunnel*/, NO/*networks*/ );

					}
									
					start_gw_service();
				}

			} else if ( todo_node->todo_type == REQ_RT_CLASS ) {
			
				if (  todo_node->def8 > 0  &&  gateway_class > 0  ) {
					gateway_class = 0;
					stop_gw_service();
				}
				
				debug_output( 3, "found todo item, changing to -r %d \n", todo_node->def8 );
									
				if ( routing_class == 0 && todo_node->def8 > 0 )
					add_del_interface_rules( NO/*del*/, YES/*tunnel*/, NO/*networks*/ );
										
				if ( routing_class > 0 && todo_node->def8 == 0 )
					add_del_interface_rules( YES/*del*/, YES/*tunnel*/, NO/*networks*/ );
									
				routing_class = todo_node->def8;
									
				if ( curr_gateway != NULL )
					del_default_route();
	

			} else if ( todo_node->todo_type == REQ_CHANGE_HNA ) {
				
				addr_to_string( todo_node->key.addr, addr_str, sizeof(addr_str) );
				
				debug_output( 3, "found todo item, %s HNA %s/%d atype %d \n", todo_node->add ? "adding":"removing", addr_str, todo_node->key.KEY_FIELD_ANETMASK, todo_node->key.KEY_FIELD_ATYPE );
				
				sprintf( fake_arg, "%s/%d", addr_str, todo_node->key.KEY_FIELD_ANETMASK);
				
				prepare_add_del_own_hna( fake_arg, (todo_node->add ? NO : YES), todo_node->key.KEY_FIELD_ATYPE );
				
				add_del_own_hna( NO /* do not purge */ );
				
				
			} else if ( todo_node->todo_type == REQ_CHANGE_SRV ) {
				
				addr_to_string( todo_node->def32, addr_str, sizeof(addr_str) );
				
				debug_output( 3, "found todo item, %s SRV IP %s, port %d, seqno %d \n", todo_node->add ? "adding":"removing", addr_str, todo_node->def16, todo_node->def8 );
				
				sprintf( fake_arg, "%s:%d:%d", addr_str, todo_node->def16, todo_node->def8 );
				
				prepare_add_del_own_srv( fake_arg, (todo_node->add ? NO : YES) );
				
				add_del_own_srv( NO /* do not purge */ );
				
				
			} else if ( todo_node->todo_type == REQ_FAKE_TIME ) {
				
				debug_output( 3, "found todo item fake time by %ld sec \n", todo_node->def32 );
				
				fake_start_time ( todo_node->def32 );
				
			} else {
				
				debug_output( 0, "Error, unkown todo_type %d\n", todo_node->todo_type );
				
			}
			
			list_del( (struct list_head *)&todo_list, todo_pos, &todo_list );
			debugFree( todo_pos, 1220 );

		}
	
		//debug_output( 3, "Unix socket: todo_mutex trylocked, - processing todo list... \n" );

		if ( pthread_mutex_unlock( (pthread_mutex_t *)todo_mutex ) != 0 )
			debug_output( 0, "Error - could not unlock un-trylock_mutex : %s \n", strerror( errno ) );
	
	}
	
}

int calc_ogm_if_size( int if_num ) {
	if ( if_num == 0 )
		return ( sizeof(struct bat_packet) + ((my_gw_ext_array_len + my_hna_ext_array_len + my_srv_ext_array_len) * sizeof(struct ext_packet)) );
	else
		return ( sizeof(struct bat_packet) + sizeof(struct ext_packet) );
}












int8_t batman() {

	struct list_head *list_pos, *forw_pos_tmp, *notun_pos_tmp;
	struct orig_node *orig_neigh_node, *orig_node; 
	struct batman_if *batman_if;
	struct forw_node *forw_node;
	struct notun_node *notun_node;
	uint32_t debug_timeout, statistic_timeout, todo_timeout, vis_timeout, select_timeout, aggregation_time = 0;
	uint8_t drop_it;

	uint16_t aggr_interval;
	
	static char orig_str[ADDR_STR_LEN], neigh_str[ADDR_STR_LEN], ifaddr_str[ADDR_STR_LEN];
	uint8_t is_my_addr, is_my_orig, is_broadcast, is_my_path, is_duplicate, is_bidirectional, is_accepted, is_direct_neigh, is_bntog, forward_duplicate_packet, has_unidirectional_flag, has_directlink_flag, has_duplicated_flag;
	int tq_rate_value, rand_nb_value, acceptance_nb_value;
	int res;
	
				
	uint32_t s_last_cpu_time = 0, s_curr_cpu_time = 0;
	
	
	struct bat_packet *ogm;
	struct ext_packet *hna_array, *gw_array, *srv_array, *vis_array, *pip_array;
	int16_t /*hna_count,*/ hna_array_len, /*gw_count,*/ gw_array_len, srv_array_len, vis_array_len, pip_array_len;
	
	uint32_t neigh, curr_time;
	struct batman_if *if_incoming;

	received_ogm = &ogm;
	received_neigh = &neigh;
	received_if_incoming = &if_incoming;
	received_batman_time = &curr_time;

	received_gw_array  = &gw_array;
	received_gw_pos    = &gw_array_len;
	received_hna_array = &hna_array;
	received_hna_pos   = &hna_array_len;
	received_srv_array = &srv_array;
	received_srv_pos   = &srv_array_len;
	received_vis_array = &vis_array;
	received_vis_pos   = &vis_array_len;
	received_pip_array = &pip_array;
	received_pip_pos   = &pip_array_len;

	curr_time = debug_timeout = todo_timeout = statistic_timeout = vis_timeout = get_time_msec();
		
	if ( aggregations_po )
		aggregation_time = curr_time + 50 + rand_num( 100 );

	if ( NULL == ( orig_hash = hash_new( 128, compare_key, choose_key, 4 ) ) )
		return(-1);
	
	if ( NULL == ( hna_hash = hash_new( 128, compare_key, choose_key, 5 ) ) )
		return(-1);
	
	
	add_del_own_srv( NO /*do not purge*/ );	
	
	add_del_own_hna( NO /*do not purge*/ );	
	
	
	
	
	list_for_each( list_pos, &if_list ) {
		
		batman_if = list_entry( list_pos, struct batman_if, list );
		schedule_own_packet( batman_if, curr_time );

	}
	
	while ( !is_aborted() ) {
		
		prof_start( PROF_all );
		
		debug_output( 4, " \n \n" );

		
		if ( aggregations_po == NO  &&  LESS_U32( curr_time, ((struct forw_node *)forw_list.next)->send_time ) ) {
			
			select_timeout = ((struct forw_node *)forw_list.next)->send_time - curr_time ;
			
			if ( select_timeout > MAX_SELECT_TIMEOUT_MS )
				select_timeout = MAX_SELECT_TIMEOUT_MS;
			
			res = receive_packet( select_timeout );
			
		} else if ( aggregations_po  &&  LESS_U32( curr_time,  aggregation_time ) ) {
		
			select_timeout = aggregation_time - curr_time ;
			
			if ( select_timeout > MAX_SELECT_TIMEOUT_MS )
				select_timeout = MAX_SELECT_TIMEOUT_MS;
			
			res = receive_packet( select_timeout );
			
		} else {
			
			res = 0;
			debug_output( 4, "skipping select \n" );
		
		}
		
		
		if ( res > 0 ) {

			addr_to_string( ogm->orig, orig_str, sizeof(orig_str) );
			addr_to_string( neigh, neigh_str, sizeof(neigh_str) );
			addr_to_string( if_incoming->addr.sin_addr.s_addr, ifaddr_str, sizeof(ifaddr_str) );

			is_my_addr = is_my_orig = is_broadcast = is_my_path = is_duplicate = is_bidirectional = is_accepted = is_direct_neigh = is_bntog = forward_duplicate_packet = 0;

			has_unidirectional_flag = ogm->flags & UNIDIRECTIONAL_FLAG ? 1 : 0;
			has_directlink_flag     = ogm->flags & DIRECTLINK_FLAG ? 1 : 0;
			has_duplicated_flag     = ogm->flags & CLONED_FLAG ? 1 : 0;

			is_direct_neigh = (ogm->orig == neigh) ? 1 : 0;

			
			debug_output( 4, "Received BATMAN packet via NB: %s , IF: %s %s (from OG: %s, seqno %d, TTL %d, V %d, UDF %d, IDF %d, DPF %d, direct_neigh %d) \n", neigh_str, if_incoming->dev, ifaddr_str, orig_str, ogm->seqno, ogm->ttl, COMPAT_VERSION, has_unidirectional_flag, has_directlink_flag, has_duplicated_flag, is_direct_neigh );

			list_for_each( list_pos, &if_list ) {

				batman_if = list_entry( list_pos, struct batman_if, list );

				if ( neigh == batman_if->addr.sin_addr.s_addr )
					is_my_addr = 1;

				if ( ogm->orig == batman_if->addr.sin_addr.s_addr )
					is_my_orig = 1;

				if ( neigh == batman_if->broad.sin_addr.s_addr )
					is_broadcast = 1;

			}

			if ( gw_array_len > 0 && gw_array != NULL && gw_array->EXT_GW_FIELD_GWFLAGS != 0 && gw_array->EXT_GW_FIELD_GWTYPES != 0 )
				debug_output( 4, "Is an internet gateway (class %i, types %i) \n", gw_array->EXT_GW_FIELD_GWFLAGS, gw_array->EXT_GW_FIELD_GWTYPES );
			

			if ( is_my_addr ) {

				debug_output( 4, "Drop packet: received my own broadcast (sender: %s) \n", neigh_str );

			} else if ( is_broadcast ) {

				debug_output( 4, "Drop packet: ignoring all packets with broadcast source IP (sender: %s) \n", neigh_str );

			} else if ( is_my_orig ) {
				
				orig_neigh_node = get_orig_node( neigh );

				debug_output( 4, "received my own OGM via NB, lastTxIfSeqno: %d, currRxSeqno: %d, prevRxSeqno: %d, currRxSeqno-prevRxSeqno %d, link_node %s \n", ( if_incoming->out.seqno - OUT_SEQNO_OFFSET ), ogm->seqno, 0, 0, (orig_neigh_node->link_node ? "exist":"NOT exists") /*, orig_neigh_node->bidirect_link[if_incoming->if_num], ogm->seqno - orig_neigh_node->bidirect_link[if_incoming->if_num] */ );

				if ( ( has_directlink_flag ) &&
				   ( if_incoming->addr.sin_addr.s_addr == ogm->orig ) &&
				   ( ogm->seqno != ( if_incoming->out.seqno - OUT_SEQNO_OFFSET ) )
				   ) {
				
					debug_output( 3, "WARNING: received own OGM via NB: %s, lastTxIfSeqno: %d, currRxSeqno: %d \n", neigh_str, ( if_incoming->out.seqno - OUT_SEQNO_OFFSET ), ogm->seqno  );

				}							   
				
				/* neighbour has to indicate direct link and it has to come via the corresponding interface */
				/* if received seqno equals last send seqno save new seqno for bidirectional check */
				if ( ( has_directlink_flag ) &&
					( if_incoming->addr.sin_addr.s_addr == ogm->orig ) &&
					( !has_duplicated_flag ) &&
					( ogm->seqno == ( if_incoming->out.seqno - OUT_SEQNO_OFFSET ) ) &&
					( orig_neigh_node->link_node != NULL ) &&
					( orig_neigh_node->primary_orig_node != NULL )  ){

					//update_bi_link_bits( orig_neigh_node, if_incoming, YES, NO );
					
							
					if (  !((orig_neigh_node->link_node->bi_link_bits[ if_incoming->if_num * MAX_NUM_WORDS ]) & 0x01) ) {
						
						bit_mark( &(orig_neigh_node->link_node->bi_link_bits[ if_incoming->if_num * MAX_NUM_WORDS ]), 0 );
						(orig_neigh_node->link_node->rcvd_bi_link_packets[if_incoming->if_num])++;
						
					} else {
						
						debug_output( 0, "Error - first bit of bitarray was NOT zero !! \n");
						
					}
					
					
					orig_neigh_node->link_node->bidirect_link[if_incoming->if_num] = ( if_incoming->out.seqno - OUT_SEQNO_OFFSET );
					
					if ( orig_neigh_node->primary_orig_node->id4me != ogm->prev_hop_id ) {
					
						if( orig_neigh_node->primary_orig_node->id4me != 0 ) 
							debug_output( 0, "WARNING: received changed prev_hop_id from neighbor %s !!!!!!!\n", neigh_str );
						
						orig_neigh_node->primary_orig_node->id4me = ogm->prev_hop_id;
					}

					debug_output( 4, "indicating bidirectional link - updating bidirect_link seqno \n");

				} else {

					debug_output( 4, "NOT indicating bidirectional link - NOT updating bidirect_link seqno \n");

				}

				debug_output( 4, "Drop packet: originator packet from myself (via neighbour) \n" );
				

			} else if ( ogm->flags & UNIDIRECTIONAL_FLAG ) {

				debug_output( 4, "Drop packet: originator packet with unidirectional flag \n" );

			} else {

				
				orig_node = get_orig_node( ogm->orig );

				/* if sender is a direct neighbor the sender ip equals originator ip */
				orig_neigh_node = ( is_direct_neigh ? orig_node : get_orig_node( neigh ) );

				drop_it = NO;
					
				/* drop packet if sender is not a direct neighbor and if we have no route towards the rebroadcasting neighbor */
				if ( !is_direct_neigh  &&  orig_neigh_node->router == NULL  ) {

					debug_output( 4, "Drop packet: OGM via unkown neighbor! \n" );
					drop_it = YES;

				} else if ( !is_direct_neigh  &&  ( orig_neigh_node->primary_orig_node == NULL ||
								orig_neigh_node->primary_orig_node->id4me == 0 ||
								orig_neigh_node->primary_orig_node->id4me == ogm->prev_hop_id ) ) {

					debug_output( 4, "Drop packet: OGM %s via NB %s %s !!!! \n",
							orig_str, neigh_str, 
							( ( orig_neigh_node->primary_orig_node == NULL || orig_neigh_node->primary_orig_node->id4me == 0 ) ? 
									"with unknown primaryOG" :" via two-hop loop " )
						    );
					drop_it = YES;

					
				} else if ( ogm->ttl == 0 ) {

					debug_output( 4, "Drop packet: TTL of zero! \n" );
					drop_it = YES;

				} else if ( ((uint16_t)( ogm->seqno - orig_node->last_rcvd_seqno )) > ((uint16_t)( FULL_SEQ_RANGE - orig_node->ws )) ) {

					debug_output( 3, "WARNING: Drop packet: OGM from %s, via NB %s, with old seqno! rcvd sqno %i  new ws %d  (old ws %d)  ttl %d  last rcvd seqno %i  (last valid seqno %i)  largest_ttl %d  time %d ! Maybe OGM-aggregation is to radical!?\n", orig_str, neigh_str, ogm->seqno, ogm->ws, orig_node->ws, ogm->ttl, orig_node->last_rcvd_seqno, orig_node->last_valid_seqno, orig_node->last_valid_largest_ttl, orig_node->last_valid );
					drop_it = YES;

				} else if ( /* this originator IP is known and*/ 
					    orig_node->last_valid != 0 && 
					    /* seqno is (more than four times: 4/100=25) out of range and*/
					    ((uint16_t)( ogm->seqno - orig_node->last_valid_seqno )) > ((uint16_t)((dad_timeout*orig_node->ws )/25)) && 
					    /* but we have received an ogm in less than  (ws * DEFAULT_ORIGINATOR_INTERVAL) ms */
					    curr_time < (orig_node->last_valid + (( DEFAULT_ORIGINATOR_INTERVAL * dad_timeout * (orig_node->ws) )/100))  ) 
					{

						debug_output( 0, "Drop packet: DAD alert! OGM from %s via NB %s with out of range seqno! rcvd sqno %i, last valid seqno: %i at %d!\n              Maybe two nodes are using this IP!? Waiting %d more seconds before reinitialization...\n", orig_str, neigh_str, ogm->seqno, orig_node->last_valid_seqno, orig_node->last_valid, ((orig_node->last_valid + ((DEFAULT_ORIGINATOR_INTERVAL * dad_timeout * (orig_node->ws))/100)) - curr_time)/1000 );
					
					drop_it = YES;

				} else if ( alreadyConsidered( orig_node, ogm->seqno, neigh, if_incoming ) ) {

					debug_output( 4, "Drop packet: Already considered this OGM and SEQNO via this link neighbor ! \n" );
					drop_it = YES;

				} else if ( has_duplicated_flag && orig_neigh_node->primary_orig_node == NULL ) {

					debug_output( 4, "Drop packet: First contact with neighbor MUST be without duplicated flag ! \n" );
					drop_it = YES;

				}

				if ( ! drop_it ) {
					
					if ( DEBUG_RCVD_ALL_BITS )
						set_dbg_rcvd_all_bits( orig_node, ogm->seqno, if_incoming );
					
					orig_node->last_rcvd_seqno = ogm->seqno;
					
					is_duplicate = ( orig_node->last_valid_seqno == ogm->seqno ); /* isDuplicate( orig_node, ogm->seqno );*/

					is_bidirectional = ( orig_neigh_node->link_node != NULL && 
							( ((uint16_t)( (if_incoming->out.seqno - OUT_SEQNO_OFFSET) -
							  orig_neigh_node->link_node->bidirect_link[if_incoming->if_num] )) < bidirect_link_to ) );
					
					update_primary_orig( orig_node );
					
					update_link( orig_node, ogm->seqno, if_incoming, ( !has_duplicated_flag && is_direct_neigh ) );
					
					tq_rate_value = tq_rate( orig_neigh_node, if_incoming, bidirect_link_to );
					
					rand_nb_value = rand_num( bidirect_link_to -1 ); //cheating to absorb late own OGM replies
										
					/* value between 0 and range. Return value of range indicates 100% acceptance*/
					acceptance_nb_value = tq_power( tq_rate_value, bidirect_link_to ) ;
					
					
					uint16_t rand_num_hundret = rand_num( 100 );
					
					
					/* do we accept or ignore the OGM according to our current policy ? */
					is_accepted = ( is_bidirectional &&
							( rand_nb_value < acceptance_nb_value +
								( ( ((MAX_ASYMMETRIC_WEIGHT - asymmetric_weight) * bidirect_link_to ) / 100 )  ) )  &&
							( !is_duplicate || /* FIXME: Do we really need this, we dont acceppt old seqno... */
							  ( dup_ttl_limit > 0  && 
							    orig_node->last_valid_seqno == ogm->seqno  &&
							    orig_node->last_valid_largest_ttl < ogm->ttl + dup_ttl_limit  &&
							    rand_num_hundret < dup_rate  && /* using the same rand_num_hundret is important */
							rand_num_hundret < (100 - (dup_degrad * (orig_node->last_valid_largest_ttl - ogm->ttl) ))
							  ) 
							) 
						      );
					
					if ( is_accepted ) {
						
						s_accepted_ogms++;
						
						update_orig( orig_node, orig_neigh_node );
					
					}
					
					/* MUST be after update_orig to represent the lates statistics */
					is_bntog = ( ( orig_node->router != NULL ) && ( orig_node->router->addr == neigh ) );
					
					//if ( is_accepted  &&  ogm->ttl != 50  /*&&  tq_rate_value < 50*/ )
					debug_output( 4, "  accepted OGM: %s  bidirectLink: %s  duplicate: %s  BNTOG: %s  mobile: %s  rand_nb: %d  acceptance_nb: %d (tq: %d), asymmetric_w: %d  lSqno: %d  cSeqno: %d  lTtl: %d  cTtl: %d  ttl_limit: %d  rand100: %d   dup_rate: %d  dup_degrad: %d  !\n", 
							( is_accepted ? "Y" : "N" ), 
							( is_bidirectional ? "Y" : "N" ), 
							( is_duplicate ? "Y" : "N" ), 
							( is_bntog ? "Y" : "N" ), 
							( mobile_device ? "Y" : "N" ), 
									rand_nb_value, acceptance_nb_value,  tq_rate_value, asymmetric_weight, orig_node->last_valid_seqno, ogm->seqno ,orig_node->last_valid_largest_ttl, ogm->ttl, dup_ttl_limit, rand_num_hundret, dup_rate, dup_degrad );
					
					
					uint8_t not_forwarded = YES;
					
					if ( ! mobile_device ) {
					
						/* is single hop (direct) neighbour */
						if ( is_direct_neigh ) {
	
							/* it is our best route towards him */
							if ( is_accepted && is_bntog ) {
	
								/* mark direct link on incoming interface */
								schedule_forward_packet( 0, 1, has_duplicated_flag, orig_neigh_node->primary_orig_node->id4him );
								not_forwarded = NO;
								debug_output( 4, "Schedule packet: rebroadcast neighbour packet with direct link flag \n" );
								
							/* if an unidirectional direct neighbour sends us a packet or
							* if a bidirectional neighbour sends us a packet who is not our best link to him: 
							*	- retransmit it with unidirectional flag to tell him that we get his packets */
							} else if ( !has_duplicated_flag /* && (( is_accepted && !is_bntog ) || ( !is_accepted ) )*/ ) {
	
								schedule_forward_packet( 1, 1, 0 /*has_duplicated_flag*/, orig_neigh_node->primary_orig_node->id4him );
								not_forwarded = NO;
	
								debug_output( 4, "Schedule packet: rebroadcast neighbour packet with direct link and unidirectional flag \n" );
	
							} else {
								
								debug_output( 4, "Drop packet: no reason to re-broadcast! \n" );
								
							}
	
						/* multihop originator */
						} else if ( is_accepted && is_bntog ) {
	
							schedule_forward_packet( 0, 0, has_duplicated_flag, orig_neigh_node->primary_orig_node->id4him );
							not_forwarded = NO;
	
							debug_output( 4, "Schedule packet: rebroadcast originator packet \n" );
	
						} else {
	
							debug_output( 4, "Drop multihop originator packet, not accepted or not via best link ! \n");
	
						}
						
					} else {
						/* we are an asocial mobile device and dont want to forward other nodes packet */
						if( is_direct_neigh && !has_duplicated_flag ) {
	
							schedule_forward_packet( 1, 1, has_duplicated_flag, orig_neigh_node->primary_orig_node->id4him );
							not_forwarded = NO;
	
							debug_output( 4, "Schedule packet: with mobile device policy: rebroadcast neighbour packet with direct link and unidirectional flag \n" );
							
						} else {
							debug_output( 4, "Drop packet, mobile devices rebroadcast almost nothing :-( \n" );
							
						}
						
					}
					
				}
				
			}
			

		} else if ( res < 0 ) {
			
			return -1;
			
		}
		
		
		if ( aggregations_po  && ( LSEQ_U32( aggregation_time, curr_time ) ) ) {
				
			aggr_interval = (my_ogi/aggregations_po > MAX_AGGREGATION_INTERVAL_MS) ? MAX_AGGREGATION_INTERVAL_MS :  (my_ogi/aggregations_po);

			send_outstanding_packets();
			aggregation_time = (curr_time + aggr_interval + rand_num( aggr_interval/2 )) - (aggr_interval/4);
			
		} else if ( aggregations_po == NO ) {

			send_outstanding_packets();
			
		}
		
		if ( LESS_U32( todo_timeout + 200,  curr_time )  ) {
			
			check_todos();
			
/*TODO: remove this */	//check_interfaces();

			if ( LESS_U32( debug_timeout + 1000,  curr_time ) ) {
		
				purge_orig( curr_time );
				
				purge_empty_hna_nodes( );
				
		
				if (	( debug_clients.clients_num[DBGL_GATEWAYS-1] > 0 ) || 
					( debug_clients.clients_num[DBGL_ROUTES-1] > 0 ) || 
					( debug_clients.clients_num[DBGL_DETAILS-1] > 0 ) || 
					( debug_clients.clients_num[DBGL_HNAS-1] > 0 ) || 
					( debug_clients.clients_num[DBGL_SERVICES-1] > 0 ) || 
					( debug_clients.clients_num[DBGL_ALL-1] > 0 )  ) {
					
					debug_orig();
				
				}
				
				checkIntegrity();
		
				if ( debug_clients.clients_num[DBGL_PROFILE-1] > 0 )
					prof_print();
		
				if ( ( routing_class != 0 ) && ( curr_gateway == NULL ) )
					choose_gw();
		
				
				if ( LESS_U32( vis_timeout + 10000, curr_time  ) && ( vis_if.sock ) ) {
		
					vis_timeout = curr_time;
					
					send_vis_packet();
		
				}
				
				
				if ( LESS_U32( statistic_timeout + 5000, curr_time ) ) {
				
					/* generating cpu load statistics... */
					s_curr_cpu_time = (uint32_t)clock();
					
					curr_statistic_period_ms = ( curr_time - statistic_timeout ) ;
					
					if ( curr_statistic_period_ms > 0 ) {
						
						debug_output( DBGL_STATISTICS, "stats: load %2d  sched. %3d, Agg. rcvd %3d, brc %3d (cp %3d), OGMs rcvd %3d, accept %3d, brc %3d, rt %3d \n",
						( s_curr_avg_cpu_load = ( (s_curr_cpu_time - s_last_cpu_time) / curr_statistic_period_ms ) ),
						s_returned_select * 1000 / curr_statistic_period_ms,
	s_received_aggregations * 1000 / curr_statistic_period_ms,
	s_broadcasted_aggregations * 1000 / curr_statistic_period_ms,
	s_broadcasted_cp_aggregations * 1000 / curr_statistic_period_ms,
	s_received_ogms * 1000 / curr_statistic_period_ms,
	s_accepted_ogms * 1000 / curr_statistic_period_ms,
	s_broadcasted_ogms * 1000 / curr_statistic_period_ms,
	s_pog_route_changes * 1000 / curr_statistic_period_ms );
	
						
						if ( s_curr_avg_cpu_load < 255 )
							(list_entry( (&if_list)->next, struct batman_if, list ))->out.reserved_someting = s_curr_avg_cpu_load;
						else 
							(list_entry( (&if_list)->next, struct batman_if, list ))->out.reserved_someting = 255;
					
					
					}
					
					s_returned_select = s_received_aggregations = s_broadcasted_aggregations = s_broadcasted_cp_aggregations = s_received_ogms = s_accepted_ogms = s_broadcasted_ogms = s_pog_route_changes = 0; 
				
					
					s_last_cpu_time = s_curr_cpu_time;
				
					statistic_timeout = curr_time;
				}
				
				/* preparing the next debug_timeout */
				debug_timeout = curr_time;
				
			}
			
			todo_timeout = curr_time;
			
		}
		
	prof_stop( PROF_all );
	}


	if ( debug_level > 0 )
		printf( "Deleting all BATMAN routes\n" );

	purge_orig( 0 );
	
	add_del_own_srv( YES /*purge*/ );
	
	add_del_own_hna( YES /*purge*/ );
	
	purge_empty_hna_nodes( );

	hash_destroy( hna_hash );
	
	hash_destroy( orig_hash );

	
	list_for_each_safe( list_pos, forw_pos_tmp, &forw_list ) {

		forw_node = list_entry( list_pos, struct forw_node, list );

		list_del( (struct list_head *)&forw_list, list_pos, &forw_list );

		debugFree( forw_node->pack_buff, 1105 );
		debugFree( forw_node, 1106 );

	}

	list_for_each_safe( list_pos, notun_pos_tmp, &notun_list ) {

		notun_node = list_entry( list_pos, struct notun_node, list );

		list_del( (struct list_head *)&notun_list, list_pos, &notun_list );

		debugFree( notun_node, 1224 );

	}
	
	if ( vis_packet != NULL )
		debugFree( vis_packet, 1108 );


	return 0;

}
