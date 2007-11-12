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


#include "os.h"
#include "batman.h"
#include "originator.h"
#include "schedule.h"



uint8_t debug_level = 0;


#ifdef PROFILE_DATA

uint8_t debug_level_max = 5;

#elif DEBUG_MALLOC && MEMORY_USAGE

uint8_t debug_level_max = 5;

#else

uint8_t debug_level_max = 4;

#endif


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

int16_t originator_interval = DEFAULT_ORIGINATOR_INTERVAL;   /* orginator message interval in miliseconds */

//int8_t advanced_opts = DEF_ADVANCED_SWITCH;

int8_t resist_blocked_send = DEF_RESIST_BLOCKED_SEND;



/* bidirectional link timeout in number+1 of maximum acceptable missed (not received by this node)
of last send own OGMs rebroadcasted from neighbors */
int32_t bidirect_link_to = DEFAULT_BIDIRECT_TIMEOUT;

int32_t aggregations_po = DEF_AGGREGATIONS_PO;

int32_t sequence_range = DEFAULT_SEQ_RANGE;
int32_t ttl = DEFAULT_TTL;

uint8_t mobile_device = NO;
uint8_t no_unreachable_rule = NO;
uint8_t no_tun_persist = NO;
uint8_t no_forw_dupl_ttl_check = NO;
int32_t dup_ttl_limit = DEF_DUP_TTL_LIMIT;
int32_t dup_rate =  DEF_DUP_RATE;
int32_t dup_degrad = DEF_DUP_DEGRAD;

int32_t send_clones = DEF_SEND_CLONES;

int32_t asymmetric_weight = DEF_ASYMMETRIC_WEIGHT;

int32_t asymmetric_exp = DEF_ASYMMETRIC_EXP;

int32_t rebrc_delay = DEF_REBRC_DELAY;

int32_t default_para_set =  DEF_BMX_PARA_SET;


int32_t penalty_min = DEF_PENALTY_MIN;
int32_t penalty_exceed = DEF_PENALTY_EXCEED;


int16_t num_words = ( DEFAULT_SEQ_RANGE / WORD_BIT_SIZE ) + ( ( DEFAULT_SEQ_RANGE % WORD_BIT_SIZE > 0)? 1 : 0 );

int32_t base_port = DEF_BASE_PORT;

int32_t rt_table_offset   = DEF_RT_TABLE_OFFSET;

int32_t rt_prio_offset = DEF_RT_PRIO_OFFSET;

int32_t more_rules = DEF_MORE_RULES;

int32_t no_prio_rules = DEF_NO_PRIO_RULES;

int32_t no_throw_rules = DEF_NO_THROW_RULES;

int32_t no_unresponsive_check = DEF_NO_UNRESP_CHECK;

int32_t one_way_tunnel = DEF_ONE_WAY_TUNNEL;

int32_t two_way_tunnel = DEF_TWO_WAY_TUNNEL;

int32_t gw_change_hysteresis = DEF_GW_CHANGE_HYSTERESIS;

uint32_t gw_tunnel_prefix; //= DEF_GW_TUNNEL_PREFIX; //initialized in init.c: apply_init_args()

uint8_t  gw_tunnel_netmask = DEF_GW_TUNNEL_NETMASK;

int32_t tunnel_ip_lease_time = DEF_TUNNEL_IP_LEASE_TIME;

struct gw_listen_arg gw_listen_arg;

struct gw_node *curr_gateway = NULL;
pthread_t curr_gateway_thread_id = 0;

uint32_t pref_gateway = 0;

struct hna_packet *my_hna_array = NULL;
uint16_t my_hna_array_len = 0;

uint8_t found_ifs = 0;
int32_t receive_max_sock = 0;
fd_set receive_wait_set;

uint8_t unix_client = 0;

struct hashtable_t *orig_hash;

struct list_head_first forw_list;
struct list_head_first gw_list;
struct list_head_first if_list;
struct list_head_first hna_list;

uint16_t hna_list_size = 0;

struct vis_if vis_if;
struct unix_if unix_if;
struct debug_clients debug_clients;

unsigned char *vis_packet = NULL;
uint16_t vis_packet_size = 0;


void print_advanced_opts ( int verbose ) {
	
	fprintf( stderr, "\n\n Advanced and dangerous options (better do not touch):\n" );
	fprintf( stderr, "\n For more background informations see: http://open-mesh.net/batman/doc/BMX/\n" );
	
	fprintf( stderr, "\n       --%s : does not set the unreachable rule for host routes.\n", NO_UNREACHABLE_RULE_SWITCH );
	
	fprintf( stderr, "\n       --%s : does not set the default priority rules.\n", NO_PRIO_RULES_SWITCH );
	
	fprintf( stderr, "\n       --%s : does not set the default throw rules.\n", NO_THROW_RULES_SWITCH );
	
	fprintf( stderr, "\n       --%s : Set unreachable rule. Limits scope of batman routing table. \n", MORE_RULES_SWITCH);
	
	
	fprintf( stderr, "\n       --%s : Disable OGM aggregation \n", NO_AGGREGATIONS_SWITCH);
	
	fprintf( stderr, "\n       --%s : Send aggregated OGMs every 1/%sth of the originator inteval. \n", AGGREGATIONS_SWITCH, ENABLED_AGGREGATIONS_PO);

	fprintf( stderr, "\n       --%s <value>: Set number of aggregations per originator interval manually.\n", AGGREGATIONS_PO_SWITCH );
	if ( verbose )
		fprintf( stderr, "          default: %s, allowed values: %d <= value <= %d \n", ENABLED_AGGREGATIONS_PO, MIN_AGGREGATIONS_PO, MAX_AGGREGATIONS_PO  );

	
	fprintf( stderr, "\n       --%s : disables the unresponsive-GW check.\n", NO_UNRESP_CHECK_SWITCH );
	
	fprintf( stderr, "\n       --%s : lets daemon survive if firewall blocks outgoing OGMs.\n", RESIST_BLOCKED_SEND_SWITCH );
	
	fprintf( stderr, "\n       --%s <vlue>: Use hysteresis for fast-switch gw connections (-r 3).\n", GW_CHANGE_HYSTERESIS_SWITCH );
	fprintf( stderr, "          <value> for number additional rcvd OGMs before changing to more stable GW.\n");
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d \n", DEF_GW_CHANGE_HYSTERESIS, MIN_GW_CHANGE_HYSTERESIS, MAX_GW_CHANGE_HYSTERESIS  );
		
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
	
	fprintf( stderr, "\n       --%s <value> : set bidirectional timeout value\n", BIDIRECT_TIMEOUT_SWITCH );
	fprintf( stderr, "        /%c <value> : attached after an interface name\n", BIDIRECT_TIMEOUT_IF_SWITCH );
	fprintf( stderr, "          to set individual bidirectionl-timeout value this interface.\n");
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d \n", DEFAULT_BIDIRECT_TIMEOUT, MIN_BIDIRECT_TIMEOUT, MAX_BIDIRECT_TIMEOUT  );
	
	fprintf( stderr, "\n       --%s <value> : set neighbor ranking frame size\n", NBRFSIZE_SWITCH );
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d\n", DEFAULT_SEQ_RANGE, MIN_SEQ_RANGE, MAX_SEQ_RANGE  );
	
	fprintf( stderr, "\n       --%s <value> : set maximum of random re-broadcast delay \n", REBRC_DELAY_SWITCH );
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed values: %d <= value <= %d\n", DEF_REBRC_DELAY, MIN_REBRC_DELAY, MAX_REBRC_DELAY  );
	
	fprintf( stderr, "\n       --%s <value> : (re-)broadcast OGMs with given probability\n", SEND_CLONES_SWITCH );
	fprintf( stderr, "        /%c <value> : attached after an interface name\n", SEND_CLONES_IF_SWITCH );
	fprintf( stderr, "          to specify an individual re-broadcast probability for this interface.\n");
	if ( verbose )
		fprintf( stderr, "          default: %d, allowed probability values in percent: %d <= value <= %d\n", DEF_SEND_CLONES, MIN_SEND_CLONES, MAX_SEND_CLONES  );
	
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
		fprintf( stderr, "          default: %d (disabled), allowed values: %d <= value <= %d\n", DEF_DUP_TTL_LIMIT, MIN_DUP_TTL_LIMIT, MAX_DUP_TTL_LIMIT );
	
	fprintf( stderr, "\n       --%s <value> : accept non-quickest OGMs to relieve preference for shortest path. \n", DUP_RATE_SWITCH );
	fprintf( stderr, "          < value > defines the probability with which non-quickest OGMs are accepted. \n");
	if ( verbose )
		fprintf( stderr, "          default: %d (disabled), allowed values in percent: %d <= value <= %d\n", DEF_DUP_RATE, MIN_DUP_RATE, MAX_DUP_RATE );
	
	fprintf( stderr, "\n       --%s <value> : accept non-quickest OGMs to relieve preference for shortest path. \n", DUP_DEGRAD_SWITCH );
	fprintf( stderr, "          < value > defines the probability degradation for each additional hop (compared \n");
	fprintf( stderr, "          to the OGM arrived via the shortest path) with which non-quickest OGMs are accepted. \n");
	if ( verbose )
		fprintf( stderr, "          default: %d (disabled), allowed values in percent: %d <= value <= %d\n", DEF_DUP_DEGRAD, MIN_DUP_DEGRAD, MAX_DUP_DEGRAD );
	
	fprintf( stderr, "\n       --%s : mobile device mode reluctant to help others.\n", ASOCIAL_SWITCH );
	
/*
	fprintf( stderr, "\n       --%s <value> : do neighbor ranking based on latest received OGMs.\n", PENALTY_MIN_SWITCH );
	fprintf( stderr, "          choosing the ranking winner with the most recent <value> OGMs in the NBRF \n");
	if ( verbose )
		fprintf( stderr, "          default: off, allowed values:  %d <= value <= %d\n", MIN_PENALTY_MIN, MAX_PENALTY_MIN  );

	fprintf( stderr, "\n       --%s <value> : do neighbor ranking based on latest received OGMs.\n", PENALTY_EXCEED_SWITCH );
	fprintf( stderr, "          choosing a new ranking winner when it came up with <value> more recent OGMs \n");
	fprintf( stderr, "          than the previous ranking winner \n");
	if ( verbose )
		fprintf( stderr, "          default: off, allowed values:  %d <= value <= %d\n", MIN_PENALTY_EXCEED, MAX_PENALTY_EXCEED  );
*/
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
	fprintf( stderr, "       -o originator interval in ms\n" );
	fprintf( stderr, "       -p preferred gateway\n" );
	fprintf( stderr, "       -r routing class\n" );
	fprintf( stderr, "       -s visualization server\n" );
	fprintf( stderr, "       -v print version\n\n" );
	
	fprintf( stderr, "       --%s : parametrize the routing algorithm to the best of BMX knowledge! DEFAULT !\n", BMX_DEFAULTS_SWITCH );
	fprintf( stderr, "       --%s : parametrize the routing algorithm according to the WCW Graz 2007 experiments!\n", GRAZ07_DEFAULTS_SWITCH );
	fprintf( stderr, "       --%s : parametrize the routing algorithm according to B.A.T.M.A.N generation III (as implemented in batmand-0.2)!\n\n", GENIII_DEFAULTS_SWITCH );
	
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
	fprintf( stderr, "          allowed values:  1 -> list neighbours\n" );
	fprintf( stderr, "                           2 -> list gateways\n" );
	fprintf( stderr, "                           3 -> observe batman\n" );
	fprintf( stderr, "                           4 -> observe batman (very verbose)\n\n" );

	if ( debug_level_max == 5  )
		fprintf( stderr, "                           5 -> memory debug / cpu usage\n\n" );

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
	fprintf( stderr, "       --%s : parametrize the routing algorithm according to the WCW Graz 2007 experiments!\n", GRAZ07_DEFAULTS_SWITCH );
	fprintf( stderr, "       --%s : parametrize the routing algorithm according to B.A.T.M.A.N generation III (as implemented in batmand-0.2)!\n\n", GENIII_DEFAULTS_SWITCH );
	
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



void add_del_hna( struct orig_node *orig_node, int8_t del ) {

	uint16_t hna_count = 0;
	uint32_t hna;
 	uint8_t  netmask;
	uint8_t  type;
	uint8_t  rt_table;

	
	while ( hna_count < orig_node->hna_array_len ) {

		hna =     orig_node->hna_array[hna_count].addr;
		netmask = orig_node->hna_array[hna_count].ANETMASK;
		type    = orig_node->hna_array[hna_count].ATYPE;
		
		//TODO: check if del==0 and HNA is not blocked by other OG  or   if del==1 and HNA has been accepted during assignement
		
		rt_table = ( type == A_TYPE_INTERFACE ? BATMAN_RT_TABLE_INTERFACES : (type == A_TYPE_NETWORK ? BATMAN_RT_TABLE_NETWORKS : 0 ) );
		
		if ( ( netmask > 0 ) && ( netmask <= 32 ) && rt_table ) {
			
			add_del_route( hna, netmask, orig_node->router->addr, orig_node->router->if_incoming->addr.sin_addr.s_addr, orig_node->batman_if->if_index, orig_node->batman_if->dev, rt_table, 0, del );
			
		}

		hna_count++;

	}

	if ( del ) {

		debugFree( orig_node->hna_array, 1101 );
		orig_node->hna_array_len = 0;

	}

}



void choose_gw() {

	prof_start( PROF_choose_gw );
	struct list_head *pos;
	struct gw_node *gw_node, *tmp_curr_gw = NULL;
	/* TBD: check the calculations of this variables for overflows */
	uint8_t max_gw_class = 0, max_packets = 0;  
	uint32_t current_time, max_gw_factor = 0, tmp_gw_factor = 0;  
	int download_speed, upload_speed; 
	static char orig_str[ADDR_STR_LEN];


	if ( ( routing_class == 0 ) || ( ( current_time = get_time() ) < originator_interval * sequence_range / CHOOSE_GW_DELAY_DIVISOR ) ) {

		prof_stop( PROF_choose_gw );
		return;

	}

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
		if ( ( gw_node->unavail_factor * gw_node->unavail_factor * MAX_GW_UNAVAIL_TIMEOUT ) + gw_node->last_failure > current_time )
			continue;

		if ( gw_node->orig_node->router == NULL )
			continue;

		if ( gw_node->deleted )
			continue;
		
		if ( !( gw_node->orig_node->gwtypes & ( (two_way_tunnel?TWO_WAY_TUNNEL_FLAG:0) | (one_way_tunnel?ONE_WAY_TUNNEL_FLAG:0) ) ) )
			continue;
			
		switch ( routing_class ) {

			case 1:   /* fast connection */
				get_gw_speeds( gw_node->orig_node->gwflags, &download_speed, &upload_speed );

				tmp_gw_factor = ( ( ( gw_node->orig_node->router->packet_count * 100 ) / sequence_range ) *
						( ( gw_node->orig_node->router->packet_count * 100 ) / sequence_range ) *
						( download_speed / 64 ) );
				
				if ( ( tmp_gw_factor > max_gw_factor ) || 
				     ( ( tmp_gw_factor == max_gw_factor ) && ( gw_node->orig_node->router->packet_count > max_packets ) ) )
					tmp_curr_gw = gw_node;
				
				break;

			case 2:   /* stable connection (use best statistic) */
				if ( gw_node->orig_node->router->packet_count > max_packets )
					tmp_curr_gw = gw_node;
				break;

			default:  /* fast-switch (use best statistic but change as soon as a better gateway appears) */
				if ( gw_node->orig_node->router->packet_count > max_packets )
					tmp_curr_gw = gw_node;
				break;

		}

		if ( gw_node->orig_node->gwflags > max_gw_class )
			max_gw_class = gw_node->orig_node->gwflags;

		if ( gw_node->orig_node->router->packet_count > max_packets )
			max_packets = gw_node->orig_node->router->packet_count;

		if ( tmp_gw_factor > max_gw_factor )
			max_gw_factor = tmp_gw_factor;
		
		if ( ( pref_gateway != 0 ) && ( pref_gateway == gw_node->orig_node->orig ) ) {

			tmp_curr_gw = gw_node;

			addr_to_string( tmp_curr_gw->orig_node->orig, orig_str, ADDR_STR_LEN );
			debug_output( 3, "Preferred gateway found: %s (gw_flags: %i, packet_count: %i, gw_product: %i)\n", orig_str, gw_node->orig_node->gwflags, gw_node->orig_node->router->packet_count, tmp_gw_factor );
			
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

		curr_gateway = tmp_curr_gw;

		/* may be the last gateway is now gone */
		if ( ( curr_gateway != NULL ) && ( !is_aborted() ) ) {

			addr_to_string( curr_gateway->orig_node->orig, orig_str, ADDR_STR_LEN );
			debug_output( 3, "Adding default route to %s (gw_flags: %i, packet_count: %i, gw_product: %i)\n", orig_str, max_gw_class, max_packets, max_gw_factor );
			add_default_route();

		}

	}

	prof_stop( PROF_choose_gw );

}



void update_routes( struct orig_node *orig_node, struct neigh_node *neigh_node, struct hna_packet *hna_array, int16_t hna_array_len ) {

	prof_start( PROF_update_routes );
	static char orig_str[ADDR_STR_LEN], next_str[ADDR_STR_LEN];


	debug_output( 4, "update_routes() \n" );


	if ( ( orig_node != NULL ) && ( orig_node->router != neigh_node ) ) {

		if ( ( orig_node != NULL ) && ( neigh_node != NULL ) ) {
			addr_to_string( orig_node->orig, orig_str, ADDR_STR_LEN );
			addr_to_string( neigh_node->addr, next_str, ADDR_STR_LEN );
			debug_output( 4, "Route to %s via %s\n", orig_str, next_str );
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
				add_del_hna( orig_node, 1 );

			add_del_route( orig_node->orig, 32, orig_node->router->addr, 0, orig_node->batman_if->if_index, orig_node->batman_if->dev, BATMAN_RT_TABLE_HOSTS, 0, 1 );

		}

		/* route altered or new route added */
		if ( ( ( orig_node->router != NULL ) && ( neigh_node != NULL ) ) || ( orig_node->router == NULL ) ) {

			if ( orig_node->router == NULL ) {
				debug_output( 4, "Adding new route\n" );
			} else {
				debug_output( 4, "Route changed\n" );
			}

			add_del_route( orig_node->orig, 32, neigh_node->addr, neigh_node->if_incoming->addr.sin_addr.s_addr, neigh_node->if_incoming->if_index, neigh_node->if_incoming->dev, BATMAN_RT_TABLE_HOSTS, 0, 0 );

			orig_node->batman_if = neigh_node->if_incoming;
			orig_node->router = neigh_node;

			/* add new announced network(s) */
			if ( ( hna_array_len > 0 ) && ( hna_array != NULL ) ) {

				orig_node->hna_array = debugMalloc( hna_array_len * sizeof(struct hna_packet), 101 );
				orig_node->hna_array_len = hna_array_len;

				memmove( orig_node->hna_array, hna_array, hna_array_len * sizeof(struct hna_packet) );

				add_del_hna( orig_node, 0 );

			}

		}

		orig_node->router = neigh_node;

	} else if ( orig_node != NULL ) {

		/* may be just HNA changed */
		if ( ( hna_array_len != orig_node->hna_array_len ) || ( ( hna_array_len > 0 ) && ( orig_node->hna_array_len > 0 ) && ( memcmp( orig_node->hna_array, hna_array, hna_array_len * sizeof(struct hna_packet) ) != 0 ) ) ) {

			if ( orig_node->hna_array_len > 0 )
				add_del_hna( orig_node, 1 );

			if ( ( hna_array_len > 0 ) && ( hna_array != NULL ) ) {

				orig_node->hna_array = debugMalloc( hna_array_len * sizeof(struct hna_packet), 102 );
				orig_node->hna_array_len = hna_array_len;

				memcpy( orig_node->hna_array, hna_array, hna_array_len * sizeof(struct hna_packet) );

				add_del_hna( orig_node, 0 );

			}

		}

	}

	prof_stop( PROF_update_routes );

}



void update_gw_list( struct orig_node *orig_node, uint8_t new_gwflags, uint8_t new_gwtypes ) {

	prof_start( PROF_update_gw_list );
	struct list_head *gw_pos, *gw_pos_tmp;
	struct gw_node *gw_node;
	static char orig_str[ADDR_STR_LEN];
	int download_speed, upload_speed;

	list_for_each_safe( gw_pos, gw_pos_tmp, &gw_list ) {

		gw_node = list_entry(gw_pos, struct gw_node, list);

		if ( gw_node->orig_node == orig_node ) {

			addr_to_string( gw_node->orig_node->orig, orig_str, ADDR_STR_LEN );
			
			debug_output( 3, "Gateway class of originator %s changed from %i to %i, new supported tunnel types %s, %s\n", orig_str, gw_node->orig_node->gwflags, new_gwflags, ((new_gwtypes&TWO_WAY_TUNNEL_FLAG)?"TWT":"-"), ((new_gwtypes&ONE_WAY_TUNNEL_FLAG)?"OWT":"-") );

			if ( !new_gwflags || (!( new_gwtypes & ( (two_way_tunnel?TWO_WAY_TUNNEL_FLAG:0) | (one_way_tunnel?ONE_WAY_TUNNEL_FLAG:0) ) )) ) {

				gw_node->deleted = get_time();
				gw_node->orig_node->gwflags = new_gwflags;
				gw_node->orig_node->gwtypes = new_gwtypes;
				
				debug_output( 3, "Gateway %s removed from gateway list\n", orig_str );

				if( gw_node == curr_gateway )
					choose_gw();

			} else {

				gw_node->deleted = 0;
				gw_node->orig_node->gwflags = new_gwflags;
				gw_node->orig_node->gwtypes = new_gwtypes;

			}

			prof_stop( PROF_update_gw_list );
			return;

		}

	}

	addr_to_string( orig_node->orig, orig_str, ADDR_STR_LEN );
	get_gw_speeds( new_gwflags, &download_speed, &upload_speed );

	debug_output( 3, "Found new gateway %s -> class: %i - %i%s/%i%s, new supported tunnel types %s, %s\n", orig_str, new_gwflags, ( download_speed > 2048 ? download_speed / 1024 : download_speed ), ( download_speed > 2048 ? "MBit" : "KBit" ), ( upload_speed > 2048 ? upload_speed / 1024 : upload_speed ), ( upload_speed > 2048 ? "MBit" : "KBit" ), ((new_gwtypes&TWO_WAY_TUNNEL_FLAG)?"TWT":"-"), ((new_gwtypes&ONE_WAY_TUNNEL_FLAG)?"OWT":"-" ) );

	gw_node = debugMalloc( sizeof(struct gw_node), 103 );
	memset( gw_node, 0, sizeof(struct gw_node) );
	INIT_LIST_HEAD( &gw_node->list );

	gw_node->orig_node = orig_node;
	orig_node->gwflags = new_gwflags;
	orig_node->gwtypes = new_gwtypes;
	gw_node->unavail_factor = 0;
	gw_node->last_failure = get_time();
	

	list_add_tail( &gw_node->list, &gw_list );

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
			
			if ( seqno == neigh_node->last_considered_seqno || ( seqno - neigh_node->last_considered_seqno ) > ( FULL_SEQ_RANGE - sequence_range ) ) {
				
				return YES;
		
			} else {
		
				neigh_node->last_considered_seqno = seqno;
				return NO;
			}
			
		}

	}

	return NO;

}


int isDuplicate( struct orig_node *orig_node, uint16_t seqno ) {

	prof_start( PROF_is_duplicate );
	struct list_head *neigh_pos;
	struct neigh_node *neigh_node;

	list_for_each( neigh_pos, &orig_node->neigh_list ) {

		neigh_node = list_entry( neigh_pos, struct neigh_node, list );

		if ( /* ( neigh == 0 || (neigh == neigh_node->addr && if_incoming == neigh_node->if_incoming) ) && */
		     get_bit_status( neigh_node->seq_bits, orig_node->last_seqno, seqno ) ) {

			prof_stop( PROF_is_duplicate );
			return 1;

		}

	}

	prof_stop( PROF_is_duplicate );

	return 0;

}



int isBntog( uint32_t neigh, struct orig_node *orig_tog_node ) {

	if ( ( orig_tog_node->router != NULL ) && ( orig_tog_node->router->addr == neigh ) )
		return 1;

	return 0;

}



int isBidirectionalNeigh( struct orig_node *orig_neigh_node, struct batman_if *if_incoming ) {

	if ( ((uint16_t)( (if_incoming->out.seqno - OUT_SEQNO_OFFSET) - orig_neigh_node->bidirect_link[if_incoming->if_num] )) < bidirect_link_to )
		return 1;

	return 0;

}



void generate_vis_packet() {

	struct hash_it_t *hashit = NULL;
	struct orig_node *orig_node;
	struct vis_data *vis_data;
	struct list_head *list_pos;
	struct batman_if *batman_if;
	struct hna_node *hna_node;


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
	((struct vis_packet *)vis_packet)->seq_range = sequence_range;

	/* neighbor list */
	while ( NULL != ( hashit = hash_iterate( orig_hash, hashit ) ) ) {

		orig_node = hashit->bucket->data;

		/* we interested in 1 hop neighbours only */
		if ( ( orig_node->router != NULL ) && ( orig_node->orig == orig_node->router->addr ) && ( orig_node->router->packet_count > 0 ) ) {

			vis_packet_size += sizeof(struct vis_data);

			vis_packet = debugRealloc( vis_packet, vis_packet_size, 105 );

			vis_data = (struct vis_data *)(vis_packet + vis_packet_size - sizeof(struct vis_data));

			//TBD: Why memcpy this uint32_t assignement ???
			memcpy( &vis_data->ip, (unsigned char *)&orig_node->orig, 4 );

			vis_data->data = orig_node->router->packet_count;
			vis_data->type = DATA_TYPE_NEIGH;

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
	if ( !( list_empty( &hna_list ) ) ) {

		list_for_each( list_pos, &hna_list ) {

			hna_node = list_entry( list_pos, struct hna_node, list );

			vis_packet_size += sizeof(struct vis_data);

			vis_packet = debugRealloc( vis_packet, vis_packet_size, 107 );

			vis_data = (struct vis_data *)(vis_packet + vis_packet_size - sizeof(struct vis_data));

			//TBD: why not simply assign: vis_data->ip = hna_node->addr; ???
			memcpy( &vis_data->ip, (unsigned char *)&hna_node->addr, 4 );
			
			vis_data->data = hna_node->ANETMASK;
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
		send_udp_packet( vis_packet, vis_packet_size, &vis_if.addr, vis_if.sock );

}



int8_t batman() {

	struct list_head *list_pos, *hna_pos_tmp, *forw_pos_tmp;
	struct orig_node *orig_neigh_node, *orig_node; 
	struct batman_if *batman_if, *if_incoming;
	struct neigh_node *neigh_node;
	struct hna_node *hna_node;
	struct forw_node *forw_node;
	uint32_t neigh, hna, debug_timeout, vis_timeout, select_timeout, aggregation_time = 0, curr_time;
	uint8_t netmask, atype;
	struct bat_packet *ogm;
	struct hna_packet *hna_array;
	uint16_t aggr_interval;

	static char orig_str[ADDR_STR_LEN], neigh_str[ADDR_STR_LEN], ifaddr_str[ADDR_STR_LEN];
	int16_t hna_count, hna_array_len;
	uint8_t forward_old, if_rp_filter_all_old, if_rp_filter_default_old, if_send_redirects_all_old, if_send_redirects_default_old;
	uint8_t is_my_addr, is_my_orig, is_broadcast, is_duplicate, is_bidirectional, is_accepted, is_direct_neigh, is_bntog, forward_duplicate_packet, has_unidirectional_flag, has_directlink_flag, has_duplicated_flag, has_version;
	int nlq_rate_value, rand_num_value, acceptance_rate_value;
	int res;
	
	curr_time = debug_timeout = vis_timeout = get_time();
		
	if ( aggregations_po )
		aggregation_time = get_time() + 50 + rand_num( 100 );

	if ( NULL == ( orig_hash = hash_new( 128, compare_orig, choose_orig ) ) )
		return(-1);
	
	
	/* for profiling the functions */
	prof_init( PROF_choose_gw, "choose_gw" );
	prof_init( PROF_update_routes, "update_routes" );
	prof_init( PROF_update_gw_list, "update_gw_list" );
	prof_init( PROF_is_duplicate, "isDuplicate" );
	prof_init( PROF_get_orig_node, "get_orig_node" );
	prof_init( PROF_update_originator, "update_orig" );
	prof_init( PROF_purge_originator, "purge_orig" );
	prof_init( PROF_schedule_forward_packet, "schedule_forward_packet" );
	prof_init( PROF_send_outstanding_packets, "send_outstanding_packets" );

		
	if ( !( list_empty( &hna_list ) ) ) {
		
		my_hna_array = debugMalloc( hna_list_size * sizeof(struct hna_packet), 15 );
		memset( my_hna_array, 0, hna_list_size * sizeof(struct hna_packet) );

		list_for_each( list_pos, &hna_list ) {
			
			//TODO: add own HNA to list of blocked HNAs !!

			hna_node = list_entry( list_pos, struct hna_node, list );

			my_hna_array[my_hna_array_len].addr     = hna_node->addr;
			my_hna_array[my_hna_array_len].ANETMASK = hna_node->ANETMASK;
			my_hna_array[my_hna_array_len].ATYPE    = hna_node->ATYPE;
			my_hna_array[my_hna_array_len].ext_flag = EXTENSION_FLAG;
			
			my_hna_array_len++;
			
			/* add throw routing entries for own hna */  
			add_del_route( hna_node->addr, hna_node->ANETMASK, 0, 0, 0, "unknown", BATMAN_RT_TABLE_INTERFACES, 1, 0 );
			add_del_route( hna_node->addr, hna_node->ANETMASK, 0, 0, 0, "unknown", BATMAN_RT_TABLE_NETWORKS,   1, 0 );
			add_del_route( hna_node->addr, hna_node->ANETMASK, 0, 0, 0, "unknown", BATMAN_RT_TABLE_HOSTS,      1, 0 );
			add_del_route( hna_node->addr, hna_node->ANETMASK, 0, 0, 0, "unknown", BATMAN_RT_TABLE_UNREACH,    1, 0 ); 
			add_del_route( hna_node->addr, hna_node->ANETMASK, 0, 0, 0, "unknown", BATMAN_RT_TABLE_TUNNEL,     1, 0 );
				
		}
		
	}

	list_for_each( list_pos, &if_list ) {

		batman_if = list_entry( list_pos, struct batman_if, list );
		
		batman_if->out.orig = batman_if->addr.sin_addr.s_addr;
		batman_if->out.flags = 0x00;
		batman_if->out.ttl = batman_if->if_ttl;
		batman_if->out.seqno = 1;
		batman_if->out.gwflags = ( (( two_way_tunnel || one_way_tunnel ) & (batman_if->if_num == 0)) ? gateway_class : 0 );
		batman_if->out.gwtypes = gateway_class ? ( (two_way_tunnel?TWO_WAY_TUNNEL_FLAG:0) | (one_way_tunnel?ONE_WAY_TUNNEL_FLAG:0) ) : 0;
		batman_if->out.version = COMPAT_VERSION;

		batman_if->if_rp_filter_old = get_rp_filter( batman_if->dev );
		set_rp_filter( 0 , batman_if->dev );

		batman_if->if_send_redirects_old = get_send_redirects( batman_if->dev );
		set_send_redirects( 0 , batman_if->dev );

		schedule_own_packet( batman_if );

	}

	if_rp_filter_all_old = get_rp_filter( "all" );
	if_rp_filter_default_old = get_rp_filter( "default" );

	if_send_redirects_all_old = get_send_redirects( "all" );
	if_send_redirects_default_old = get_send_redirects( "default" );

	set_rp_filter( 0, "all" );
	set_rp_filter( 0, "default" );

	set_send_redirects( 0, "all" );
	set_send_redirects( 0, "default" );

	forward_old = get_forwarding();
	set_forwarding(1);

	curr_time = get_time();

	
	while ( !is_aborted() ) {

		debug_output( 4, " \n \n" );

		/* harden select_timeout against sudden time change (e.g. ntpdate) */
		//curr_time = get_time();
		
		if ( aggregations_po == NO  &&  curr_time < ((struct forw_node *)forw_list.next)->send_time) {
		
			select_timeout = ((struct forw_node *)forw_list.next)->send_time - curr_time ;
			
			res = receive_packet( &ogm, &hna_array, &hna_array_len, &neigh, select_timeout, &if_incoming, &curr_time );
			
		} else if ( aggregations_po  &&  curr_time < aggregation_time ) { 
		
			select_timeout = aggregation_time - curr_time ;
			
			res = receive_packet( &ogm, &hna_array, &hna_array_len, &neigh, select_timeout, &if_incoming, &curr_time );
		
		} else {
			
			res = 0;
			debug_output( 4, "skipping select \n" );
		
		}

		
		if ( res > 0 ) {

			//curr_time = get_time();

			addr_to_string( ogm->orig, orig_str, sizeof(orig_str) );
			addr_to_string( neigh, neigh_str, sizeof(neigh_str) );
			addr_to_string( if_incoming->addr.sin_addr.s_addr, ifaddr_str, sizeof(ifaddr_str) );

			is_my_addr = is_my_orig = is_broadcast = is_duplicate = is_bidirectional = is_accepted = is_direct_neigh = is_bntog = forward_duplicate_packet = 0;

			has_unidirectional_flag = ogm->flags & UNIDIRECTIONAL_FLAG ? 1 : 0;
			has_directlink_flag     = ogm->flags & DIRECTLINK_FLAG ? 1 : 0;
			has_duplicated_flag     = ogm->flags & CLONED_FLAG ? 1 : 0;
			has_version             = ogm->version;

			is_direct_neigh = (ogm->orig == neigh) ? 1 : 0;

			debug_output( 4, "Received BATMAN packet via NB: %s , IF: %s %s (from OG: %s, seqno %d, TTL %d, V %d, UDF %d, IDF %d, DPF %d) \n", neigh_str, if_incoming->dev, ifaddr_str, orig_str, ogm->seqno, ogm->ttl, has_version, has_unidirectional_flag, has_directlink_flag, has_duplicated_flag );

			list_for_each( list_pos, &if_list ) {

				batman_if = list_entry( list_pos, struct batman_if, list );

				if ( neigh == batman_if->addr.sin_addr.s_addr )
					is_my_addr = 1;

				if ( ogm->orig == batman_if->addr.sin_addr.s_addr )
					is_my_orig = 1;

				if ( neigh == batman_if->broad.sin_addr.s_addr )
					is_broadcast = 1;

			}


			if ( ogm->gwflags != 0 && ogm->gwtypes != 0 )
				debug_output( 4, "Is an internet gateway (class %i, types %i) \n", ogm->gwflags, ogm->gwtypes );

			if ( hna_array_len > 0 ) {

				debug_output( 4, "HNA information received (%i HNA network%s): \n", hna_array_len, ( hna_array_len > 1 ? "s": "" ) );
				hna_count = 0;

				while ( hna_count < hna_array_len ) {

					hna =     (hna_array[hna_count]).addr;
					netmask = (hna_array[hna_count]).ANETMASK;
					atype   = (hna_array[hna_count]).ATYPE;


					addr_to_string( hna, orig_str, sizeof(orig_str) );

					if (  netmask > 0  &&  netmask <= 32  &&  atype <= A_TYPE_MAX )
						debug_output( 4, "hna: %s/%i, type %d\n", orig_str, netmask, atype );
					else
						debug_output( 4, "hna: %s/%i, type %d -> ignoring (invalid netmask or type) \n", orig_str, netmask, atype );

					hna_count++;

				}

			}

			if ( is_my_addr ) {

				debug_output( 4, "Drop packet: received my own broadcast (sender: %s) \n", neigh_str );

			} else if ( is_broadcast ) {

				debug_output( 4, "Drop packet: ignoring all packets with broadcast source IP (sender: %s) \n", neigh_str );

			} else if ( is_my_orig ) {

				orig_neigh_node = get_orig_node( neigh );

				debug_output( 4, "received my own OGM via NB, lastTxIfSeqno: %d, currRxSeqno: %d, prevRxSeqno: %d, currRxSeqno-prevRxSeqno %d \n", ( if_incoming->out.seqno - OUT_SEQNO_OFFSET ), ogm->seqno, orig_neigh_node->bidirect_link[if_incoming->if_num], ogm->seqno - orig_neigh_node->bidirect_link[if_incoming->if_num] );

				if ( ( has_directlink_flag ) &&
				   ( if_incoming->addr.sin_addr.s_addr == ogm->orig ) &&
				   ( !has_duplicated_flag ) &&
				   ( ogm->seqno != ( if_incoming->out.seqno - OUT_SEQNO_OFFSET ) )
				   ) {
				
					debug_output( 3, "STRANGE: received own OGM via NB: %s, lastTxIfSeqno: %d, currRxSeqno: %d, prevRxSeqno: %d, currRxSeqno-prevRxSeqno %d \n", neigh_str, ( if_incoming->out.seqno - OUT_SEQNO_OFFSET ), ogm->seqno, orig_neigh_node->bidirect_link[if_incoming->if_num], ogm->seqno - orig_neigh_node->bidirect_link[if_incoming->if_num] );

				}							   
				
				/* neighbour has to indicate direct link and it has to come via the corresponding interface */
				/* if received seqno equals last send seqno save new seqno for bidirectional check */
				if ( ( has_directlink_flag ) &&
					( if_incoming->addr.sin_addr.s_addr == ogm->orig ) &&
					( !has_duplicated_flag ) &&
					( ogm->seqno == ( if_incoming->out.seqno - OUT_SEQNO_OFFSET ) )
				   ) {

					update_bi_link_bits( orig_neigh_node, if_incoming, YES, NO );

					orig_neigh_node->bidirect_link[if_incoming->if_num] = ( if_incoming->out.seqno - OUT_SEQNO_OFFSET );

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

				/* drop packet if sender is not a direct neighbor and if we have no route towards the rebroadcasting neighbor */
				if ( ( ogm->orig != neigh ) && ( orig_neigh_node->router == NULL ) ) {

					debug_output( 4, "Drop packet: OGM via unkown neighbor! \n" );

				} else if ( ogm->ttl == 0 ) {

					debug_output( 4, "Drop packet: TTL of zero! \n" );

				} else if ( ((uint16_t)( ogm->seqno - orig_node->last_seqno )) > ((uint16_t)( FULL_SEQ_RANGE - ((uint16_t)sequence_range ))) ) {

					debug_output( 3, "Drop packet: OGM from %s, via NB %s, with old seqno! rcvd sqno %i, previos rcvd: %i! OGM-aggregation might be to radical!?\n", neigh_str, orig_str, ogm->seqno, orig_node->last_seqno );

				} else if ( alreadyConsidered( orig_node, ogm->seqno, neigh, if_incoming ) ) {

					debug_output( 4, "Drop packet: Already considered this OGM and SEQNO via this link neighbor ! \n" );

				} else {
					
//					is_alreadyConsidered = alreadyConsidered( orig_node, ogm->seqno, neigh, if_incoming );

					is_duplicate = isDuplicate( orig_node, ogm->seqno );

					is_bidirectional = isBidirectionalNeigh( orig_neigh_node, if_incoming );
					
					set_lq_bits( orig_node, ogm->seqno, if_incoming, ( !has_duplicated_flag && is_direct_neigh ) );

					nlq_rate_value = nlq_rate( orig_neigh_node, if_incoming );
					
					rand_num_value = rand_num( sequence_range );
										
					acceptance_rate_value = acceptance_rate( nlq_rate_value, sequence_range /*sequence_range <-> 100% because lq loss has already been applied by realety*/ );
					
					/* do we accept or ignore the OGM according to our current policy ? */
					is_accepted = ( is_bidirectional &&
							( ( asymmetric_weight == DEF_ASYMMETRIC_WEIGHT ) ||
							( rand_num_value < acceptance_rate_value +
								( ( ((MAX_ASYMMETRIC_WEIGHT - asymmetric_weight) * sequence_range ) / 100 )  ) ) ) );
					
					uint16_t rand_num_hundret = rand_num( 100 );
					
					/* update ranking */
					if ( is_accepted && 
						( !is_duplicate || 
						  ( ( dup_ttl_limit > 0 ) && 
						    orig_node->last_seqno == ogm->seqno &&
						    orig_node->last_seqno_largest_ttl < ogm->ttl + dup_ttl_limit &&
						    rand_num_hundret < dup_rate && /* using the same rand_num_hundret is important */
						    rand_num_hundret < (100 - (dup_degrad * (orig_node->last_seqno_largest_ttl - ogm->ttl) ))
						  )
						) ) {
						
						update_orig( orig_node, ogm , neigh, if_incoming, hna_array, hna_array_len, curr_time );
					
					}
								 
					set_dbg_rcvd_all_bits( orig_node, ogm->seqno, if_incoming, (is_bidirectional && ( !is_duplicate || 
							( dup_ttl_limit && 
									( orig_node->last_seqno == ogm->seqno && 
									orig_node->last_seqno_largest_ttl < ogm->ttl + dup_ttl_limit) ) ) ) );

					
					is_bntog = isBntog( neigh, orig_node );
					
					debug_output( 4, "  received via bidirectional link: %s, accepted OGM: %s, BNTOG: %s, iam a mobile device: %s, nlq_rate: %d, rand_num: %d, acceptance_rate: %d !\n", 
							( is_bidirectional ? "YES" : "NO" ), 
							( is_accepted ? "YES" : "NO" ), 
							( is_bntog ? "YES" : "NO" ), 
							( mobile_device ? "YES" : "NO" ), 
							nlq_rate_value, rand_num_value, acceptance_rate_value );
					
					/* is single hop (direct) neighbour */
					if ( is_direct_neigh ) {

						/* we are an asocial mobile device and dont want to forward other nodes packet */
						if( mobile_device ) {

							schedule_forward_packet( ogm, 1, 1, has_duplicated_flag, hna_array, hna_array_len, if_incoming, curr_time );

							debug_output( 4, "Forward packet: with mobile device policy: rebroadcast neighbour packet with direct link and unidirectional flag \n" );

						/* it is our best route towards him */
						} else if ( is_accepted && is_bntog ) {

							/* mark direct link on incoming interface */
							schedule_forward_packet( ogm, 0, 1, has_duplicated_flag, hna_array, hna_array_len, if_incoming, curr_time );

							debug_output( 4, "Forward packet: rebroadcast neighbour packet with direct link flag \n" );
/*
							if ( is_duplicate ) {
								// this is for remembering the actual re-broadcasted non-unidirectional OGMs 
								bit_mark( orig_node->send_old_seq_bits, -( ogm->seqno - orig_node->last_seqno ) );
							}
*/							
							
						/* if an unidirectional neighbour sends us a packet - retransmit it with unidirectional flag to tell him that we get his packets */
						/* if a bidirectional neighbour sends us a packet who is not our best link to him- retransmit it with unidirectional flag in order to prevent routing problems */
						} else if ( ( is_accepted && !is_bntog ) || ( !is_accepted ) ) {

							schedule_forward_packet( ogm, 1, 1, has_duplicated_flag, hna_array, hna_array_len, if_incoming, curr_time );

							debug_output( 4, "Forward packet: rebroadcast neighbour packet with direct link and unidirectional flag \n" );

						}

					/* multihop originator */
					} else {

						if ( is_accepted && is_bntog && !mobile_device ) {

							if ( !is_duplicate ) {

								schedule_forward_packet( ogm, 0, 0, has_duplicated_flag, hna_array, hna_array_len, if_incoming, curr_time );

								debug_output( 4, "Forward packet: rebroadcast originator packet \n" );

							} else { /* is_bntog anyway */

								list_for_each( list_pos, &orig_node->neigh_list ) {

									neigh_node = list_entry( list_pos, struct neigh_node, list );

									if ( ( neigh_node->addr == neigh ) && ( neigh_node->if_incoming == if_incoming ) ) {

										if ( no_forw_dupl_ttl_check || neigh_node->last_ttl == ogm->ttl ) {

											forward_duplicate_packet = 1;

											/* also update only last_valid time if arrived (and rebroadcasted because of best neighbor) */
											orig_node->last_valid = curr_time;
											neigh_node->last_valid = curr_time;

										}

										break;

									}

								}
								
								/* we are forwarding duplicate o-packets if they come via our best neighbour and ttl is valid */
								if ( forward_duplicate_packet ) {

									schedule_forward_packet( ogm, 0, 0, has_duplicated_flag, hna_array, hna_array_len, if_incoming, curr_time );

									debug_output( 4, "Forward packet: duplicate packet received via best neighbour with best ttl \n" );
/*
									// this is for remembering the actual re-broadcasted non-unidirectional OGMs
									bit_mark( orig_node->send_old_seq_bits,
										-( ogm->seqno - orig_node->last_seqno ) );
*/
								} else {

									debug_output( 4, "Drop packet: duplicate packet received via best neighbour but not best ttl \n" );

								}

							}

						} else {

							debug_output( 4, "Drop packet !  ");

						}

					}
					

				}

			}

		} else if ( res < 0 ) {
			
			return -1;
			
		}


		if ( aggregations_po  &&  aggregation_time <= curr_time ) {
				
			aggr_interval = originator_interval/aggregations_po;

			send_outstanding_packets();
			aggregation_time = (curr_time + aggr_interval + rand_num( aggr_interval/2 )) - (aggr_interval/4);
			
		} else if ( aggregations_po == NO ) {

			send_outstanding_packets();
			
		}

		if ( debug_timeout + 1000 < curr_time ) {

			debug_timeout = curr_time;

			purge_orig( curr_time );

			debug_orig();

			checkIntegrity();

			if ( debug_clients.clients_num[4] > 0 )
				prof_print();

			if ( ( routing_class != 0 ) && ( curr_gateway == NULL ) )
				choose_gw();

			if ( ( vis_if.sock ) && ( vis_timeout + 10000 < curr_time ) ) {

				vis_timeout = curr_time;
				send_vis_packet();

			}

		}

	}


	if ( debug_level > 0 )
		printf( "Deleting all BATMAN routes\n" );

	purge_orig( get_time() + ( 5 * PURGE_TIMEOUT ) + originator_interval );

	hash_destroy( orig_hash );


	list_for_each_safe( list_pos, hna_pos_tmp, &hna_list ) {

		hna_node = list_entry( list_pos, struct hna_node, list );
		
		/* del throw routing entries for own hna */
		add_del_route( hna_node->addr, hna_node->ANETMASK, 0, 0, 0, "unknown", BATMAN_RT_TABLE_INTERFACES, 1, 1 );
		add_del_route( hna_node->addr, hna_node->ANETMASK, 0, 0, 0, "unknown", BATMAN_RT_TABLE_NETWORKS,   1, 1 );
		add_del_route( hna_node->addr, hna_node->ANETMASK, 0, 0, 0, "unknown", BATMAN_RT_TABLE_HOSTS,      1, 1 );
		add_del_route( hna_node->addr, hna_node->ANETMASK, 0, 0, 0, "unknown", BATMAN_RT_TABLE_UNREACH,    1, 1 );
		add_del_route( hna_node->addr, hna_node->ANETMASK, 0, 0, 0, "unknown", BATMAN_RT_TABLE_TUNNEL,     1, 1 );
		
		debugFree( hna_node, 1103 );

	}

	if ( my_hna_array != NULL )
		debugFree( my_hna_array, 1104 );


	list_for_each_safe( list_pos, forw_pos_tmp, &forw_list ) {

		forw_node = list_entry( list_pos, struct forw_node, list );

		list_del( (struct list_head *)&forw_list, list_pos, &forw_list );

		debugFree( forw_node->pack_buff, 1105 );
		debugFree( forw_node, 1106 );

	}

	if ( vis_packet != NULL )
		debugFree( vis_packet, 1108 );

	set_forwarding( forward_old );

	list_for_each( list_pos, &if_list ) {

		batman_if = list_entry( list_pos, struct batman_if, list );

		set_rp_filter( batman_if->if_rp_filter_old , batman_if->dev );
		set_send_redirects( batman_if->if_send_redirects_old , batman_if->dev );

	}

	set_rp_filter( if_rp_filter_all_old, "all" );
	set_rp_filter( if_rp_filter_default_old, "default" );

	set_send_redirects( if_send_redirects_all_old, "all" );
	set_send_redirects( if_send_redirects_default_old, "default" );

	return 0;

}
