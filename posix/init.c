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



#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <paths.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "../os.h"
#include "../originator.h"
#include "../batman.h"

#define IOCSETDEV 1


//from  linux/wireless.h
#define SIOCGIWNAME    0x8B01          /* get name == wireless protocol */


int8_t stop;



int my_daemon() {

	int fd;

	switch( fork() ) {

		case -1:
			return -1;

		case 0:
			break;

		default:
			exit(EXIT_SUCCESS);

	}

	if ( setsid() == -1 )
		return(-1);

	/* Make certain we are not a session leader, or else we might reacquire a controlling terminal */
	if ( fork() )
		exit(EXIT_SUCCESS);

	chdir( "/" );

	if ( ( fd = open(_PATH_DEVNULL, O_RDWR, 0) ) != -1 ) {

		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);

		if ( fd > 2 )
			close(fd);

	}

	return 0;

}

void set_init_arg( char* switch_name, char* switch_arg, int min, int max, int32_t *target_value ) {
	errno = 0;
	int32_t tmp = strtol (switch_arg, NULL , 10);

	/*
	printf ("--%s", switch_name );
	if (switch_arg)
		printf (" %d", tmp );
	printf (" \\ \n");
	*/
	
	if ( tmp < min || tmp > max ) {

		printf( "Invalid --%s value specified: %i ! Value must be %i <= <value> <= %i !\n", switch_name, tmp, min, max );

		exit(EXIT_FAILURE);
	}

	*target_value = tmp;
	return;
}


void set_gw_network ( char *optarg_p ) {
	
	struct in_addr tmp_ip_holder;
	uint16_t netmask;
	char *slash_ptr;
	//static char netmask_str[ADDR_STR_LEN];
		
	char optarg_str[22];
	
	memcpy( optarg_str, optarg_p, sizeof(optarg_str) < strlen( optarg_p)+1 ? sizeof(optarg_str) : strlen(optarg_p)+1 );
	
	if ( ( slash_ptr = strchr( optarg_str, '/' ) ) == NULL ) {

		printf( "Invalid GW network (netmask is missing): %s\n", optarg_str );
		exit(EXIT_FAILURE);

	}

	*slash_ptr = '\0';

	if ( inet_pton( AF_INET, optarg_str, &tmp_ip_holder ) < 1 ) {

		*slash_ptr = '/';
		printf( "Invalid GW network (IP is invalid): %s\n", optarg_str );
		exit(EXIT_FAILURE);

	}

	errno = 0;

	netmask = strtol( slash_ptr + 1, NULL, 10 );

	if ( ( errno == ERANGE ) || ( errno != 0 && netmask == 0 ) ) {

		perror("strtol");
		exit(EXIT_FAILURE);

	}

	if ( netmask < MIN_GW_TUNNEL_NETMASK || netmask > MAX_GW_TUNNEL_NETMASK ) {

		*slash_ptr = '/';
		printf( "Invalid GW network (netmask %d is invalid): %s !\n", netmask, optarg_str );
		exit(EXIT_FAILURE);

	}

	gw_tunnel_prefix  = tmp_ip_holder.s_addr;
	gw_tunnel_prefix  = gw_tunnel_prefix & htonl( 0xFFFFFFFF<<(32-netmask) );
	gw_tunnel_netmask = netmask;
	
	
	*slash_ptr = '/';
	
}


void prepare_add_del_own_hna ( char *optarg_str, int8_t del, uint8_t atype ) {
	
	struct hna_node *hna_node;
	struct in_addr tmp_ip_holder;
	uint16_t netmask;
	char *slash_ptr;
	struct list_head *hna_list_pos;
	char str[16];
	uint8_t found = NO;
			
	
	// check if number of HNAs fit into max packet size
	if ( !del  &&  sizeof(struct bat_header) + sizeof(struct bat_packet) + 
		     ( ( 2 /*placeholder for the new hna-ext and one gw-ext packet*/ +  
		     my_srv_ext_array_len + my_hna_list_enabled) * sizeof(struct ext_packet)) > MAX_PACKET_OUT_SIZE ) {
		
		debug_output(3, "HNAs do not fit into max packet size \n");
		exit(EXIT_FAILURE);
		

	}

	
	if ( ( slash_ptr = strchr( optarg_str, '/' ) ) == NULL ) {

		printf( "Invalid announced network (netmask is missing): %s\n", optarg_str );
		exit(EXIT_FAILURE);

	}

	*slash_ptr = '\0';

	if ( inet_pton( AF_INET, optarg_str, &tmp_ip_holder ) < 1 ) {

		*slash_ptr = '/';
		printf( "Invalid announced network (IP is invalid): %s\n", optarg_str );
		exit(EXIT_FAILURE);

	}

	errno = 0;

	netmask = strtol( slash_ptr + 1, NULL, 10 );

	if ( ( errno == ERANGE ) || ( errno != 0 && netmask == 0 ) ) {

		perror("strtol");
		exit(EXIT_FAILURE);

	}

	if ( netmask < 1 || netmask > 32 ) {

		*slash_ptr = '/';
		printf( "Invalid announced network (netmask is invalid): %s\n", optarg_str );
		exit(EXIT_FAILURE);

	}
	
	tmp_ip_holder.s_addr = ( tmp_ip_holder.s_addr & htonl(0xFFFFFFFF<<(32-netmask)) );
		
	
	list_for_each( hna_list_pos, &my_hna_list ) {

		hna_node = list_entry( hna_list_pos, struct hna_node, list );

		if ( hna_node->key.addr == tmp_ip_holder.s_addr && 
				   hna_node->key.KEY_FIELD_ANETMASK == netmask && 
				   hna_node->key.KEY_FIELD_ATYPE == atype ) {
				
			found = YES;
			
			if ( del && hna_node->enabled ) {
			//printf( "removing HNA %s/%i, atype %d \n", str, netmask, atype );
				hna_node->enabled = NO;
				my_hna_list_enabled--;
		
			} else if ( !del && ! hna_node->enabled ) {
			
				hna_node->enabled = YES;
				my_hna_list_enabled++;
			}
			
			
			break;
			
		}

	}

	
	if ( ! found ) {
		
		hna_node = debugMalloc( sizeof(struct hna_node), 203 );
		memset( hna_node, 0, sizeof(struct hna_node) );
		INIT_LIST_HEAD( &hna_node->list );
	
		hna_node->key.addr = tmp_ip_holder.s_addr;
		hna_node->key.KEY_FIELD_ANETMASK = netmask;
		hna_node->key.KEY_FIELD_ATYPE = atype;
		hna_node->enabled = ( del ? NO : YES ) ;
		
		
		addr_to_string( hna_node->key.addr, str, sizeof (str) );
		//printf( "adding HNA %s/%i, atype %d \n", str, netmask, atype );
	
		list_add_tail( &hna_node->list, &my_hna_list );
		
		if ( hna_node->enabled )
			my_hna_list_enabled++;

	}
	
	*slash_ptr = '/';
	
}

void prepare_add_no_tunnel (  char *optarg_str ) {
	struct notun_node *notun_node;
	struct in_addr tmp_ip_holder;
	char *delimiter1_ptr;
	uint32_t netmask;
	
	if ( ( delimiter1_ptr = strchr( optarg_str, '/' ) ) == NULL ) {

		printf( "Invalid %s argument (netmask is missing): %s\n", NO_TUNNEL_RULE_SWITCH, optarg_str );
		exit(EXIT_FAILURE);

	}

	*delimiter1_ptr = '\0';

	if ( inet_pton( AF_INET, optarg_str, &tmp_ip_holder ) < 1 ) {

		*delimiter1_ptr = '/';
		printf( "Invalid %s argument (IP is invalid): %s\n", NO_TUNNEL_RULE_SWITCH, optarg_str );
		exit(EXIT_FAILURE);

	}

	*delimiter1_ptr = '/';
	
	errno = 0;
	netmask = strtol( delimiter1_ptr + 1, NULL, 10 );
	
	if ( ( errno == ERANGE ) || netmask > 32 ) {
	
		printf( "Invalid %s argument (netmask is invalid): %s\n", NO_TUNNEL_RULE_SWITCH, optarg_str );
		perror("strtol");
		exit(EXIT_FAILURE);
	
	}


	notun_node = debugMalloc( sizeof(struct notun_node), 224 );
	memset( notun_node, 0, sizeof(struct notun_node) );
	INIT_LIST_HEAD( &notun_node->list );

	notun_node->addr = tmp_ip_holder.s_addr;
	notun_node->netmask = netmask;

	list_add_tail( &notun_node->list, &notun_list );
	
}

	
	
void prepare_add_del_own_srv ( char *optarg_str, int8_t del ) {
	
	struct srv_node *srv_node;
	struct in_addr tmp_ip_holder;
	uint16_t port;
	uint8_t seqno = 0;
	char *delimiter1_ptr, *delimiter2_ptr;
	struct list_head *srv_list_pos;
	char str[16];
	uint8_t found = NO;
	
	int opt_len = strlen( optarg_str );
	
	// check if number of SRVs fit into max packet size
	if ( !del  &&  sizeof(struct bat_header) + sizeof(struct bat_packet) + 
		     ( ( 2 /*placeholder for the new hna-ext and one gw-ext packet*/ +  
		     my_srv_list_enabled + my_hna_list_enabled) * sizeof(struct ext_packet)) > MAX_PACKET_OUT_SIZE ) {
		
		debug_output(3, "SRV announcements do not fit into max packet size \n");
		exit(EXIT_FAILURE);
		
	}


	if ( ( delimiter1_ptr = strchr( optarg_str, ':' ) ) == NULL ) {

		printf( "Invalid SRV announcement (first : is missing): %s\n", optarg_str );
		exit(EXIT_FAILURE);

	}

	*delimiter1_ptr = '\0';

	if ( inet_pton( AF_INET, optarg_str, &tmp_ip_holder ) < 1 ) {

		*delimiter1_ptr = ':';
		printf( "Invalid SRV announcement (IP is invalid): %s\n", optarg_str );
		exit(EXIT_FAILURE);

	}
	
	*delimiter1_ptr = ':';

	
	errno = 0;
	port = strtol( delimiter1_ptr + 1, NULL, 10 );
	
	if ( ( errno == ERANGE ) ) {
	
		//*delimiter2_ptr = ':';
		printf( "Invalid SRV announcement (port is invalid): %s\n", optarg_str );
		perror("strtol");
		exit(EXIT_FAILURE);
	
	}
	
	if( !del ) {
	
		if ( ( ((delimiter1_ptr + 2) - optarg_str) > opt_len ) || ( delimiter2_ptr = strchr( (delimiter1_ptr + 1), ':' ) ) == NULL ) {
	
			printf( "Invalid SRV announcement (second : is missing): %s\n", optarg_str );
			exit(EXIT_FAILURE);
	
		}
		
	
		//*delimiter2_ptr = ':';
	
		
		
		if (  ((delimiter2_ptr + 2) - optarg_str) > opt_len  ) {
	
			printf( "Invalid SRV announcement (seqno is missing): %s\n", optarg_str );
			exit(EXIT_FAILURE);
	
		}
		
		errno = 0;
		seqno = strtol( delimiter2_ptr + 1, NULL, 10 );
	
		if ( ( errno == ERANGE ) ) {
	
			printf( "Invalid SRV announcement (seqno is invalid): %s\n", optarg_str );
			perror("strtol");
			exit(EXIT_FAILURE);
	
		}
	
	}	
	

	list_for_each( srv_list_pos, &my_srv_list ) {

		srv_node = list_entry( srv_list_pos, struct srv_node, list );

		if ( srv_node->srv_addr == tmp_ip_holder.s_addr && srv_node->srv_port == port ) {
		
			found = YES;
	
			if ( del && srv_node->enabled ) {
				//printf( "removing HNA %s/%i, atype %d \n", str, netmask, atype );
				srv_node->enabled = NO;
				my_srv_list_enabled--;

			} else if ( !del && ! srv_node->enabled ) {
	
				srv_node->enabled = YES;
				srv_node->srv_seqno = seqno;
				my_srv_list_enabled++;
			
			} else if ( !del && srv_node->enabled ) {
	
				srv_node->srv_seqno = seqno;
			
			}
	
	
			break;
	
		}

	}


	if ( ! found ) {

		srv_node = debugMalloc( sizeof(struct srv_node), 223 );
		memset( srv_node, 0, sizeof(struct srv_node) );
		INIT_LIST_HEAD( &srv_node->list );

		srv_node->srv_addr = tmp_ip_holder.s_addr;
		srv_node->srv_port = port;
		srv_node->srv_seqno = ( !del ? seqno : 0 );
		srv_node->enabled = ( del ? NO : YES ) ;


		addr_to_string( srv_node->srv_addr, str, sizeof (str) );
		printf( "adding SRV %s:%d:%i \n", str, port, seqno );

		list_add_tail( &srv_node->list, &my_srv_list );

		if ( srv_node->enabled )
			my_srv_list_enabled++;

	}
	
}



void apply_init_args( int argc, char *argv[] ) {

	struct in_addr tmp_ip_holder;
	struct batman_if *batman_if;
	struct debug_level_info *debug_level_info;
	uint8_t found_args = 1, batch_mode = 0, info_output = 0;
	int8_t res;
	struct hna_node *hna_node;
	struct srv_node *srv_node;
	char  ifaddr_str[ADDR_STR_LEN];


	int32_t optchar, recv_buff_len, bytes_written, download_speed = 0, upload_speed = 0;
	char str1[16], str2[16], *slash_ptr, *unix_buff, *buff_ptr, *cr_ptr;
	char req_opt = 0;
	struct ext_type_hna hna_type_request;
	uint32_t vis_server = 0;

	memset( &hna_type_request, 0, sizeof( hna_type_request ) );
	
	memset( &tmp_ip_holder, 0, sizeof (struct in_addr) );
	stop = 0;
	prog_name = argv[0];
	
	inet_pton( AF_INET, DEF_GW_TUNNEL_PREFIX_STR, &gw_tunnel_prefix );

	
	printf( "WARNING: You are using BatMan-eXp %s%s (compatibility version %d) !\n", SOURCE_VERSION, ( strncmp( REVISION_VERSION, "0", 1 ) != 0 ? REVISION_VERSION : "" ), COMPAT_VERSION );

	while ( 1 ) {

		int32_t option_index = 0;
		static struct option long_options[] =
		{
   {ADVANCED_SWITCH,            0, 0, 0},
   {GENIII_DEFAULTS_SWITCH,     0, 0, 0},
   {BMX_DEFAULTS_SWITCH,        0, 0, 0},
   {GRAZ07_DEFAULTS_SWITCH,     0, 0, 0},
   {ADD_SRV_SWITCH,             1, 0, 0},
   {DEL_SRV_SWITCH,             1, 0, 0},
   {AGGREGATIONS_PO_SWITCH,     1, 0, 0},
   {NO_AGGREGATIONS_SWITCH,     0, 0, 0},
   {AGGREGATIONS_SWITCH,        0, 0, 0},
   {BIDIRECT_TIMEOUT_SWITCH,    1, 0, 0},
   {NBRFSIZE_SWITCH,            1, 0, 0},
   {INITIAL_SEQNO_SWITCH,       1, 0, 0},
   {FAKE_UPTIME_SWITCH,         1, 0, 0},
   {DAD_TIMEOUT_SWITCH,         1, 0, 0},
   {GW_CHANGE_HYSTERESIS_SWITCH,1, 0, 0},
   {GW_TUNNEL_NETW_SWITCH,      1, 0, 0},
   {TUNNEL_IP_LEASE_TIME_SWITCH,1, 0, 0},
   {TWO_WAY_TUNNEL_SWITCH,      1, 0, 0},
   {ONE_WAY_TUNNEL_SWITCH,      1, 0, 0},
   {TTL_SWITCH,                 1, 0, 0},
   {ASOCIAL_SWITCH,             0, 0, 0},
   {NO_UNREACHABLE_RULE_SWITCH, 0, 0, 0},
   {NO_TUNPERSIST_SWITCH,       0, 0, 0},
   {RT_PRIO_OFFSET_SWITCH,      1, 0, 0},
   {MORE_RULES_SWITCH,          0, 0, 0},
   {NO_PRIO_RULES_SWITCH,       0, 0, 0},
   {NO_LO_RULE_SWITCH,          0, 0, 0},
   {NO_TUNNEL_RULE_SWITCH,      1, 0, 0},
   {NO_THROW_RULES_SWITCH,      0, 0, 0},
   {NO_UNRESP_CHECK_SWITCH,     0, 0, 0},
   {RESIST_BLOCKED_SEND_SWITCH, 0, 0, 0},
   {RT_TABLE_OFFSET_SWITCH,     1, 0, 0},
   {BASE_PORT_SWITCH,           1, 0, 0},
   {DUP_TTL_LIMIT_SWITCH,       1, 0, 0},
   {DUP_RATE_SWITCH,	        1, 0, 0},
   {DUP_DEGRAD_SWITCH,	        1, 0, 0},
   {WL_CLONES_SWITCH,           1, 0, 0},
   {ASYMMETRIC_WEIGHT_SWITCH,   1, 0, 0},
   {ASYMMETRIC_EXP_SWITCH,      1, 0, 0},
   {REBRC_DELAY_SWITCH,         1, 0, 0},
   {PARALLEL_BAT_NETA_SWITCH,   0, 0, 0},
   {PARALLEL_BAT_NETB_SWITCH,   0, 0, 0},
   {PARALLEL_BAT_NETC_SWITCH,   0, 0, 0},
   {PARALLEL_BAT_24C3_SWITCH,   0, 0, 0},
   {0, 0, 0, 0}
		};

		
		if ( ( optchar = getopt_long ( argc, argv, "a:A:bcmd:hHio:l:q:g:p:r:s:vV", long_options, &option_index ) ) == -1 ) {
			break;
		}
		
//		printf(" found_args: %i, optchar %c \n", found_args, optchar );
		

		switch ( optchar ) {

			case 0: {
				
				if( strcmp( ADVANCED_SWITCH, long_options[option_index].name ) == 0 ) {
	
					errno = 0;
					
					verbose_usage();
					print_advanced_opts( YES /*verbose*/ );
					exit(EXIT_SUCCESS);

				} else if ( strcmp( BMX_DEFAULTS_SWITCH, long_options[option_index].name ) == 0 ) {

	
					errno = 0;
	
					if ( found_args == 1 ) {
						default_para_set = PARA_SET_BMX;
	
					} else {
						printf( "Error - Parametrization set can only be specified once and must be the first given argument !\n" );
						exit(EXIT_FAILURE);
					}


					found_args += 1;
					break;

				} else if ( strcmp( GENIII_DEFAULTS_SWITCH, long_options[option_index].name ) == 0 ) {

	
					errno = 0;
	
					printf( "Error - Sorry, %s is not supported anymore... !\n", GENIII_DEFAULTS_SWITCH );
					exit(EXIT_FAILURE);

				} else if ( strcmp( GRAZ07_DEFAULTS_SWITCH, long_options[option_index].name ) == 0 ) {

					errno = 0;
	
					if ( found_args == 1  ) {
						default_para_set = PARA_SET_GRAZ07;
					} else {
						printf( "Error - Parametrization set can only be specified once !\n" );
						exit(EXIT_FAILURE);
					}
					
	
					my_ogi = 1500;
	
					set_init_arg( BIDIRECT_TIMEOUT_SWITCH, "20", MIN_BIDIRECT_TIMEOUT, MAX_BIDIRECT_TIMEOUT, &bidirect_link_to );
	
					set_init_arg( NBRFSIZE_SWITCH, "100", MIN_SEQ_RANGE, MAX_SEQ_RANGE, &my_ws );
					//num_words = ( my_ws / WORD_BIT_SIZE ) + ( ( my_ws % WORD_BIT_SIZE > 0)? 1 : 0 );
	
					set_init_arg( GW_CHANGE_HYSTERESIS_SWITCH, "2", MIN_GW_CHANGE_HYSTERESIS, MAX_GW_CHANGE_HYSTERESIS, &gw_change_hysteresis ); 
					
					set_init_arg( DUP_TTL_LIMIT_SWITCH, "2", MIN_DUP_TTL_LIMIT, MAX_DUP_TTL_LIMIT, &dup_ttl_limit );
	
					set_init_arg( DUP_RATE_SWITCH, "99", MIN_DUP_RATE, MAX_DUP_RATE, &dup_rate );
	
					set_init_arg( DUP_DEGRAD_SWITCH, "2", MIN_DUP_DEGRAD, MAX_DUP_DEGRAD, &dup_degrad );
	
					set_init_arg( WL_CLONES_SWITCH, "200", MIN_WL_CLONES, MAX_WL_CLONES, &wl_clones );
					
					set_init_arg( ASYMMETRIC_WEIGHT_SWITCH, "100", MIN_ASYMMETRIC_WEIGHT, MAX_ASYMMETRIC_WEIGHT, &asymmetric_weight );
	
					set_init_arg( ASYMMETRIC_EXP_SWITCH, "1", MIN_ASYMMETRIC_EXP, MAX_ASYMMETRIC_EXP, &asymmetric_exp );
	
					set_init_arg( REBRC_DELAY_SWITCH, "35", MIN_REBRC_DELAY, MAX_REBRC_DELAY, &rebrc_delay );
	
					set_init_arg( AGGREGATIONS_PO_SWITCH, "0", MIN_AGGREGATIONS_PO, MAX_AGGREGATIONS_PO, &aggregations_po );
					
					found_args += 1;
					break;

				} else if ( strcmp( BIDIRECT_TIMEOUT_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( BIDIRECT_TIMEOUT_SWITCH, optarg, MIN_BIDIRECT_TIMEOUT, MAX_BIDIRECT_TIMEOUT, &bidirect_link_to );
					
					//blt_opt = YES; /* for changing the link-window size on the fly */
					req_opt = REQ_LWS;
					
					found_args += 2;
					break;

				} else if ( strcmp( NBRFSIZE_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( NBRFSIZE_SWITCH, optarg, MIN_SEQ_RANGE, MAX_SEQ_RANGE, &my_ws );
					//num_words = ( my_ws / WORD_BIT_SIZE ) + ( ( my_ws % WORD_BIT_SIZE > 0)? 1 : 0 );
					
					//ws_opt = YES; /* for changing the window-size on-the fly */
					req_opt = REQ_PWS;
					
					found_args += 2;
					break;

				} else if ( strcmp( DAD_TIMEOUT_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( DAD_TIMEOUT_SWITCH, optarg, MIN_DAD_TIMEOUT, MAX_DAD_TIMEOUT, &dad_timeout );
					
					found_args += 2;
					break;

				} else if ( strcmp( INITIAL_SEQNO_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( INITIAL_SEQNO_SWITCH, optarg, MIN_INITIAL_SEQNO, MAX_INITIAL_SEQNO, &initial_seqno );
					found_args += 2;
					break;
				
				} else if ( strcmp( FAKE_UPTIME_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( FAKE_UPTIME_SWITCH, optarg, MIN_FAKE_UPTIME, MAX_FAKE_UPTIME, &fake_uptime );
					
					req_opt = REQ_FAKE_TIME;
					
					fake_start_time( fake_uptime );
					
					found_args += 2;
					break;
				
				} else if ( strcmp( GW_CHANGE_HYSTERESIS_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( GW_CHANGE_HYSTERESIS_SWITCH, optarg, MIN_GW_CHANGE_HYSTERESIS, MAX_GW_CHANGE_HYSTERESIS, &gw_change_hysteresis );
					found_args += 2;
					break;

				} else if ( strcmp( GW_TUNNEL_NETW_SWITCH, long_options[option_index].name ) == 0 ) {

					set_gw_network( optarg );

					found_args += 2;
					break;
					
					
				} else if ( strcmp( TUNNEL_IP_LEASE_TIME_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( TUNNEL_IP_LEASE_TIME_SWITCH, optarg, MIN_TUNNEL_IP_LEASE_TIME, MAX_TUNNEL_IP_LEASE_TIME, &tunnel_ip_lease_time );
					found_args += 2;
					break;
							
				} else if ( strcmp( TWO_WAY_TUNNEL_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( TWO_WAY_TUNNEL_SWITCH, optarg, MIN_TWO_WAY_TUNNEL, MAX_TWO_WAY_TUNNEL, &two_way_tunnel );
					req_opt = REQ_2WT;
					found_args += 2;
					break;
				
				} else if ( strcmp( ONE_WAY_TUNNEL_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( ONE_WAY_TUNNEL_SWITCH, optarg, MIN_ONE_WAY_TUNNEL, MAX_ONE_WAY_TUNNEL, &one_way_tunnel );
					req_opt = REQ_1WT;
					found_args += 2;
					break;
				
				} else if ( strcmp( TTL_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( TTL_SWITCH, optarg, MIN_TTL, MAX_TTL, &ttl );
					found_args += 2;
					break;

				} else if ( strcmp( DUP_TTL_LIMIT_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( DUP_TTL_LIMIT_SWITCH, optarg, MIN_DUP_TTL_LIMIT, MAX_DUP_TTL_LIMIT, &dup_ttl_limit );
					found_args += 2;
					break;
				
				} else if ( strcmp( DUP_RATE_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( DUP_RATE_SWITCH, optarg, MIN_DUP_RATE, MAX_DUP_RATE, &dup_rate );
					found_args += 2;
					break;

				} else if ( strcmp( DUP_DEGRAD_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( DUP_DEGRAD_SWITCH, optarg, MIN_DUP_DEGRAD, MAX_DUP_DEGRAD, &dup_degrad );
					
					req_opt = REQ_DTD;
					found_args += 2;
					break;
				
				} else if ( strcmp( WL_CLONES_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( WL_CLONES_SWITCH, optarg, MIN_WL_CLONES, MAX_WL_CLONES, &wl_clones );
					
					//if( send_clones > DEF_SEND_CLONES )
					//compat_version = DEF_COMPAT_VERSION + 1;

					found_args += 2;
					break;

				} else if ( strcmp( ASYMMETRIC_WEIGHT_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( ASYMMETRIC_WEIGHT_SWITCH, optarg, MIN_ASYMMETRIC_WEIGHT, MAX_ASYMMETRIC_WEIGHT, &asymmetric_weight );
					found_args += 2;
					break;

				} else if ( strcmp( ASYMMETRIC_EXP_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( ASYMMETRIC_EXP_SWITCH, optarg, MIN_ASYMMETRIC_EXP, MAX_ASYMMETRIC_EXP, &asymmetric_exp );
					found_args += 2;
					break;
					
				} else if ( strcmp( REBRC_DELAY_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( REBRC_DELAY_SWITCH, optarg, MIN_REBRC_DELAY, MAX_REBRC_DELAY, &rebrc_delay );
					found_args += 2;
					break;
							
				} else if ( strcmp( RT_PRIO_OFFSET_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( RT_PRIO_OFFSET_SWITCH, optarg, MIN_RT_PRIO_OFFSET, MAX_RT_PRIO_OFFSET, &rt_prio_offset );
					found_args += 2;
					break;
					
				} else if ( strcmp( BASE_PORT_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( BASE_PORT_SWITCH, optarg, MIN_BASE_PORT, MAX_BASE_PORT, &ogm_port );
					found_args += 2;
					break;
				
				} else if ( strcmp( RT_TABLE_OFFSET_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( RT_TABLE_OFFSET_SWITCH, optarg, MIN_RT_TABLE_OFFSET, MAX_RT_TABLE_OFFSET, &rt_table_offset );
					found_args += 2;
					break;
					
				} else if ( strcmp( AGGREGATIONS_PO_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( AGGREGATIONS_PO_SWITCH, optarg, MIN_AGGREGATIONS_PO, MAX_AGGREGATIONS_PO, &aggregations_po );
					set_init_arg( REBRC_DELAY_SWITCH, "0", MIN_REBRC_DELAY, MAX_REBRC_DELAY, &rebrc_delay );
					found_args += 2;
					break;
				
				} else if ( strcmp( ADD_SRV_SWITCH, long_options[option_index].name ) == 0 ) {

					prepare_add_del_own_srv( optarg, NO /* do not delete */ );
			
					//tout_opt = YES; /* for activating the add request */
					req_opt = REQ_CHANGE_SRV;

					found_args += 2;
					break;
				
				} else if ( strcmp( DEL_SRV_SWITCH, long_options[option_index].name ) == 0 ) {

					prepare_add_del_own_srv( optarg, YES /*delete*/ );
				
					//tout_opt = YES; /* for activating the del request */
					req_opt = REQ_CHANGE_SRV;
				
					found_args += 2;
					break;
					
				} else if ( strcmp( NO_TUNNEL_RULE_SWITCH, long_options[option_index].name ) == 0 ) {

					prepare_add_no_tunnel( optarg );
					
					found_args += 2;
					break;
				
				/*	this is just a template:
				} else if ( strcmp( _SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( _SWITCH, optarg, MIN_, MAX_, & );
					found_args += 2;
					break;
				*/
						
				} else if ( strcmp( NO_AGGREGATIONS_SWITCH, long_options[option_index].name ) == 0 ) {

					aggregations_po = 0;
					set_init_arg( REBRC_DELAY_SWITCH, "35", MIN_REBRC_DELAY, MAX_REBRC_DELAY, &rebrc_delay );
					found_args += 1;
					break;
					
				} else if ( strcmp( AGGREGATIONS_SWITCH, long_options[option_index].name ) == 0 ) {

					aggregations_po = DEF_AGGREGATIONS_PO;
					set_init_arg( REBRC_DELAY_SWITCH, "0", MIN_REBRC_DELAY, MAX_REBRC_DELAY, &rebrc_delay );
					found_args += 1;
					break;
					
				
				} else if ( strcmp( ASOCIAL_SWITCH, long_options[option_index].name ) == 0 ) {

					printf ("--%s \\ \n", long_options[option_index].name);
					errno = 0;
					mobile_device = YES;
					found_args += 1;
					break;

				} else if ( strcmp( NO_UNREACHABLE_RULE_SWITCH, long_options[option_index].name ) == 0 ) {

					printf ("--%s \\ \n", long_options[option_index].name);
					errno = 0;
					no_unreachable_rule = YES;
					found_args += 1;
					break;
				
				} else if ( strcmp( NO_TUNPERSIST_SWITCH, long_options[option_index].name ) == 0 ) {

					printf ("--%s \\ \n", long_options[option_index].name);
					errno = 0;
					no_tun_persist = YES;
					found_args += 1;
					break;
				
				} else if ( strcmp( MORE_RULES_SWITCH, long_options[option_index].name ) == 0 ) {

					printf ("--%s \\ \n", long_options[option_index].name);
					errno = 0;
					more_rules = YES;
					found_args += 1;
					break;

				} else if ( strcmp( NO_PRIO_RULES_SWITCH, long_options[option_index].name ) == 0 ) {

					printf ("--%s \\ \n", long_options[option_index].name);
					errno = 0;
					no_prio_rules = YES;
					found_args += 1;
					break;

				} else if ( strcmp( NO_LO_RULE_SWITCH, long_options[option_index].name ) == 0 ) {

					printf ("--%s \\ \n", long_options[option_index].name);
					errno = 0;
					no_lo_rule = YES;
					found_args += 1;
					break;

				} else if ( strcmp( NO_THROW_RULES_SWITCH, long_options[option_index].name ) == 0 ) {

					printf ("--%s \\ \n", long_options[option_index].name);
					errno = 0;
					no_throw_rules = YES;
					found_args += 1;
					break;

				} else if ( strcmp( NO_UNRESP_CHECK_SWITCH, long_options[option_index].name ) == 0 ) {

					printf ("--%s \\ \n", long_options[option_index].name);
					errno = 0;
					no_unresponsive_check = YES;
					found_args += 1;
					break;
					
				} else if ( strcmp( RESIST_BLOCKED_SEND_SWITCH, long_options[option_index].name ) == 0 ) {

					printf ("WARNING: --%s is deprecated, it is activated by default now! \\ \n", long_options[option_index].name);
					errno = 0;
					resist_blocked_send = YES;
					found_args += 1;
					break;
							
				} else if ( strcmp( PARALLEL_BAT_NETA_SWITCH, long_options[option_index].name ) == 0 ) {

					errno = 0;
					
					set_init_arg( BASE_PORT_SWITCH,       "14305", MIN_BASE_PORT,       MAX_BASE_PORT,       &ogm_port ); 
					set_init_arg( RT_TABLE_OFFSET_SWITCH, "144",   MIN_RT_TABLE_OFFSET, MAX_RT_TABLE_OFFSET, &rt_table_offset ); 
					set_init_arg( RT_PRIO_OFFSET_SWITCH,  "14500", MIN_RT_PRIO_OFFSET, MAX_RT_PRIO_OFFSET, &rt_prio_offset ); 
					set_gw_network( "169.254.128.0/22" );
					
					found_args += 1;
					break;
					
				} else if ( strcmp( PARALLEL_BAT_NETB_SWITCH, long_options[option_index].name ) == 0 ) {

					errno = 0;
					
					set_init_arg( BASE_PORT_SWITCH,       "16305", MIN_BASE_PORT,       MAX_BASE_PORT,       &ogm_port ); 
					set_init_arg( RT_TABLE_OFFSET_SWITCH, "40",   MIN_RT_TABLE_OFFSET, MAX_RT_TABLE_OFFSET, &rt_table_offset ); 
					set_init_arg( RT_PRIO_OFFSET_SWITCH,  "4000", MIN_RT_PRIO_OFFSET, MAX_RT_PRIO_OFFSET, &rt_prio_offset ); 
					set_gw_network( "169.254.160.0/22" );
					
					found_args += 1;
					break;
					
				} else if ( strcmp( PARALLEL_BAT_NETC_SWITCH, long_options[option_index].name ) == 0 ) {

					errno = 0;
					
					set_init_arg( BASE_PORT_SWITCH,       "18305", MIN_BASE_PORT,       MAX_BASE_PORT,       &ogm_port ); 
					set_init_arg( RT_TABLE_OFFSET_SWITCH, "184",   MIN_RT_TABLE_OFFSET, MAX_RT_TABLE_OFFSET, &rt_table_offset ); 
					set_init_arg( RT_PRIO_OFFSET_SWITCH,  "18500", MIN_RT_PRIO_OFFSET, MAX_RT_PRIO_OFFSET, &rt_prio_offset ); 
					set_gw_network( "169.254.192.0/22" );
					
					set_init_arg( NBRFSIZE_SWITCH, "10", MIN_SEQ_RANGE, MAX_SEQ_RANGE, &my_ws );
					//num_words = ( my_ws / WORD_BIT_SIZE ) + ( ( my_ws % WORD_BIT_SIZE > 0)? 1 : 0 );

					found_args += 1;
					break;
					
				} else if ( strcmp( PARALLEL_BAT_24C3_SWITCH, long_options[option_index].name ) == 0 ) {

					errno = 0;
					
					set_init_arg( BASE_PORT_SWITCH,       "4308", MIN_BASE_PORT,       MAX_BASE_PORT,       &ogm_port ); 
					set_init_arg( RT_TABLE_OFFSET_SWITCH, "76",   MIN_RT_TABLE_OFFSET, MAX_RT_TABLE_OFFSET, &rt_table_offset ); 
					set_init_arg( RT_PRIO_OFFSET_SWITCH,  "7600", MIN_RT_PRIO_OFFSET, MAX_RT_PRIO_OFFSET, &rt_prio_offset ); 
					set_gw_network( "0.0.0.0/30" );
					
					set_init_arg( TWO_WAY_TUNNEL_SWITCH, "0", MIN_TWO_WAY_TUNNEL, MAX_TWO_WAY_TUNNEL, &two_way_tunnel );
					set_init_arg( ONE_WAY_TUNNEL_SWITCH, "3", MIN_TWO_WAY_TUNNEL, MAX_TWO_WAY_TUNNEL, &two_way_tunnel );

					set_init_arg( NBRFSIZE_SWITCH, "100", MIN_SEQ_RANGE, MAX_SEQ_RANGE, &my_ws );
					set_init_arg( BIDIRECT_TIMEOUT_SWITCH, "30", MIN_BIDIRECT_TIMEOUT, MAX_BIDIRECT_TIMEOUT, &bidirect_link_to );
					no_lo_rule = YES;

					found_args += 1;
					break;
				
				/* this is just a template:
				} else if ( strcmp( _SWITCH, long_options[option_index].name ) == 0 ) {

					errno = 0;
					= YES;
					found_args += 1;
					break;
				*/	
				
//				}

				}

				usage();
				exit(EXIT_FAILURE);


			}

			case 'a':

				prepare_add_del_own_hna( optarg, NO, A_TYPE_NETWORK );
				
				//hna_opt = YES; /* for activating the add request */
				req_opt = REQ_CHANGE_HNA;
				
				
				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;

			case 'A':

				prepare_add_del_own_hna( optarg, YES, A_TYPE_NETWORK );
				
				//hna_opt = YES; /* for activating the del request */
				req_opt = REQ_CHANGE_HNA;
				
				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;
			
			case 'b':
				batch_mode = YES;
				found_args += 1;
				break;

			case 'c':
				conn_client = YES;
				req_opt = REQ_RESET;
				found_args += 1;
				break;

			case 'd':

				errno = 0;

				debug_level = strtol( optarg, NULL, 10 );

				if ( ( errno == ERANGE ) || ( errno != 0 && debug_level == 0 ) ) {

					perror("strtol");
					exit(EXIT_FAILURE);

				}

				if ( debug_level > debug_level_max ) {

					printf( "Invalid debug level: %i\nDebug level has to be between 0 and %i.\n", debug_level, debug_level_max );
					exit(EXIT_FAILURE);

				}

				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;

			case 'g':

				if ( ( slash_ptr = strchr( optarg, '/' ) ) != NULL )
					*slash_ptr = '\0';

				errno = 0;

				download_speed = strtol( optarg, NULL, 10 );

				if ( ( errno == ERANGE ) || ( errno != 0 && download_speed == 0 ) ) {

					perror("strtol");
					exit(EXIT_FAILURE);

				}

				if ( ( strlen( optarg ) > 4 ) && ( ( strncmp( optarg + strlen( optarg ) - 4, "MBit", 4 ) == 0 ) || ( strncmp( optarg + strlen( optarg ) - 4, "mbit", 4 ) == 0 ) || ( strncmp( optarg + strlen( optarg ) - 4, "Mbit", 4 ) == 0 ) ) )
					download_speed *= 1024;

				if ( slash_ptr != NULL ) {

					errno = 0;

					upload_speed = strtol( slash_ptr + 1, NULL, 10 );

					if ( ( errno == ERANGE ) || ( errno != 0 && upload_speed == 0 ) ) {
						perror("strtol");
						exit(EXIT_FAILURE);
					}

					if ( ( strlen( slash_ptr + 1 ) > 4 ) && ( ( strncmp( slash_ptr + 1 + strlen( slash_ptr + 1 ) - 4, "MBit", 4 ) == 0 ) || ( strncmp( slash_ptr + 1 + strlen( slash_ptr + 1 ) - 4, "mbit", 4 ) == 0 ) || ( strncmp( slash_ptr + 1 + strlen( slash_ptr + 1 ) - 4, "Mbit", 4 ) == 0 ) ) )
						upload_speed *= 1024;

					*slash_ptr = '/';

				}
				
				//gateway_class_opt = 1;
				req_opt = REQ_GW_CLASS;
				
				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;

			case 'H':
				verbose_usage();
				exit(EXIT_SUCCESS);
				
			case 'i':
				info_output++;
				break;

			case 'n':
				no_policy_routing = 1;
				found_args++;
				break;

			case 'o':

				errno = 0;
				my_ogi = strtol (optarg, NULL , 10 );

				if ( my_ogi < MIN_ORIGINATOR_INTERVAL || my_ogi > MAX_ORIGINATOR_INTERVAL ) {

					printf( "Invalid originator interval specified: %i.\n The value must be >= %i and <= %i.\n", my_ogi, MIN_ORIGINATOR_INTERVAL, MAX_ORIGINATOR_INTERVAL );

					exit(EXIT_FAILURE);
				}
				
				//ogi_opt = 1;
				req_opt = REQ_OGI;

				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;

			case 'p':

				errno = 0;

				if ( inet_pton( AF_INET, optarg, &tmp_ip_holder ) < 1 ) {

					printf( "Invalid preferred gateway IP specified: %s\n", optarg );
					exit(EXIT_FAILURE);

				}

				pref_gateway = tmp_ip_holder.s_addr;
				
				//pref_gw_opt = 1;
				req_opt = REQ_PREF_GW;


				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;

			case 'r':

				errno = 0;

				routing_class = strtol( optarg, NULL, 10 );

				if ( routing_class > 3 ) {

					printf( "Invalid routing class specified: %i.\nThe class is a value between 0 and 3.\n", routing_class );
					exit(EXIT_FAILURE);

				}
				
				//routing_class_opt = 1;
				req_opt = REQ_RT_CLASS;

				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;

			case 's':

				errno = 0;
				if ( inet_pton( AF_INET, optarg, &tmp_ip_holder ) < 1 ) {

					printf( "Invalid preferred visualation server IP specified: %s\n", optarg );
					exit(EXIT_FAILURE);

				}

				vis_server = tmp_ip_holder.s_addr;


				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;
			
			case 'v':

				printf( "BatMan-eXp %s%s (compatibility version %i)\n", SOURCE_VERSION, ( strncmp( REVISION_VERSION, "0", 1 ) != 0 ? REVISION_VERSION : "" ), COMPAT_VERSION );
				exit(EXIT_SUCCESS);

			case 'V':

				print_animation();

				printf( "\x1B[0;0HBatMan-eXp %s%s (compatibility version %i)\n", SOURCE_VERSION, ( strncmp( REVISION_VERSION, "0", 1 ) != 0 ? REVISION_VERSION : "" ), COMPAT_VERSION );
				printf( "\x1B[9;0H \t May the bat guide your path ...\n\n\n" );

				exit(EXIT_SUCCESS);

			case 'h':
				usage();
				exit(EXIT_SUCCESS);

			default:
				usage();
				exit(EXIT_FAILURE);

		}

		if ( conn_client && req_opt )
			break;
		
	}
	
	if (!conn_client && info_output) {

		internal_output(1);
		exit(EXIT_SUCCESS);

	}

	if ( ( download_speed > 0 ) && ( upload_speed == 0 ) )
		upload_speed = download_speed / 5;

	if ( download_speed > 0 ) {

		gateway_class = get_gw_class( download_speed, upload_speed );
		get_gw_speeds( gateway_class, &download_speed, &upload_speed );

	}


	if ( ( gateway_class != 0 ) && ( routing_class != 0 ) ) {
		fprintf( stderr, "Error - routing class can't be set while gateway class is in use !\n" );
		usage();
		exit(EXIT_FAILURE);
	}

	if ( ( gateway_class != 0 ) && ( pref_gateway != 0 ) ) {
		fprintf( stderr, "Error - preferred gateway can't be set while gateway class is in use !\n" );
		usage();
		exit(EXIT_FAILURE);
	}

	/* use routing class 1 if none specified */
	if ( ( routing_class == 0 ) && ( pref_gateway != 0 ) )
		routing_class = 1;

	if ( ( ( routing_class != 0 ) || ( gateway_class != 0 ) ) && ( !probe_tun(1) ) )
		exit(EXIT_FAILURE);

	/* this must be set for unix_clients and non-unix_clients */ 
	sprintf( unix_path, "%s.%d", DEF_UNIX_PATH, ogm_port);

	
	if ( !conn_client ) {

		if ( argc <= found_args ) {

			fprintf( stderr, "\nError - no interface specified !\n\n" );
			usage();
//			restore_defaults();
			exit(EXIT_FAILURE);

		}

		signal( SIGINT, handler );
		signal( SIGTERM, handler );
		signal( SIGPIPE, SIG_IGN );
		signal( SIGSEGV, segmentation_fault );

		debug_clients.fd_list = debugMalloc( sizeof(struct list_head_first *) * debug_level_max, 203 );
		debug_clients.mutex = debugMalloc( sizeof(pthread_mutex_t *) * debug_level_max, 209 );
		debug_clients.clients_num = debugMalloc( sizeof(int16_t) * debug_level_max, 209 );

		for ( res = 0; res < debug_level_max; res++ ) {

			debug_clients.fd_list[res] = debugMalloc( sizeof(struct list_head_first), 204 );
			((struct list_head_first *)debug_clients.fd_list[res])->next = debug_clients.fd_list[res];
			((struct list_head_first *)debug_clients.fd_list[res])->prev = debug_clients.fd_list[res];

			debug_clients.mutex[res] = debugMalloc( sizeof(pthread_mutex_t), 209 );
			pthread_mutex_init( (pthread_mutex_t *)debug_clients.mutex[res], NULL );

			debug_clients.clients_num[res] = 0;

		}

		if ( flush_routes_rules(0 /* flush routes */) < 0 ) {

			restore_defaults();
			exit(EXIT_FAILURE);

		}

		if ( !no_prio_rules ) {
			if ( flush_routes_rules(1 /* flush rules */) < 0 ) {
	
				restore_defaults();
				exit(EXIT_FAILURE);
	
			}
		}

		printf ("Causing duplicate-address-detection timeout %ds, purge timeout %ds, my originator interval %dms, my window size %d \n",
		  (((DEFAULT_ORIGINATOR_INTERVAL)*(my_ws)*(dad_timeout))/100000), MY_PURGE_TIMEOUT, my_ogi, my_ws );

		
		
		if ( initial_seqno == 0 )
			initial_seqno = rand_num( FULL_SEQ_RANGE - (10*my_ws) );
	


		while ( argc > found_args ) {

			batman_if = debugMalloc( sizeof(struct batman_if), 206 );
			memset( batman_if, 0, sizeof(struct batman_if) );
			INIT_LIST_HEAD( &batman_if->list );

			list_add_tail( &batman_if->list, &if_list );
			
			batman_if->dev = argv[found_args];
			batman_if->if_num = found_ifs;
			
			batman_if->out.ext_msg = NO;
			batman_if->out.bat_type = BAT_TYPE_OGM;
			batman_if->out.flags = 0x00;
			batman_if->out.size = 0x00;
			batman_if->out.ws     = my_ws;
			batman_if->out.seqno    = initial_seqno;

			batman_if->if_ttl_conf  = -1;
			batman_if->if_send_clones_conf  = -1;
			batman_if->send_ogm_only_via_owning_if_conf  = -1;
			batman_if->make_ip_hna_if_conf = -1;
			batman_if->dont_make_ip_hna_if_conf = -1;
					
			while ( argc > found_args && strlen( argv[found_args] ) >= 2 && *argv[found_args] == '/') {

				if ( (argv[found_args])[1] == TTL_IF_SWITCH && argc > (found_args+1) ) {

					errno = 0;
					uint8_t tmp = strtol ( argv[ found_args+1 ], NULL , 10 );
					//printf ("Interface %s specific option: /%c %d \n", batman_if->dev, ((argv[found_args])[1]), tmp );

					if ( tmp < MIN_TTL || tmp > MAX_TTL ) {

						printf( "Invalid ttl specified: %i.\nThe ttl must be >= %i and <= %i.\n", tmp, MIN_TTL, MAX_TTL );

						exit(EXIT_FAILURE);
					}

					batman_if->if_ttl_conf = tmp;

					found_args += 2;

				} else if ( (argv[found_args])[1] == CLONES_IF_SWITCH && argc > (found_args+1) ) {

					errno = 0;
					int16_t tmp = strtol ( argv[ found_args+1 ], NULL , 10 );
					//printf ("Interface %s specific option: /%c %d \n", batman_if->dev, ((argv[found_args])[1]), tmp );

					if ( tmp < MIN_WL_CLONES || tmp > MAX_WL_CLONES ) {

						printf( "Invalid /%c specified: %i.\n Value must be %i <= value <= %i.\n", 
								CLONES_IF_SWITCH, tmp, MIN_WL_CLONES, MAX_WL_CLONES );

						exit(EXIT_FAILURE);
					}

					batman_if->if_send_clones_conf = tmp;
					
					found_args += 2;

				
				} else if ( (argv[found_args])[1] == OGM_ONLY_VIA_OWNING_IF_SWITCH && argc > (found_args) ) {

					errno = 0;
					//printf ("Interface %s specific option: /%c  \n", batman_if->dev, ((argv[found_args])[1]) );

					batman_if->send_ogm_only_via_owning_if_conf = YES;
					batman_if->if_ttl_conf = 1;

					found_args += 1;

				
				} else if ( (argv[found_args])[1] == WLAN_IF_SWITCH && argc > (found_args) ) {

					errno = 0;
					//printf ("Interface %s specific option: /%c  \n", batman_if->dev, ((argv[found_args])[1]) );
					//printf (" applying %s specific option: /%c %d \n", batman_if->dev, SEND_CLONES_IF_SWITCH, DEF_WLAN_IF_CLONES );

					batman_if->if_send_clones_conf = wl_clones;

					found_args += 1;

				
				} else if ( (argv[found_args])[1] == LAN_IF_SWITCH && argc > (found_args) ) {

					errno = 0;
					//printf ("Interface %s specific option: /%c  \n", batman_if->dev, ((argv[found_args])[1]) );
					//printf (" applying %s specific option: /%c %d \n", batman_if->dev, SEND_CLONES_IF_SWITCH, DEF_LAN_IF_CLONES );

					batman_if->if_send_clones_conf = DEF_LAN_CLONES;

					found_args += 1;

				
				} else if ( (argv[found_args])[1] == MAKE_IP_HNA_IF_SWITCH && argc > (found_args) ) {

					//printf ("Interface %s specific option: /%c  \n", batman_if->dev, ((argv[found_args])[1]) );
					
					if ( batman_if->if_num > 0 ) {
					
						errno = 0;
						
						batman_if->make_ip_hna_if_conf = YES;

					} else {
						
						printf( "Never ever add the IP address of the first interface to the HNA list !!! \n" );
						exit(EXIT_FAILURE);
	
					}
					
					found_args += 1;

							
				} else if ( (argv[found_args])[1] == UNDO_IP_HNA_IF_SWITCH && argc > (found_args) ) {

					//printf ("Interface %s specific option: /%c  \n", batman_if->dev, ((argv[found_args])[1]) );
					
					errno = 0;
					
					batman_if->dont_make_ip_hna_if_conf = YES;
						
					found_args += 1;

							
				} else {
					
					printf( "Invalid interface specific option specified! \n" );
					exit(EXIT_FAILURE);
				
				}
			
			}

			
			init_interface ( batman_if );
						
			found_args++;
		
			
			if (batman_if->if_active) {

				addr_to_string(batman_if->addr.sin_addr.s_addr, str1, sizeof (str1));
				addr_to_string(batman_if->broad.sin_addr.s_addr, str2, sizeof (str2));

				printf("Using interface %s with address %s and broadcast address %s\n", batman_if->dev, str1, str2);

			} else {

				printf("Not using interface %s (retrying later): interface not active\n", batman_if->dev);

			}
			
			found_ifs++;
			
		}
		
		
		memset( my_pip_ext_array, 0, sizeof(struct ext_packet) );
		my_pip_ext_array->EXT_FIELD_MSG = YES;
		my_pip_ext_array->EXT_FIELD_TYPE = EXT_TYPE_PIP;
		my_pip_ext_array->EXT_PIP_FIELD_ADDR = (list_entry( (&if_list)->next, struct batman_if, list ))->addr.sin_addr.s_addr;
	
		if ( found_ifs > 1 ) 
			my_pip_ext_array_len = 1;
		else
			my_pip_ext_array_len = 0;

		
		unlink( unix_path );
		unix_if.unix_sock = socket( AF_LOCAL, SOCK_STREAM, 0 );

		memset( &unix_if.addr, 0, sizeof(struct sockaddr_un) );
		unix_if.addr.sun_family = AF_LOCAL;
		strcpy( unix_if.addr.sun_path, unix_path );

		if ( bind ( unix_if.unix_sock, (struct sockaddr *)&unix_if.addr, sizeof (struct sockaddr_un) ) < 0 ) {

			printf( "Error - can't bind unix socket '%s': %s\n", unix_path, strerror(errno) );
			restore_defaults();
			exit(EXIT_FAILURE);

		}

		if ( listen( unix_if.unix_sock, 10 ) < 0 ) {

			printf( "Error - can't listen unix socket '%s': %s\n", unix_path, strerror(errno) );
			restore_defaults();
			exit(EXIT_FAILURE);

		}

		/* daemonize */
		if ( debug_level == 0 ) {

			if ( my_daemon() < 0 ) {

				printf( "Error - can't fork to background: %s\n", strerror(errno) );
				restore_defaults();
				exit(EXIT_FAILURE);

			}

			openlog( "bmxd", LOG_PID, LOG_DAEMON );

		} else {
			printf( "BatMan-eXp %s%s (compatibility version %i)\n", SOURCE_VERSION, ( strncmp( REVISION_VERSION, "0", 1 ) != 0 ? REVISION_VERSION : "" ), COMPAT_VERSION );

			debug_clients.clients_num[ debug_level - 1 ]++;
			debug_level_info = debugMalloc( sizeof(struct debug_level_info), 205 );
			INIT_LIST_HEAD( &debug_level_info->list );
			debug_level_info->fd = 1;
			list_add( &debug_level_info->list, (struct list_head_first *)debug_clients.fd_list[debug_level - 1] );

		}

		pthread_create( &unix_if.listen_thread_id, NULL, &unix_listen, NULL );

		log_facility_active = YES;
		
		
		/* add rule for hosts and announced interfaces */
		if( !more_rules  &&  !no_prio_rules ) { 
		
			add_del_rule( 0, 0, BATMAN_RT_TABLE_INTERFACES, BATMAN_RT_PRIO_INTERFACES, 0, 1, 0 );
			add_del_rule( 0, 0, BATMAN_RT_TABLE_HOSTS, BATMAN_RT_PRIO_HOSTS, 0, 1, 0 );

		}

		/* add rule for hna networks */
		if( !no_prio_rules )
			add_del_rule( 0, 0, BATMAN_RT_TABLE_NETWORKS,   BATMAN_RT_PRIO_NETWORKS,   0, 1, 0 );

		/* add unreachable routing table entry */
		if( !no_unreachable_rule )
			add_del_route( 0, 0, 0, 0, 0, "unknown", BATMAN_RT_TABLE_UNREACH, 2, 0 );

		
		
		if ( add_del_interface_rules( 0, (routing_class > 0 ? YES : NO), YES ) < 0 ) {

			restore_defaults();
			exit(EXIT_FAILURE);

		}

		if ( routing_class > 0 ) {
			
			struct list_head *notun_pos;
			struct notun_node *notun_node;
			
			list_for_each(notun_pos, &notun_list) {
	
				notun_node = list_entry(notun_pos, struct notun_node, list);
		
				if ( notun_node->match_found == NO ) {
					addr_to_string( notun_node->addr, ifaddr_str, sizeof(ifaddr_str) );
					debug_output(0, "WARNING: NO interface found matching %s %s/%d \n", NO_TUNNEL_RULE_SWITCH, ifaddr_str, notun_node->netmask );
				}
			}
		}		

		
		memset( &vis_if, 0, sizeof(vis_if) );

		if ( vis_server ) {

			vis_if.addr.sin_family = AF_INET;
			vis_if.addr.sin_port = htons( vis_port );
			vis_if.addr.sin_addr.s_addr = vis_server;
			vis_if.sock = socket( PF_INET, SOCK_DGRAM, 0 );

		}

		if ( gateway_class != 0 )
			start_gw_service( );


		if ( debug_level > 0 ) {

			printf( "debug level: %i\n", debug_level );

			if ( my_ogi != DEFAULT_ORIGINATOR_INTERVAL )
				printf( "originator interval: %i\n", my_ogi );

			if ( gateway_class > 0 )
				printf( "gateway class: %i -> propagating: %i%s/%i%s\n", gateway_class, ( download_speed > 2048 ? download_speed / 1024 : download_speed ), ( download_speed > 2048 ? "MBit" : "KBit" ), ( upload_speed > 2048 ? upload_speed / 1024 : upload_speed ), ( upload_speed > 2048 ? "MBit" : "KBit" ) );

			if ( routing_class > 0 )
				printf( "routing class: %i\n", routing_class );

			if ( pref_gateway > 0 ) {
				addr_to_string( pref_gateway, str1, sizeof(str1) );
				printf( "preferred gateway: %s\n", str1 );
			}

			if ( vis_server > 0 ) {
				addr_to_string( vis_server, str1, sizeof(str1) );
				printf( "visualisation server: %s\n", str1 );
			}

		}

	/* connect to running batmand via unix socket */
	} else {

		unix_if.unix_sock = socket( AF_LOCAL, SOCK_STREAM, 0 );

		memset( &unix_if.addr, 0, sizeof(struct sockaddr_un) );
		unix_if.addr.sun_family = AF_LOCAL;
		strcpy( unix_if.addr.sun_path, unix_path );

		if ( connect ( unix_if.unix_sock, (struct sockaddr *)&unix_if.addr, sizeof(struct sockaddr_un) ) < 0 ) {

			printf( "Error - can't connect to unix socket '%s': %s ! Is batmand running on this host ?\n", unix_path, strerror(errno) );
			close( unix_if.unix_sock );
			exit(EXIT_FAILURE);

		}

		unix_buff = debugMalloc( MAX_UNIX_RCV_SIZE, 5001 );

		if ( debug_level > 0 ) {

			if ( debug_level <= debug_level_max ) {

				snprintf( unix_buff, MAX_UNIX_REQ_SIZE, "%c:%c", REQ_DEBUG, debug_level );

				if ( ( batch_mode ) && ( debug_level == DBGL_CHANGES || debug_level == DBGL_ALL || debug_level == DBGL_PROFILE ) )
					printf( "WARNING: Your chosen debug level (%i) does not support batch mode !\n", debug_level );

			}

		} else if ( req_opt == REQ_RT_CLASS ) {

			batch_mode = 1;
			snprintf( unix_buff, MAX_UNIX_REQ_SIZE, "%c:%c", REQ_RT_CLASS, routing_class );

		} else if ( req_opt == REQ_PREF_GW ) {

			batch_mode = 1;
			addr_to_string( pref_gateway, str1, sizeof(str1) );
			snprintf( unix_buff, MAX_UNIX_REQ_SIZE, "%c:%s", REQ_PREF_GW, str1 );

		} else if ( req_opt == REQ_GW_CLASS ) {

			batch_mode = 1;
			snprintf( unix_buff, MAX_UNIX_REQ_SIZE, "%c:%c", REQ_GW_CLASS, gateway_class );

		} else if ( req_opt == REQ_PWS ) {

			batch_mode = 1;
			snprintf( unix_buff, MAX_UNIX_REQ_SIZE, "%c:%c", REQ_PWS, my_ws );
		
		} else if ( req_opt == REQ_LWS ) {

			batch_mode = 1;
			snprintf( unix_buff, MAX_UNIX_REQ_SIZE, "%c:%c", REQ_LWS, bidirect_link_to );
		
		} else if ( req_opt == REQ_DTD ) {

			batch_mode = 1;
			snprintf( unix_buff, MAX_UNIX_REQ_SIZE, "%c:%c", REQ_DTD, dup_degrad );
		
		} else if ( req_opt == REQ_OGI ) {

			batch_mode = 1;
			snprintf( unix_buff, MAX_UNIX_REQ_SIZE, "%c:%d", REQ_OGI, my_ogi );
		
		} else if ( req_opt == REQ_1WT ) {

			batch_mode = 1;
			snprintf( unix_buff, MAX_UNIX_REQ_SIZE, "%c:%c", REQ_1WT, one_way_tunnel );
		
		} else if ( req_opt == REQ_2WT ) {

			batch_mode = 1;
			snprintf( unix_buff, MAX_UNIX_REQ_SIZE, "%c:%c", REQ_2WT, two_way_tunnel );
		
		} else if ( req_opt == REQ_FAKE_TIME ) {

			batch_mode = 1;
			snprintf( unix_buff, MAX_UNIX_REQ_SIZE, "%c:%d", REQ_FAKE_TIME, fake_uptime );
		
		} else if ( req_opt ==  REQ_CHANGE_HNA ) {

			hna_node = list_entry( (&my_hna_list)->next, struct hna_node, list );
			
			addr_to_string( hna_node->key.addr, str1, sizeof(str1) );
			printf(" sending %d:%d %-3d %u %s\n", REQ_CHANGE_HNA, hna_node->enabled, hna_node->key.KEY_FIELD_ANETMASK, hna_node->key.addr, str1 );
			
			snprintf( unix_buff, MAX_UNIX_REQ_SIZE, "%c:%d %-3d %u", REQ_CHANGE_HNA, hna_node->enabled, hna_node->key.KEY_FIELD_ANETMASK, hna_node->key.addr );
			
			batch_mode = 1;
			
			
		} else if ( req_opt == REQ_CHANGE_SRV ) {

			srv_node = list_entry( (&my_srv_list)->next, struct srv_node, list );
			
			addr_to_string( srv_node->srv_addr, str1, sizeof(str1) );
			printf(" sending %d:%d %-5d %-3d %u (%s)\n", REQ_CHANGE_SRV, srv_node->enabled, srv_node->srv_port, srv_node->srv_seqno, srv_node->srv_addr, str1 );
			
			snprintf( unix_buff, MAX_UNIX_REQ_SIZE, "%c:%d %-5d %-3d %u", REQ_CHANGE_SRV, srv_node->enabled, srv_node->srv_port, srv_node->srv_seqno, srv_node->srv_addr );
			
			batch_mode = 1;
			

		} else if ( info_output ) {

			batch_mode = 1;
			snprintf( unix_buff, MAX_UNIX_REQ_SIZE, "%c", REQ_INFO );

		} else {

			batch_mode = 1;
			snprintf( unix_buff, MAX_UNIX_REQ_SIZE, "%c", REQ_DEFAULT );

		}


		if ( write( unix_if.unix_sock, unix_buff, MAX_UNIX_REQ_SIZE ) < 0 ) {

			printf( "Error - can't write to unix socket: %s\n", strerror(errno) );
			close( unix_if.unix_sock );
			debugFree( unix_buff, 5101 );
			exit(EXIT_FAILURE);

		}

		while ( ( recv_buff_len = read( unix_if.unix_sock, unix_buff, 1500 ) ) > 0 ) {

			unix_buff[recv_buff_len] = '\0';

			buff_ptr = unix_buff;
			bytes_written = 0;

			while ( ( cr_ptr = strchr( buff_ptr, '\n' ) ) != NULL ) {

				*cr_ptr = '\0';

				if ( strncmp( buff_ptr, "EOD", 3 ) == 0 ) {

					if ( batch_mode ) {

						close( unix_if.unix_sock );
						debugFree( unix_buff, 5102 );
						exit(EXIT_SUCCESS);

					}

				} else if ( strncmp( buff_ptr, "BOD", 3 ) == 0 ) {

					if ( !batch_mode )
						system( "clear" );

				} else {

					printf( "%s\n", buff_ptr );

				}

				bytes_written += strlen( buff_ptr ) + 1;
				buff_ptr = cr_ptr + 1;

			}

			if ( bytes_written != recv_buff_len )
				printf( "%s", buff_ptr );

		}

		close( unix_if.unix_sock );
		debugFree( unix_buff, 5103 );

		if ( recv_buff_len < 0 ) {

			printf( "Error - can't read from unix socket: %s\n", strerror(errno) );
			exit(EXIT_FAILURE);

		} else {

			printf( "Connection terminated by remote host\n" );

		}

		exit(EXIT_SUCCESS);

	}

}


void interface_listen_sockets()
{
	struct list_head *list_pos;
	struct batman_if *batman_if;

	FD_ZERO(&receive_wait_set);
	receive_max_sock = 0;
	
	receive_max_sock = ifevent_sk;
	FD_SET(ifevent_sk, &receive_wait_set);
	
	list_for_each(list_pos, &if_list) {
		batman_if = list_entry(list_pos, struct batman_if, list);

		if (batman_if->if_active) {
			if (batman_if->udp_recv_sock > receive_max_sock)
				receive_max_sock = batman_if->udp_recv_sock;

			FD_SET(batman_if->udp_recv_sock, &receive_wait_set);
		}
	}
}

int is_interface_up(char *dev)
{
	struct ifreq int_req;
	int sock;

	if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
		return 0;

	memset(&int_req, 0, sizeof (struct ifreq));
	strncpy(int_req.ifr_name, dev, IFNAMSIZ - 1);

	if (ioctl(sock, SIOCGIFFLAGS, &int_req) < 0)
		goto failure;

	if (!(int_req.ifr_flags & IFF_UP))
		goto failure;

	if (ioctl(sock, SIOCGIFADDR, &int_req) < 0)
		goto failure;
	
	close (sock);
	return 1;

failure:
	close (sock);
	return 0;
	
}


void deactivate_interface( struct batman_if *batman_if ) {

	debug_output(3, "1 Deactivating interface: %s\n", batman_if->dev);
	
	if (batman_if->udp_recv_sock != 0)
		close(batman_if->udp_recv_sock);

	if (batman_if->udp_send_sock != 0)
		close(batman_if->udp_send_sock);

	batman_if->udp_recv_sock = 0;
	batman_if->udp_send_sock = 0;

	if ( more_rules ) {

		if ( ( batman_if->netaddr > 0 ) && ( batman_if->netmask > 0 ) ) {

			if( !no_prio_rules ) {
			
				add_del_rule( batman_if->netaddr, batman_if->netmask, BATMAN_RT_TABLE_INTERFACES, BATMAN_RT_PRIO_INTERFACES + batman_if->if_num, 0, 1, 1 );
				add_del_rule( batman_if->netaddr, batman_if->netmask, BATMAN_RT_TABLE_HOSTS, BATMAN_RT_PRIO_HOSTS + batman_if->if_num, 0, 1, 1 );
				
			}
			
			if ( !no_unreachable_rule )
				add_del_rule( batman_if->netaddr, batman_if->netmask, BATMAN_RT_TABLE_UNREACH, BATMAN_RT_PRIO_UNREACH + batman_if->if_num, 0, 1, 1 );
		
		}
		
	}
	
	
	
	batman_if->if_active = 0;
	active_ifs--;

	if (batman_if->if_rp_filter_old > -1)
		set_rp_filter(batman_if->if_rp_filter_old, batman_if->dev);

	if (batman_if->if_send_redirects_old > -1)
		set_send_redirects(batman_if->if_send_redirects_old, batman_if->dev);

	batman_if->if_rp_filter_old = -1;
	batman_if->if_send_redirects_old = -1;

	
	interface_listen_sockets();
	debug_output(3, "Interface deactivated: %s\n", batman_if->dev);
}

void activate_interface(struct batman_if *batman_if)
{
	struct ifreq int_req;
	int on = 1, sock_opts;
	char fake_arg[ADDR_STR_LEN + 4], ifaddr_str[ADDR_STR_LEN];


	if ( ( batman_if->udp_recv_sock = socket( PF_INET, SOCK_DGRAM, 0 ) ) < 0 ) {

		debug_output(3, "Error - can't create receive socket: %s\n", strerror(errno) );
		goto error;

	}

	memset( &int_req, 0, sizeof (struct ifreq) );
	strncpy( int_req.ifr_name, batman_if->dev, IFNAMSIZ - 1 );

	if ( ioctl( batman_if->udp_recv_sock, SIOCGIFADDR, &int_req ) < 0 ) {

		debug_output(3, "Error - can't get IP address of interface %s: %s\n", batman_if->dev, strerror(errno) );
		goto error;

	}

	batman_if->addr.sin_family = AF_INET;
	batman_if->addr.sin_port = htons(ogm_port);
	batman_if->addr.sin_addr.s_addr = ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr;

	if (batman_if->addr.sin_addr.s_addr == 0) {

		debug_output(3, "Error - invalid ip address detected (0.0.0.0): %s\n", batman_if->dev);
		goto error;

	}

	if ( ioctl( batman_if->udp_recv_sock, SIOCGIFBRDADDR, &int_req ) < 0 ) {

		debug_output(3, "Error - can't get broadcast IP address of interface %s: %s\n", batman_if->dev, strerror(errno) );
		goto error;

	}

	batman_if->broad.sin_family = AF_INET;
	batman_if->broad.sin_port = htons(ogm_port);
	batman_if->broad.sin_addr.s_addr = ((struct sockaddr_in *)&int_req.ifr_broadaddr)->sin_addr.s_addr;

	if ( batman_if->broad.sin_addr.s_addr == 0 ) {

		debug_output(3, "Error - invalid broadcast address detected (0.0.0.0): %s\n", batman_if->dev );
		goto error;

	}


#ifdef __linux__
	/* The SIOCGIFINDEX ioctl is Linux specific, but I am not yet sure if the
	* equivalent exists on *BSD. There is a function called if_nametoindex()
	* on both Linux and BSD.
	* Maybe it does the same as this code and we can simply call it instead?
	* --stsp
	*/
	if ( ioctl( batman_if->udp_recv_sock, SIOCGIFINDEX, &int_req ) < 0 ) {

		debug_output(3, "Error - can't get index of interface %s: %s\n", batman_if->dev, strerror(errno) );
		goto error;

	}

	batman_if->if_index = int_req.ifr_ifindex;
#else
	batman_if->if_index = 0;
#endif

	if ( ioctl( batman_if->udp_recv_sock, SIOCGIFNETMASK, &int_req ) < 0 ) {

		debug_output(3, "Error - can't get netmask address of interface %s: %s\n", batman_if->dev, strerror(errno) );
		goto error;

	}

	batman_if->netaddr = ( ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr & batman_if->addr.sin_addr.s_addr );
	batman_if->netmask = bit_count( ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr );

	/* check if interface is a wireless interface */

	if (  (batman_if->is_wlan = (ioctl( batman_if->udp_recv_sock, SIOCGIWNAME, &int_req ) < 0 ? NO : YES ))  )
		printf( "Detected wireless interface %s  (use %s /l to correct this assumption) !\n", batman_if->dev, batman_if->dev);
	else 
		printf( "Detected non-wireless interface %s  (use %s /w to correct this assumption) !\n", batman_if->dev, batman_if->dev);
	
	
	if ( more_rules ) {

		if( !no_prio_rules ) {
			
			// use 0,0 instead of batman_if->netaddr, batman_if->netmask to find also batman nodes with different netmasks
			add_del_rule( batman_if->netaddr, batman_if->netmask, BATMAN_RT_TABLE_INTERFACES, BATMAN_RT_PRIO_INTERFACES + batman_if->if_num, 0, 1, 0 );
			add_del_rule( batman_if->netaddr, batman_if->netmask, BATMAN_RT_TABLE_HOSTS, BATMAN_RT_PRIO_HOSTS + batman_if->if_num, 0, 1, 0 );
		}
		
		if ( !no_unreachable_rule )
			add_del_rule( batman_if->netaddr, batman_if->netmask, BATMAN_RT_TABLE_UNREACH, BATMAN_RT_PRIO_UNREACH + batman_if->if_num, 0, 1, 0 );
			
	}



	if ( ( batman_if->udp_send_sock = socket( PF_INET, SOCK_DGRAM, 0 ) ) < 0 ) {

		debug_output(3, "Error - can't create send socket: %s\n", strerror(errno) );
		goto error;

	}

	if ( setsockopt( batman_if->udp_send_sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on) ) < 0 ) {

		debug_output(3, "Error - can't enable broadcasts: %s\n", strerror(errno) );
		goto error;

	}

	// bind send socket to interface name
	if ( bind_to_iface( batman_if->udp_send_sock, batman_if->dev ) < 0 ) {

		debug_output(3, "Cannot bind socket to device %s : %s \n", batman_if->dev, strerror(errno));
		goto error;

	}
	
	// bind send socket to address 
	if ( bind( batman_if->udp_send_sock, (struct sockaddr *)&batman_if->addr, sizeof(struct sockaddr_in) ) < 0 ) {

		debug_output(3, "Error - can't bind send socket: %s\n", strerror(errno) );
		goto error;

	}

	// make udp send socket non blocking
	sock_opts = fcntl(batman_if->udp_send_sock, F_GETFL, 0);
	fcntl(batman_if->udp_send_sock, F_SETFL, sock_opts | O_NONBLOCK);

	
	// bind recv socket to interface name
	if ( bind_to_iface( batman_if->udp_recv_sock, batman_if->dev ) < 0 ) {

		debug_output(3, "Cannot bind socket to device %s : %s \n", batman_if->dev, strerror(errno));
		goto error;

	}

	// bind recv socket to address 
	if ( bind( batman_if->udp_recv_sock, (struct sockaddr *)&batman_if->broad, sizeof(struct sockaddr_in) ) < 0 ) {

		debug_output(3, "Error - can't bind receive socket: %s\n", strerror(errno));
		goto error;

	}

	
	batman_if->if_rp_filter_old = get_rp_filter(batman_if->dev);
	set_rp_filter(0, batman_if->dev);

	batman_if->if_send_redirects_old = get_send_redirects(batman_if->dev);
	set_send_redirects(0, batman_if->dev);

	
	//apply default values
	batman_if->if_ttl = ttl;
	batman_if->if_send_clones = wl_clones;
	batman_if->packet_out_len = sizeof( struct bat_header );

	//apply interface specific parametrization sets	
	if( default_para_set == PARA_SET_BMX || default_para_set == PARA_SET_GRAZ07 ) {
				
		if ( batman_if->if_num != 0 ) {
			
			errno = 0;
						
			addr_to_string( batman_if->addr.sin_addr.s_addr, ifaddr_str, sizeof(ifaddr_str) );
			sprintf( fake_arg, "%s/32", ifaddr_str);
			prepare_add_del_own_hna( fake_arg, NO, A_TYPE_INTERFACE );
						
			batman_if->send_ogm_only_via_owning_if = YES;
			batman_if->if_ttl = 1;

		}
					
				
		if( !batman_if->is_wlan )
			batman_if->if_send_clones = DEF_LAN_CLONES;
				
	}
	
	
	//apply interface specific parametrizations:
	
	if ( batman_if->make_ip_hna_if_conf != -1  &&  batman_if->if_num != 0 ) {
		addr_to_string( batman_if->addr.sin_addr.s_addr, ifaddr_str, sizeof(ifaddr_str) );
		sprintf( fake_arg, "%s/32", ifaddr_str);
		prepare_add_del_own_hna( fake_arg, NO, A_TYPE_INTERFACE );
		
		batman_if->send_ogm_only_via_owning_if = YES;
		batman_if->if_ttl = 1;
	}
	
	if ( batman_if->dont_make_ip_hna_if_conf != -1  &&  batman_if->if_num != 0 ) {
		addr_to_string( batman_if->addr.sin_addr.s_addr, ifaddr_str, sizeof(ifaddr_str) );
		sprintf( fake_arg, "%s/32", ifaddr_str);
		prepare_add_del_own_hna( fake_arg, YES, A_TYPE_INTERFACE );
		
		batman_if->send_ogm_only_via_owning_if_conf = NO;
		batman_if->if_ttl_conf = ttl;
	}
	
	if ( batman_if->if_ttl_conf != -1 )
		batman_if->if_ttl = batman_if->if_ttl_conf;
	
	if ( batman_if->if_send_clones_conf != -1 )
		batman_if->if_send_clones =  batman_if->if_send_clones_conf;
	
	if ( batman_if->send_ogm_only_via_owning_if_conf  != -1 )
		batman_if->send_ogm_only_via_owning_if = batman_if->send_ogm_only_via_owning_if_conf;
	
	
	//prepare originator
	batman_if->out.ttl = batman_if->if_ttl;
	batman_if->out.orig = batman_if->addr.sin_addr.s_addr;
	
	
	//prepare extenson messages:
	my_pip_ext_array->EXT_PIP_FIELD_ADDR = (list_entry( (&if_list)->next, struct batman_if, list ))->addr.sin_addr.s_addr;


	batman_if->if_active = 1;
	active_ifs++;

	//activate selector for active interfaces
	interface_listen_sockets();
	
//	add_del_own_hna( NO /*do not purge*/ );
	
	debug_output(3, "Interface activated: %s\n", batman_if->dev);

	
	
	return;

error:
	deactivate_interface( batman_if );
	
}

void init_interface(struct batman_if *batman_if)
{
	if (strlen( batman_if->dev ) > IFNAMSIZ - 1) {
		printf("Error - interface name too long: %s\n", batman_if->dev);
		restore_defaults();
		exit(EXIT_FAILURE);
	}

	if (is_interface_up(batman_if->dev))
		activate_interface(batman_if);
}


void check_interfaces() {
	
	struct list_head *list_pos;
	struct batman_if *batman_if;
	uint8_t purge_origs = NO;
	char fake_arg[ADDR_STR_LEN + 12], ifaddr_str[ADDR_STR_LEN];


	list_for_each(list_pos, &if_list) {
		
		int deactivate_if = NO;

		batman_if = list_entry(list_pos, struct batman_if, list);

		if ((!batman_if->if_active) && (is_interface_up(batman_if->dev))) {
			
			debug_output( 0, "WARNING: Detected active but unused interface:%s ! Going to activate\n", batman_if->dev );
			activate_interface(batman_if);
			add_del_own_hna( NO  /*do not purge*/ );
			
			if( batman_if->if_num == 0  &&  batman_if->if_active  &&  gateway_class  &&  (one_way_tunnel || two_way_tunnel)  &&  probe_tun(0) )
				start_gw_service();
		
		} else if ((batman_if->if_active) && (!is_interface_up(batman_if->dev))) {
			
			debug_output( 0, "WARNING: Detected inactive but used interface:%s ! Going to deactivate.. \n", batman_if->dev );
			deactivate_if = YES;

		/* Interface properties might have changed */
		} else if ((batman_if->if_active) && (is_interface_up(batman_if->dev))) {
			
			struct ifreq int_req;

			memset( &int_req, 0, sizeof (struct ifreq) );
			strncpy( int_req.ifr_name, batman_if->dev, IFNAMSIZ - 1 );

			if ( ioctl( batman_if->udp_recv_sock, SIOCGIFADDR, &int_req ) < 0 ) {

				debug_output(0, "WARNING: can't get IP address of interface %s: %s\n", batman_if->dev, strerror(errno) );
				deactivate_if = YES;

			} else if ( batman_if->addr.sin_addr.s_addr != ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr ) {
				
				debug_output(0, "WARNING: IP address of interface %s: changed !!\n", batman_if->dev );
				deactivate_if = YES;
				
			} else if ( ioctl( batman_if->udp_recv_sock, SIOCGIFBRDADDR, &int_req ) < 0 ) {

				debug_output(0, "WARNING: Can't get broadcast IP address of interface %s: %s\n", batman_if->dev, strerror(errno) );
				deactivate_if = YES;

			} else if ( batman_if->broad.sin_addr.s_addr != ((struct sockaddr_in *)&int_req.ifr_broadaddr)->sin_addr.s_addr ) {

				debug_output(0, "WARNING: Broadcast address of  interface %s changed \n", batman_if->dev );
				deactivate_if = YES;

			} else if ( ioctl( batman_if->udp_recv_sock, SIOCGIFNETMASK, &int_req ) < 0 ) {

				debug_output(0, "WARNING: can't get netmask address of interface %s: %s\n", batman_if->dev, strerror(errno) );
				deactivate_if = YES;

			} else if ( batman_if->netaddr != ( ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr & batman_if->addr.sin_addr.s_addr ) ) {
				 
				debug_output(0, "WARNING: Net address of  interface %s changed \n", batman_if->dev );
				deactivate_if = YES;
			
			} else if ( batman_if->netmask != bit_count( ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr ) ) {
				
				debug_output(0, "WARNING: Netmask address of  interface %s changed \n", batman_if->dev );
				deactivate_if = YES;
			
			}

		}
		
		if ( deactivate_if ) {
				
			purge_origs = YES;
			
			deactivate_interface( batman_if );
			
			if ( batman_if->if_num != 0 ) {
				
				addr_to_string( batman_if->addr.sin_addr.s_addr, ifaddr_str, sizeof(ifaddr_str) );
				sprintf( fake_arg, "%s/32", ifaddr_str);
				prepare_add_del_own_hna( fake_arg, YES, A_TYPE_INTERFACE );
				add_del_own_hna( NO );	
		
			}
				
			debug_output( 0, "WARNING: Interface %s deactivated \n", batman_if->dev );
		}
	
	}
	
	if ( purge_origs ) {
		
		// if there is a gw-client thread: stop it now, it restarts automatically
		del_default_route(); 
									
		// if there is a gw thread: stop it now
		stop_gw_service();
									
		purge_orig( 0 );
		
		if ( gateway_class  &&  (one_way_tunnel || two_way_tunnel)  &&  probe_tun(0) )
			start_gw_service();

	}
		
}





void stop_gw_service ( void ) {
	
	my_gw_ext_array_len = 0;
	memset( my_gw_ext_array, 0, sizeof(struct ext_packet) );

	gw_thread_finish = YES;
	
	if ( gw_thread_id > 0 ) {
		pthread_join( gw_thread_id, NULL );
		gw_thread_id = 0;
	}
	
	gw_thread_finish = NO;
	
}



void start_gw_service ( void ) {

	int32_t sock_opts;
	struct gw_listen_arg *gw_listen_arg;
	struct sockaddr_in addr;

	
	debug_output( 3, "start_gw_service () \n");
	
	// join old thread if not already done
	stop_gw_service();

	if (!( gw_thread_id == 0  &&  gateway_class  &&  ( two_way_tunnel || one_way_tunnel ) &&  (list_entry( (&if_list)->next, struct batman_if, list ))->if_active ) )
		return;
	
	/* TODO: This needs a better security concept...
	if ( my_gw_port == 0 ) */
		my_gw_port = ogm_port + 1;
	
	/* TODO: This needs a better security concept...
	if ( my_gw_addr == 0 ) */
		my_gw_addr = (list_entry( (&if_list)->next, struct batman_if, list ))->addr.sin_addr.s_addr ;
			

	
	memset( my_gw_ext_array, 0, sizeof(struct ext_packet) );
		
	my_gw_ext_array->EXT_FIELD_MSG  = YES;
	my_gw_ext_array->EXT_FIELD_TYPE = EXT_TYPE_GW;
	
	my_gw_ext_array->EXT_GW_FIELD_GWFLAGS = ( ( two_way_tunnel || one_way_tunnel ) ? gateway_class : 0 );
	my_gw_ext_array->EXT_GW_FIELD_GWTYPES = ( gateway_class ? ( (two_way_tunnel?TWO_WAY_TUNNEL_FLAG:0) | (one_way_tunnel?ONE_WAY_TUNNEL_FLAG:0) ) : 0);
	
	my_gw_ext_array->EXT_GW_FIELD_GWPORT = htons( my_gw_port );
	my_gw_ext_array->EXT_GW_FIELD_GWADDR = my_gw_addr;
	
	my_gw_ext_array_len = 1;
	
	
	gw_listen_arg = debugMalloc( sizeof( struct gw_listen_arg ), 223 );
	
	memset( gw_listen_arg, 0, sizeof( struct gw_listen_arg ) );

	gw_listen_arg->prefix = gw_tunnel_prefix;
	gw_listen_arg->netmask = gw_tunnel_netmask;
	gw_listen_arg->port = my_gw_port;
	gw_listen_arg->owt = one_way_tunnel;
	gw_listen_arg->twt = two_way_tunnel;
	gw_listen_arg->lease_time = tunnel_ip_lease_time;
	
	
	if( (gw_listen_arg->gw_client_list = debugMalloc( (0xFFFFFFFF>>gw_tunnel_netmask) * sizeof( struct gw_client* ), 210 ) ) == NULL ) {
	
		debug_output( 0, "Error - start_gw_service(): could not allocate memory for gw_client_list \n");
		restore_defaults();
		exit(EXIT_FAILURE);
	}
	
/*	
	for( i=0; i<(0xFFFFFFFF>>gw_tunnel_netmask); i++) {
		//debug_output( 3, "resetting %d at %ld\n", i, gw_listen_arg.gw_client_list[i]);
		gw_listen_arg->gw_client_list[i] = NULL;
	}
*/
	memset( gw_listen_arg->gw_client_list, 0, (0xFFFFFFFF>>gw_tunnel_netmask) * sizeof( struct gw_client* ) );

	gw_listen_arg->sock = socket( PF_INET, SOCK_DGRAM, 0 );

	if ( gw_listen_arg->sock < 0 ) {

		debug_output( 0, "Error - can't create tunnel socket: %s", strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);

	}

	memset( &addr, 0, sizeof( struct sockaddr_in ) );
	addr.sin_family = AF_INET;
	addr.sin_port = htons( my_gw_port );
	addr.sin_addr.s_addr = (list_entry( (&if_list)->next, struct batman_if, list ))->addr.sin_addr.s_addr;
	
	if ( bind( gw_listen_arg->sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in) ) < 0 ) {

		debug_output( 0, "Error - can't bind tunnel socket: %s\n", strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);

	}

	/* make udp socket non blocking */
	sock_opts = fcntl( gw_listen_arg->sock, F_GETFL, 0 );
	fcntl( gw_listen_arg->sock, F_SETFL, sock_opts | O_NONBLOCK );

	pthread_create( &gw_thread_id, NULL, &gw_listen, gw_listen_arg );

}


