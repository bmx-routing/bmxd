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
#include "../batman.h"

#define IOCSETDEV 1

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
	int16_t tmp = strtol (switch_arg, NULL , 10);

	printf ("--%s", switch_name );
	if (switch_arg)
		printf (" %d", tmp );
	printf (" \\ \n");
	
	if ( tmp < min || tmp > max ) {

		printf( "Invalid --%s value specified: %i ! Value must be %i <= <value> <= %i !\n", switch_name, tmp, min, max );

		exit(EXIT_FAILURE);
	}

	*target_value = tmp;
	return;
}


void set_gw_network ( char *optarg_str ) {
	
	struct in_addr tmp_ip_holder;
	uint16_t netmask;
	char *slash_ptr;
	static char netmask_str[ADDR_STR_LEN];
		
	
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

	if ( netmask != 16 || netmask < 1 || netmask > 32) {

		*slash_ptr = '/';
		printf( "Invalid GW network (netmask is invalid): %s ! Sorry, currently only /16 networks are supported!\n", optarg_str );
		exit(EXIT_FAILURE);

	}

	gw_tunnel_prefix  = tmp_ip_holder.s_addr;
	gw_tunnel_netmask = netmask;
	
	addr_to_string( gw_tunnel_prefix, netmask_str, ADDR_STR_LEN );
	printf("Setting GW-tunnel-network to (%X) %s/%i  -- %i.%i.%i.%i\n",gw_tunnel_prefix, netmask_str, netmask, 
		((uint8_t*)&gw_tunnel_prefix)[0],
		((uint8_t*)&gw_tunnel_prefix)[1],
		((uint8_t*)&gw_tunnel_prefix)[2],
		((uint8_t*)&gw_tunnel_prefix)[3]
	      );
	
	*slash_ptr = '/';
	
}


void add_del_hna_opt ( char *optarg_str, int8_t del ) {
	
	struct hna_node *hna_node;
	struct in_addr tmp_ip_holder;
	uint16_t netmask;
//	char str1[17];
	char *slash_ptr;
	struct list_head *hna_list_pos, *prev_hna_list_head, *hna_pos_tmp;
	char str[16];
			
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
		

	if ( del ) {
		
		prev_hna_list_head = (struct list_head *)&hna_list;
		
		list_for_each_safe( hna_list_pos, hna_pos_tmp, &hna_list ) {

			hna_node = list_entry( hna_list_pos, struct hna_node, list );

			if ( hna_node->addr == tmp_ip_holder.s_addr && hna_node->netmask == netmask ) {
				
				addr_to_string( hna_node->addr, str, sizeof (str) );
				printf( "removing HNA %s/%i \n", str, hna_node->netmask );
				
				list_del( prev_hna_list_head, hna_list_pos, &hna_list );
				debugFree( hna_node, 1103 );	
			
			} else {
				
				prev_hna_list_head = &hna_node->list;
				
			}

		}

		
	} else {
		
		hna_node = debugMalloc( sizeof(struct hna_node), 203 );
		memset( hna_node, 0, sizeof(struct hna_node) );
		INIT_LIST_HEAD( &hna_node->list );
	
		hna_node->addr = tmp_ip_holder.s_addr;
		hna_node->netmask = netmask;
		
		addr_to_string( hna_node->addr, str, sizeof (str) );
		printf( "adding HNA %s/%i \n", str, hna_node->netmask );
	
		list_add_tail( &hna_node->list, &hna_list );

	}
	*slash_ptr = '/';
	
}

void apply_init_args( int argc, char *argv[] ) {

	struct in_addr tmp_ip_holder;
	struct batman_if *batman_if;
//	struct hna_node *hna_node;
	struct debug_level_info *debug_level_info;
	struct list_head *list_pos;
	uint8_t found_args = 1, batch_mode = 0, apply_default_paras_and_break = NO;
//	uint16_t netmask;
	int8_t res;

	int32_t optchar, recv_buff_len, bytes_written, download_speed = 0, upload_speed = 0;
	char str1[16], str2[16], *slash_ptr, *unix_buff, *buff_ptr, *cr_ptr;
	char routing_class_opt = 0, gateway_class_opt = 0, pref_gw_opt = 0;
	uint32_t vis_server = 0;


	memset( &tmp_ip_holder, 0, sizeof (struct in_addr) );
	stop = 0;
	prog_name = argv[0];
	sprintf( unix_path, "%s.%d", DEF_UNIX_PATH, base_port);



	printf( "WARNING: You are using the experimental batman branch!\n" );

	while ( 1 ) {

		int32_t option_index = 0;
		static struct option long_options[] =
		{
   {ADVANCED_SWITCH,            0, 0, 0},
   {GENIII_DEFAULTS_SWITCH,     0, 0, 0},
   {BMX_DEFAULTS_SWITCH,        0, 0, 0},
   {GRAZ07_DEFAULTS_SWITCH,     0, 0, 0},
   {BIDIRECT_TIMEOUT_SWITCH,    1, 0, 0},
   {NBRFSIZE_SWITCH,            1, 0, 0},
   {GW_CHANGE_HYSTERESIS_SWITCH,1, 0, 0},
   {GW_TUNNEL_NETW_SWITCH,      1, 0, 0},
   {TTL_SWITCH,                 1, 0, 0},
   {ASOCIAL_SWITCH,             0, 0, 0},
   {NO_UNREACHABLE_RULE_SWITCH, 0, 0, 0},
   {NO_TUNPERSIST_SWITCH,       0, 0, 0},
   {RT_PRIO_DEFAULT_SWITCH,     1, 0, 0},
   {NO_PRIO_RULES_SWITCH,       0, 0, 0},
   {NO_THROW_RULES_SWITCH,      0, 0, 0},
   {NO_UNRESP_CHECK_SWITCH,     0, 0, 0},
   {RESIST_BLOCKED_SEND_SWITCH, 0, 0, 0},
   {RT_TABLE_OFFSET_SWITCH,     1, 0, 0},
   {BASE_PORT_SWITCH,           1, 0, 0},
   {TEST_SWITCH,                0, 0, 0},
   {DUP_TTL_LIMIT_SWITCH,       1, 0, 0},
   {DUP_RATE_SWITCH,	        1, 0, 0},
   {DUP_DEGRAD_SWITCH,	        1, 0, 0},
   {SEND_CLONES_SWITCH,         1, 0, 0},
   {ASYMMETRIC_WEIGHT_SWITCH,   1, 0, 0},
   {ASYMMETRIC_EXP_SWITCH,      1, 0, 0},
   {REBRC_DELAY_SWITCH,         1, 0, 0},
   {PENALTY_MIN_SWITCH,         1, 0, 0},
   {PENALTY_EXCEED_SWITCH,      1, 0, 0},
   {0, 0, 0, 0}
		};

		apply_default_paras_and_break = NO;
		
		if ( ( optchar = getopt_long ( argc, argv, "a:bcmd:hHo:l:q:t:g:p:r:s:vV", long_options, &option_index ) ) == -1 ) {
			
			if ( found_args == 1 ) {
						
				apply_default_paras_and_break = YES;
		
			} else {
				break;
			}
		}
		
//		printf(" found_args: %i, optchar %c \n", found_args, optchar );
		
		if ( apply_default_paras_and_break || 
				   ( found_args == 1 && optchar != 0 && optchar != 'c' && optchar != '?' && optchar != 'v' && optchar != 'h' && optchar != 'H') || 
				   ( found_args == 1 && optchar == 0 &&  
				     strcmp( ADVANCED_SWITCH, long_options[option_index].name ) != 0 &&
				     strcmp( GRAZ07_DEFAULTS_SWITCH, long_options[option_index].name ) != 0 &&
				     strcmp( GENIII_DEFAULTS_SWITCH, long_options[option_index].name ) != 0 ) || 
				   ( optchar == 0 && strcmp( BMX_DEFAULTS_SWITCH, long_options[option_index].name ) == 0 ) ) {

			
			printf ("Applying %s ! \nThis parametrization expects the first given interface argument to be a wireless interface !\n", BMX_DEFAULTS_SWITCH );
	
			errno = 0;
	
			if ( found_args == 1 ) {
				default_para_set = PARA_SET_BMX;
					
			} else {
				printf( "Error - Parametrization set can only be specified once !\n" );
				exit(EXIT_FAILURE);
			}
						
	
			originator_interval = 1500;
			printf ("-o %d \\ \n", originator_interval );
	
					//set_init_arg( BASE_PORT_SWITCH, "4305", MIN_BASE_PORT, MAX_BASE_PORT, &base_port );
					//sprintf( unix_path, "%s.%d", DEF_UNIX_PATH, base_port);
	
			set_init_arg( BIDIRECT_TIMEOUT_SWITCH, "20", MIN_BIDIRECT_TIMEOUT, MAX_BIDIRECT_TIMEOUT, &bidirect_link_to );
	
			set_init_arg( NBRFSIZE_SWITCH, "100", MIN_SEQ_RANGE, MAX_SEQ_RANGE, &sequence_range );
			num_words = ( sequence_range / WORD_BIT_SIZE ) + ( ( sequence_range % WORD_BIT_SIZE > 0)? 1 : 0 );
	
			set_init_arg( GW_CHANGE_HYSTERESIS_SWITCH, "2", MIN_GW_CHANGE_HYSTERESIS, MAX_GW_CHANGE_HYSTERESIS, &gw_change_hysteresis ); 
	
			set_init_arg( DUP_TTL_LIMIT_SWITCH, "2", MIN_DUP_TTL_LIMIT, MAX_DUP_TTL_LIMIT, &dup_ttl_limit );
	
			set_init_arg( DUP_RATE_SWITCH, "99", MIN_DUP_RATE, MAX_DUP_RATE, &dup_rate );
	
			set_init_arg( DUP_DEGRAD_SWITCH, "2", MIN_DUP_DEGRAD, MAX_DUP_DEGRAD, &dup_degrad );
	
			set_init_arg( SEND_CLONES_SWITCH, "200", MIN_SEND_CLONES, MAX_SEND_CLONES, &send_clones );
					//compat_version = DEF_COMPAT_VERSION + 1;
	
			set_init_arg( ASYMMETRIC_WEIGHT_SWITCH, "100", MIN_ASYMMETRIC_WEIGHT, MAX_ASYMMETRIC_WEIGHT, &asymmetric_weight );
	
			set_init_arg( ASYMMETRIC_EXP_SWITCH, "1", MIN_ASYMMETRIC_EXP, MAX_ASYMMETRIC_EXP, &asymmetric_exp );
	
			set_init_arg( REBRC_DELAY_SWITCH, "35", MIN_REBRC_DELAY, MAX_REBRC_DELAY, &rebrc_delay );
	
			
			if ( strcmp( BMX_DEFAULTS_SWITCH, long_options[option_index].name ) == 0 ) {
				found_args += 1;
				continue;
			}
			
			if ( apply_default_paras_and_break ) {
				break;
			}
			
		}

		switch ( optchar ) {

			case 0: {
				
				if( strcmp( ADVANCED_SWITCH, long_options[option_index].name ) == 0 ) {
	
					errno = 0;
					
					verbose_usage();
					print_advanced_opts( YES /*verbose*/ );
					exit(EXIT_SUCCESS);

				} else if ( strcmp( GENIII_DEFAULTS_SWITCH, long_options[option_index].name ) == 0 ) {

					printf ("Applying %s ! \nThis parametrization causes the same behavior as implemented in batmand-0.2 !\n", long_options[option_index].name);
	
					errno = 0;
	
					if ( found_args == 1 /*default_para_set == DEF_BMX_PARA_SET || default_para_set == PARA_SET_GENIII */ ) {
						default_para_set = PARA_SET_GENIII;
	
					} else {
						printf( "Error - Parametrization set can only be specified once !\n" );
						exit(EXIT_FAILURE);
					}

					found_args += 1;
					break;

				} else if ( strcmp( GRAZ07_DEFAULTS_SWITCH, long_options[option_index].name ) == 0 ) {

					printf ("Applying %s ! \nThis parametrization expects the first given interface argument to be a wireless interface !\n", long_options[option_index].name);
					printf ("Parametrization based on experience gained from the Wireless Community Weekend in Graz 2007!\n");
					errno = 0;
	
					if ( found_args == 1 /*default_para_set == DEF_BMX_PARA_SET || default_para_set == PARA_SET_GRAZ07*/ ) {
						default_para_set = PARA_SET_GRAZ07;
					} else {
						printf( "Error - Parametrization set can only be specified once !\n" );
						exit(EXIT_FAILURE);
					}
	
					originator_interval = 1500;
					printf ("-o %d \\ \n", originator_interval );
	
					set_init_arg( BIDIRECT_TIMEOUT_SWITCH, "20", MIN_BIDIRECT_TIMEOUT, MAX_BIDIRECT_TIMEOUT, &bidirect_link_to );
	
					set_init_arg( NBRFSIZE_SWITCH, "100", MIN_SEQ_RANGE, MAX_SEQ_RANGE, &sequence_range );
					num_words = ( sequence_range / WORD_BIT_SIZE ) + ( ( sequence_range % WORD_BIT_SIZE > 0)? 1 : 0 );
	
					set_init_arg( DUP_TTL_LIMIT_SWITCH, "2", MIN_DUP_TTL_LIMIT, MAX_DUP_TTL_LIMIT, &dup_ttl_limit );
	
					set_init_arg( DUP_RATE_SWITCH, "99", MIN_DUP_RATE, MAX_DUP_RATE, &dup_rate );
	
					set_init_arg( DUP_DEGRAD_SWITCH, "2", MIN_DUP_DEGRAD, MAX_DUP_DEGRAD, &dup_degrad );
	
					set_init_arg( SEND_CLONES_SWITCH, "200", MIN_SEND_CLONES, MAX_SEND_CLONES, &send_clones );
					//compat_version = DEF_COMPAT_VERSION + 1;
					
					set_init_arg( ASYMMETRIC_WEIGHT_SWITCH, "100", MIN_ASYMMETRIC_WEIGHT, MAX_ASYMMETRIC_WEIGHT, &asymmetric_weight );
	
					set_init_arg( ASYMMETRIC_EXP_SWITCH, "1", MIN_ASYMMETRIC_EXP, MAX_ASYMMETRIC_EXP, &asymmetric_exp );
	
					set_init_arg( REBRC_DELAY_SWITCH, "35", MIN_REBRC_DELAY, MAX_REBRC_DELAY, &rebrc_delay );
	
					found_args += 1;
					break;

				} else if ( strcmp( BIDIRECT_TIMEOUT_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( BIDIRECT_TIMEOUT_SWITCH, optarg, MIN_BIDIRECT_TIMEOUT, MAX_BIDIRECT_TIMEOUT, &bidirect_link_to );
					found_args += 2;
					break;

				} else if ( strcmp( NBRFSIZE_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( NBRFSIZE_SWITCH, optarg, MIN_SEQ_RANGE, MAX_SEQ_RANGE, &sequence_range );
					
					num_words = ( sequence_range / WORD_BIT_SIZE ) + ( ( sequence_range % WORD_BIT_SIZE > 0)? 1 : 0 );

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
					found_args += 2;
					break;
				
				} else if ( strcmp( SEND_CLONES_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( SEND_CLONES_SWITCH, optarg, MIN_SEND_CLONES, MAX_SEND_CLONES, &send_clones );
					
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
							
				} else if ( strcmp( PENALTY_MIN_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( PENALTY_MIN_SWITCH, optarg, MIN_PENALTY_MIN, MAX_PENALTY_MIN, &penalty_min );
					found_args += 2;
					break;

				} else if ( strcmp( PENALTY_EXCEED_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( PENALTY_EXCEED_SWITCH, optarg, MIN_PENALTY_EXCEED, MAX_PENALTY_EXCEED, &penalty_exceed );
					found_args += 2;
					break;

				} else if ( strcmp( RT_PRIO_DEFAULT_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( RT_PRIO_DEFAULT_SWITCH, optarg, MIN_RT_PRIO_DEFAULT, MAX_RT_PRIO_DEFAULT, &rt_prio_default );
					found_args += 2;
					break;
					
				} else if ( strcmp( BASE_PORT_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( BASE_PORT_SWITCH, optarg, MIN_BASE_PORT, MAX_BASE_PORT, &base_port );
					
					sprintf( unix_path, "%s.%d", DEF_UNIX_PATH, base_port);

					found_args += 2;
					break;
				
				} else if ( strcmp( RT_TABLE_OFFSET_SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( RT_TABLE_OFFSET_SWITCH, optarg, MIN_RT_TABLE_OFFSET, MAX_RT_TABLE_OFFSET, &rt_table_offset );
					
					found_args += 2;
					break;
					
				/*	this is just a template:
				} else if ( strcmp( _SWITCH, long_options[option_index].name ) == 0 ) {

					set_init_arg( _SWITCH, optarg, MIN_, MAX_, & );
					found_args += 2;
					break;
				*/											
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
				
				} else if ( strcmp( NO_PRIO_RULES_SWITCH, long_options[option_index].name ) == 0 ) {

					printf ("--%s \\ \n", long_options[option_index].name);
					errno = 0;
					no_prio_rules = YES;
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

					printf ("--%s \\ \n", long_options[option_index].name);
					errno = 0;
					resist_blocked_send = YES;
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

				add_del_hna_opt( optarg, NO );
				
				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;

			case 'b':
				batch_mode++;
				found_args += 1;
				break;

			case 'c':
				unix_client++;
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
				
				gateway_class_opt = 1;
				
				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;

			case 'H':
				verbose_usage();
				exit(EXIT_SUCCESS);

			case 'o':

				errno = 0;
				originator_interval = strtol (optarg, NULL , 10 );

				if ( originator_interval < MIN_ORIGINATOR_INTERVAL || originator_interval > MAX_ORIGINATOR_INTERVAL ) {

					printf( "Invalid originator interval specified: %i.\n The value must be >= %i and <= %i.\n", originator_interval, MIN_ORIGINATOR_INTERVAL, MAX_ORIGINATOR_INTERVAL );

					exit(EXIT_FAILURE);
				}

				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;

			case 'p':

				errno = 0;

				if ( inet_pton( AF_INET, optarg, &tmp_ip_holder ) < 1 ) {

					printf( "Invalid preferred gateway IP specified: %s\n", optarg );
					exit(EXIT_FAILURE);

				}

				pref_gateway = tmp_ip_holder.s_addr;
				
				pref_gw_opt = 1;

				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;

			case 'r':

				errno = 0;

				routing_class = strtol( optarg, NULL, 10 );

				if ( routing_class > 3 ) {

					printf( "Invalid routing class specified: %i.\nThe class is a value between 0 and 3.\n", routing_class );
					exit(EXIT_FAILURE);

				}

				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;

			case 's':

				errno = 0;
				if ( inet_pton( AF_INET, optarg, &tmp_ip_holder ) < 1 ) {

					printf( "Invalid preferred visualation server IP specified: %s\n", optarg );
					exit(EXIT_FAILURE);

				}

				vis_server = tmp_ip_holder.s_addr;

				routing_class_opt = 1;

				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;

			case 'v':

				printf( "BatMan-eXperimental %s%s (compatibility version %i)\n", SOURCE_VERSION, ( strncmp( REVISION_VERSION, "0", 1 ) != 0 ? REVISION_VERSION : "" ), COMPAT_VERSION );
				exit(EXIT_SUCCESS);

			case 'V':

				print_animation();

				printf( "\x1B[0;0HBatMan-eXperimental %s%s (compatibility version %i)\n", SOURCE_VERSION, ( strncmp( REVISION_VERSION, "0", 1 ) != 0 ? REVISION_VERSION : "" ), COMPAT_VERSION );
				printf( "\x1B[9;0H \t May the bat guide your path ...\n\n\n" );

				exit(EXIT_SUCCESS);

			case 'h':
				usage();
				exit(EXIT_SUCCESS);

			default:
				usage();
				exit(EXIT_FAILURE);

		}

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

	if ( !unix_client ) {

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

		FD_ZERO( &receive_wait_set );

		while ( argc > found_args ) {

			batman_if = debugMalloc( sizeof(struct batman_if), 206 );
			memset( batman_if, 0, sizeof(struct batman_if) );
			INIT_LIST_HEAD( &batman_if->list );

			batman_if->dev = argv[found_args];
			batman_if->if_num = found_ifs;
			batman_if->udp_tunnel_sock = 0;
			batman_if->if_bidirect_link_to = bidirect_link_to;
			batman_if->if_ttl = ttl;
			batman_if->if_send_clones = send_clones;

			list_add_tail( &batman_if->list, &if_list );

			init_interface ( batman_if );

			if ( batman_if->udp_recv_sock > receive_max_sock )
				receive_max_sock = batman_if->udp_recv_sock;

			FD_SET( batman_if->udp_recv_sock, &receive_wait_set );

			addr_to_string(batman_if->addr.sin_addr.s_addr, str1, sizeof (str1));
			addr_to_string(batman_if->broad.sin_addr.s_addr, str2, sizeof (str2));

			printf( "Using interface %s with address %s and broadcast address %s\n", batman_if->dev, str1, str2 );

			if( default_para_set == PARA_SET_BMX ) {
				
				if ( batman_if->if_num > 0 ) {
					
					char fake_arg[ADDR_STR_LEN + 4], ifaddr_str[ADDR_STR_LEN];
					errno = 0;
						
					addr_to_string( batman_if->addr.sin_addr.s_addr, ifaddr_str, sizeof(ifaddr_str) );
					sprintf( fake_arg, "%s/32", ifaddr_str);
					add_del_hna_opt( fake_arg, NO );
					printf ("Interface %s specific option: /%c \n", batman_if->dev, MAKE_IP_HNA_IF_SWITCH );
						
					batman_if->send_ogm_only_via_owning_if = YES;
					printf ("Interface %s specific option: /%c \n", batman_if->dev, OGM_ONLY_VIA_OWNING_IF_SWITCH );
					batman_if->if_ttl = 1;
					printf ("Interface %s specific option: /%c %d \n", batman_if->dev, TTL_IF_SWITCH, batman_if->if_ttl );

					batman_if->if_send_clones = 100;
					printf ("Interface %s specific option: /%c %d \n", batman_if->dev, SEND_CLONES_IF_SWITCH, batman_if->if_send_clones );

				}
					
			} else if( default_para_set == PARA_SET_GRAZ07 ) {
				
				if ( batman_if->if_num > 0 ) {
					
					char fake_arg[ADDR_STR_LEN + 4], ifaddr_str[ADDR_STR_LEN];
					errno = 0;
						
					addr_to_string( batman_if->addr.sin_addr.s_addr, ifaddr_str, sizeof(ifaddr_str) );
					sprintf( fake_arg, "%s/32", ifaddr_str);
					add_del_hna_opt( fake_arg, NO );
					printf ("Interface %s specific option: /%c \n", batman_if->dev, MAKE_IP_HNA_IF_SWITCH );
						
					batman_if->send_ogm_only_via_owning_if = YES;
					printf ("Interface %s specific option: /%c \n", batman_if->dev, OGM_ONLY_VIA_OWNING_IF_SWITCH );
					batman_if->if_ttl = 1;
					printf ("Interface %s specific option: /%c %d \n", batman_if->dev, TTL_IF_SWITCH, batman_if->if_ttl );

					batman_if->if_send_clones = 100;
					printf ("Interface %s specific option: /%c %d \n", batman_if->dev, SEND_CLONES_IF_SWITCH, batman_if->if_send_clones );

				}
					
			}

			
			found_ifs++;
			found_args++;

			while ( argc > found_args && strlen( argv[found_args] ) >= 2 && *argv[found_args] == '/') {

				if ( (argv[found_args])[1] == BIDIRECT_TIMEOUT_IF_SWITCH && argc > (found_args+1) ) {

					errno = 0;
					int16_t tmp = strtol ( argv[ found_args+1 ], NULL , 10 );
					printf ("Interface %s specific option: /%c %d \n", batman_if->dev, ((argv[found_args])[1]), tmp );

					if ( tmp < MIN_BIDIRECT_TIMEOUT || tmp > MAX_BIDIRECT_TIMEOUT ) {

						printf( "Invalid /%c specified: %i.\n Value must be %i <= value <= %i.\n", 
								BIDIRECT_TIMEOUT_IF_SWITCH, tmp, MIN_BIDIRECT_TIMEOUT, MAX_BIDIRECT_TIMEOUT );

						exit(EXIT_FAILURE);
					}

					batman_if->if_bidirect_link_to = tmp;

					found_args += 2;

				} else if ( (argv[found_args])[1] == TTL_IF_SWITCH && argc > (found_args+1) ) {

					errno = 0;
					uint8_t tmp = strtol ( argv[ found_args+1 ], NULL , 10 );
					printf ("Interface %s specific option: /%c %d \n", batman_if->dev, ((argv[found_args])[1]), tmp );

					if ( tmp < MIN_TTL || tmp > MAX_TTL ) {

						printf( "Invalid ttl specified: %i.\nThe ttl must be >= %i and <= %i.\n", tmp, MIN_TTL, MAX_TTL );

						exit(EXIT_FAILURE);
					}

					batman_if->if_ttl = tmp;

					found_args += 2;

				} else if ( (argv[found_args])[1] == SEND_CLONES_IF_SWITCH && argc > (found_args+1) ) {

					errno = 0;
					int16_t tmp = strtol ( argv[ found_args+1 ], NULL , 10 );
					printf ("Interface %s specific option: /%c %d \n", batman_if->dev, ((argv[found_args])[1]), tmp );

					if ( tmp < MIN_SEND_CLONES || tmp > MAX_SEND_CLONES ) {

						printf( "Invalid /%c specified: %i.\n Value must be %i <= value <= %i.\n", 
								SEND_CLONES_IF_SWITCH, tmp, MIN_SEND_CLONES, MAX_SEND_CLONES );

						exit(EXIT_FAILURE);
					}

					batman_if->if_send_clones = tmp;
					
//					if( tmp > DEF_SEND_CLONES )
//						compat_version = DEF_COMPAT_VERSION + 1;

					found_args += 2;

				
				} else if ( (argv[found_args])[1] == OGM_ONLY_VIA_OWNING_IF_SWITCH && argc > (found_args) ) {

					errno = 0;
					printf ("Interface %s specific option: /%c  \n", batman_if->dev, ((argv[found_args])[1]) );

					batman_if->send_ogm_only_via_owning_if = YES;
					batman_if->if_ttl = 1;

					found_args += 1;

				
				} else if ( (argv[found_args])[1] == MAKE_IP_HNA_IF_SWITCH && argc > (found_args) ) {

					printf ("Interface %s specific option: /%c  \n", batman_if->dev, ((argv[found_args])[1]) );
					
					if ( batman_if->if_num > 0 ) {
					
						char fake_arg[ADDR_STR_LEN + 4], ifaddr_str[ADDR_STR_LEN];
						errno = 0;
						
						addr_to_string( batman_if->addr.sin_addr.s_addr, ifaddr_str, sizeof(ifaddr_str) );
						sprintf( fake_arg, "%s/32", ifaddr_str);
						add_del_hna_opt( fake_arg, NO );
						
						batman_if->send_ogm_only_via_owning_if = YES;
						batman_if->if_ttl = 1;

					} else {
						
						printf( "Never ever add the IP address of the first interface to the HNA list !!! \n" );
						exit(EXIT_FAILURE);
	
					}
					
					found_args += 1;

							
				} else if ( (argv[found_args])[1] == UNDO_IP_HNA_IF_SWITCH && argc > (found_args) ) {

					printf ("Interface %s specific option: /%c  \n", batman_if->dev, ((argv[found_args])[1]) );
					
					char fake_arg[ADDR_STR_LEN + 4], ifaddr_str[ADDR_STR_LEN];
					errno = 0;
					
					addr_to_string( batman_if->addr.sin_addr.s_addr, ifaddr_str, sizeof(ifaddr_str) );
					sprintf( fake_arg, "%s/32", ifaddr_str);
					add_del_hna_opt( fake_arg, YES );
						
					found_args += 1;

							
				} else {
					
					printf( "Invalid interface specific option specified! \n" );
					exit(EXIT_FAILURE);
				
				}
			
			}

		}
		
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

			openlog( "batmand", LOG_PID, LOG_DAEMON );

		} else {
			printf( "BatMan-eXperimental %s%s (compatibility version %i)\n", SOURCE_VERSION, ( strncmp( REVISION_VERSION, "0", 1 ) != 0 ? REVISION_VERSION : "" ), COMPAT_VERSION );

			debug_clients.clients_num[ debug_level - 1 ]++;
			debug_level_info = debugMalloc( sizeof(struct debug_level_info), 205 );
			INIT_LIST_HEAD( &debug_level_info->list );
			debug_level_info->fd = 1;
			list_add( &debug_level_info->list, (struct list_head_first *)debug_clients.fd_list[debug_level - 1] );

		}

		pthread_create( &unix_if.listen_thread_id, NULL, &unix_listen, NULL );

		/* add rule for hna networks */
		if( !no_prio_rules )
			add_del_rule( 0, 0, BATMAN_RT_TABLE_NETWORKS, BATMAN_RT_PRIO_UNREACH - 1, 0, 1, 0 );

		/* add unreachable routing table entry */
		if( !no_unreachable_rule )
			add_del_route( 0, 0, 0, 0, 0, "unknown", BATMAN_RT_TABLE_UNREACH, 2, 0 );

		
		
		if ( routing_class > 0 ) {

			if ( add_del_interface_rules( 0 ) < 0 ) {

				restore_defaults();
				exit(EXIT_FAILURE);

			}

		}

		memset( &vis_if, 0, sizeof(vis_if) );

		if ( vis_server ) {

			vis_if.addr.sin_family = AF_INET;
			vis_if.addr.sin_port = htons(PORT + 2);
			vis_if.addr.sin_addr.s_addr = vis_server;
			vis_if.sock = socket( PF_INET, SOCK_DGRAM, 0 );

		}

		if ( gateway_class != 0 ) {

			list_for_each( list_pos, &if_list ) {

				batman_if = list_entry( list_pos, struct batman_if, list );

				init_interface_gw( batman_if );

			}

		}


		if ( debug_level > 0 ) {

			printf( "debug level: %i\n", debug_level );

			if ( originator_interval != 1000 )
				printf( "originator interval: %i\n", originator_interval );

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

		unix_buff = debugMalloc( 1501, 5001 );

		if ( debug_level > 0 ) {

			if ( debug_level <= debug_level_max ) {

				snprintf( unix_buff, 10, "d:%c", debug_level );

				if ( ( debug_level > 2 ) && ( batch_mode ) )
					printf( "WARNING: Your chosen debug level (%i) does not support batch mode !\n", debug_level );

			}

		} else if ( routing_class_opt ) {

			batch_mode = 1;
			snprintf( unix_buff, 10, "r:%c", routing_class );

		} else if ( pref_gw_opt ) {

			batch_mode = 1;
			addr_to_string( pref_gateway, str1, sizeof(str1) );
			snprintf( unix_buff, 20, "p:%s", str1 );

		} else if ( gateway_class_opt ) {

			batch_mode = 1;
			snprintf( unix_buff, 10, "g:%c", gateway_class );

		} else {

			batch_mode = 1;
			snprintf( unix_buff, 10, "i" );

		}

		if ( write( unix_if.unix_sock, unix_buff, 20 ) < 0 ) {

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



void init_interface ( struct batman_if *batman_if ) {

	struct ifreq int_req;
	int16_t on = 1;


	if ( strlen( batman_if->dev ) > IFNAMSIZ - 1 ) {
		printf( "Error - interface name too long: %s\n", batman_if->dev );
		restore_defaults();
		exit(EXIT_FAILURE);
	}

	if ( ( batman_if->udp_recv_sock = socket( PF_INET, SOCK_DGRAM, 0 ) ) < 0 ) {

		printf( "Error - can't create receive socket: %s", strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);

	}

	memset( &int_req, 0, sizeof (struct ifreq) );
	strncpy( int_req.ifr_name, batman_if->dev, IFNAMSIZ - 1 );

	if ( ioctl( batman_if->udp_recv_sock, SIOCGIFADDR, &int_req ) < 0 ) {

		printf( "Error - can't get IP address of interface %s: %s\n", batman_if->dev, strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);

	}

	batman_if->addr.sin_family = AF_INET;
	batman_if->addr.sin_port = htons(PORT);
	batman_if->addr.sin_addr.s_addr = ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr;

	if ( ioctl( batman_if->udp_recv_sock, SIOCGIFBRDADDR, &int_req ) < 0 ) {

		printf( "Error - can't get broadcast IP address of interface %s: %s\n", batman_if->dev, strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);

	}

	batman_if->broad.sin_family = AF_INET;
	batman_if->broad.sin_port = htons(PORT);
	batman_if->broad.sin_addr.s_addr = ((struct sockaddr_in *)&int_req.ifr_broadaddr)->sin_addr.s_addr;

	if ( batman_if->broad.sin_addr.s_addr == 0 ) {

		printf( "Error - invalid broadcast address detected (0.0.0.0): %s\n", batman_if->dev );
		restore_defaults();
		exit(EXIT_FAILURE);

	}


#ifdef __linux__
	/* The SIOCGIFINDEX ioctl is Linux specific, but I am not yet sure if the
	 * equivalent exists on *BSD. There is a function called if_nametoindex()
	 * on both Linux and BSD.
	 * Maybe it does the same as this code and we can simply call it instead?
	 * --stsp
	 */
	if ( ioctl( batman_if->udp_recv_sock, SIOCGIFINDEX, &int_req ) < 0 ) {

		printf( "Error - can't get index of interface %s: %s\n", batman_if->dev, strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);

	}

	batman_if->if_index = int_req.ifr_ifindex;
#else
	batman_if->if_index = 0;
#endif

	if ( ioctl( batman_if->udp_recv_sock, SIOCGIFNETMASK, &int_req ) < 0 ) {

		printf( "Error - can't get netmask address of interface %s: %s\n", batman_if->dev, strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);

	}

	batman_if->netaddr = ( ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr & batman_if->addr.sin_addr.s_addr );
	batman_if->netmask = bit_count( ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr );
	if( !no_prio_rules )
		add_del_rule( batman_if->netaddr, batman_if->netmask, BATMAN_RT_TABLE_HOSTS, BATMAN_RT_PRIO_DEFAULT + batman_if->if_num, 0, 1, 0 );
	
	if ( !no_unreachable_rule )
		add_del_rule( batman_if->netaddr, batman_if->netmask, BATMAN_RT_TABLE_UNREACH, BATMAN_RT_PRIO_UNREACH + batman_if->if_num, 0, 1, 0 );


	if ( ( batman_if->udp_send_sock = use_kernel_module( batman_if->dev ) ) < 0 ) {

		if ( ( batman_if->udp_send_sock = socket( PF_INET, SOCK_DGRAM, 0 ) ) < 0 ) {

			printf( "Error - can't create send socket: %s", strerror(errno) );
			restore_defaults();
			exit(EXIT_FAILURE);

		}

		if ( setsockopt( batman_if->udp_send_sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(int) ) < 0 ) {

			printf( "Error - can't enable broadcasts: %s\n", strerror(errno) );
			restore_defaults();
			exit(EXIT_FAILURE);

		}

		if ( bind_to_iface( batman_if->udp_send_sock, batman_if->dev ) < 0 ) {

			restore_defaults();
			exit(EXIT_FAILURE);

		}

		if ( bind( batman_if->udp_send_sock, (struct sockaddr *)&batman_if->addr, sizeof(struct sockaddr_in) ) < 0 ) {

			printf( "Error - can't bind send socket: %s\n", strerror(errno) );
			restore_defaults();
			exit(EXIT_FAILURE);

		}

	}

	if ( bind_to_iface( batman_if->udp_recv_sock, batman_if->dev ) < 0 ) {

		restore_defaults();
		exit(EXIT_FAILURE);

	}

	if ( bind( batman_if->udp_recv_sock, (struct sockaddr *)&batman_if->broad, sizeof(struct sockaddr_in) ) < 0 ) {

		printf( "Error - can't bind receive socket: %s\n", strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);

	}

}




void init_interface_gw ( struct batman_if *batman_if ) {

	int32_t sock_opts;
	unsigned short tmp_cmd[2];
	unsigned int cmd;

	if ( ( batman_if->udp_tunnel_sock = use_gateway_module( batman_if->dev ) ) < 0 ) {

		batman_if->addr.sin_port = htons(PORT + 1);

		batman_if->udp_tunnel_sock = socket( PF_INET, SOCK_DGRAM, 0 );

		if ( batman_if->udp_tunnel_sock < 0 ) {

			debug_output( 0, "Error - can't create tunnel socket: %s", strerror(errno) );
			restore_defaults();
			exit(EXIT_FAILURE);

		}

		if ( bind( batman_if->udp_tunnel_sock, (struct sockaddr *)&batman_if->addr, sizeof(struct sockaddr_in) ) < 0 ) {

			debug_output( 0, "Error - can't bind tunnel socket: %s\n", strerror(errno) );
			restore_defaults();
			exit(EXIT_FAILURE);

		}

		/* make udp socket non blocking */
		sock_opts = fcntl( batman_if->udp_tunnel_sock, F_GETFL, 0 );
		fcntl( batman_if->udp_tunnel_sock, F_SETFL, sock_opts | O_NONBLOCK );

		batman_if->addr.sin_port = htons(PORT);

		pthread_create( &batman_if->listen_thread_id, NULL, &gw_listen, batman_if );

	} else {

	    tmp_cmd[0] = (unsigned short)IOCSETDEV;
	    tmp_cmd[1] = (unsigned short)strlen(batman_if->dev);
	    memcpy(&cmd, tmp_cmd, sizeof(int));
		/* TODO: test if we can assign tmp_cmd direct */
	    if(ioctl(batman_if->udp_tunnel_sock,cmd, batman_if->dev) < 0) {
			debug_output( 0, "Error - can't add device %s: %s\n", batman_if->dev,strerror(errno) );
			restore_defaults();
			exit(EXIT_FAILURE);
	    }
	}

}


