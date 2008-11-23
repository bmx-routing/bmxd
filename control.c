/*
 * Copyright (C) 2006 BATMAN contributors:
 * Axel Neumann
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
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

#include "batman.h"
#include "os.h"
#include "originator.h"
#include "metrics.h"
#include "control.h"

int unix_sock = 0;

SIMPEL_LIST( cmsg_list );

SIMPEL_LIST( unix_clients );

struct list_head_first dbgl_clients[DBGL_MAX+1];

uint8_t debug_system_active = NO;

void init_control( void ) {
	
	int i;
	
	for ( i = DBGL_MIN; i <= DBGL_MAX; i++ )
		INIT_LIST_HEAD_FIRST( dbgl_clients[i] );
	
	openlog( "bmxd", LOG_PID, LOG_DAEMON );

	
	// just to check if sizeof( struct xyz { char[] }__attribute__((packed)); ) is zero for all compilers...
	if ( sizeof( struct cntl_msg ) != 20 ) {
		printf( "sizeof cntl_msg %zu MUST BE 20 !!!\n", sizeof( struct cntl_msg ) ); 
		exit(EXIT_FAILURE);
	}

}



void cleanup_control( void ) {
	
	debug_system_active = NO;
	closelog();

	if ( unix_sock )
		close( unix_sock );

	unix_sock = 0;

	int8_t i;
	struct client_node *client_node;
	struct list_head *list_pos, *list_tmp;
	
	for ( i = DBGL_MIN; i <= DBGL_MAX; i++ ) {

		list_for_each_safe( list_pos, list_tmp, (struct list_head *)&dbgl_clients[i] ) {

			client_node = list_entry(list_pos, struct client_node, list);

			close( client_node->fd );
			
			list_del( (struct list_head *)&dbgl_clients[i], list_pos, &dbgl_clients[i] );
			debugFree( list_pos, 1218 );

		}

	}
	
	list_for_each_safe( list_pos, list_tmp, &unix_clients ) {

		client_node = list_entry( list_pos, struct client_node, list);

		close( client_node->fd );
	
		list_del( (struct list_head *)&unix_clients, list_pos, &unix_clients );
		debugFree( list_pos, 1219 );

	}
	

}
	
	
	
void activate_debug_system( void ) {
	
	//openlog( "bmxd", LOG_PID, LOG_DAEMON );
	
	debug_system_active = YES;

}

void accept_unix_client( void )
{
	
	struct client_node *unix_client;
	struct sockaddr addr;
	socklen_t addr_size = sizeof(struct sockaddr);
	int32_t unix_opts;
		
	unix_client = debugMalloc( sizeof(struct client_node), 201 );
	memset( unix_client, 0, sizeof(struct client_node) );

	INIT_LIST_HEAD( &unix_client->list );

	if ( ( unix_client->fd = accept( unix_sock, (struct sockaddr *)&addr, &addr_size) ) == -1 ) {
		debug_output( 0, "Error - can't accept unix client: %s\n", strerror(errno) );
		return;
	}


	/* make unix socket non blocking */
	unix_opts = fcntl( unix_client->fd, F_GETFL, 0 );
	fcntl( unix_client->fd, F_SETFL, unix_opts | O_NONBLOCK );

	list_add_tail( &unix_client->list, &unix_clients );
	
	changed_readfds++;
	
	debug_all( "accept_unix_client(): got unix control connection\n" );
	
}



void handle_unix_control_msg( struct list_head* list_pos, struct list_head * prev_list_head )
{
	char buff[MAX_UNIX_MSG_SIZE+1];
	struct cntl_msg *cmsg = (struct cntl_msg*) buff;
	
	struct client_node *client = list_entry( list_pos, struct client_node, list );
	
	errno=0;
	int input = read( client->fd, buff, sizeof( struct cntl_msg ) );

	if ( input == sizeof(struct cntl_msg)  &&  cmsg->version == COMPAT_VERSION  && 
		( cmsg->len == sizeof(struct cntl_msg) ||  cmsg->len == ( input += read( client->fd, cmsg->aux, (cmsg->len-sizeof(struct cntl_msg)) ) ) ) ) {
		
		debug_all( "rcvd control request via fd %d type %d  of %d bytes, version %d, val %d\n", client->fd, cmsg->type, cmsg->len, cmsg->version, cmsg->val );
		
		if ( cmsg->type == REQ_DBGL   ) {

			if (  cmsg->val == DBGL_SYSTEM || cmsg->val == DBGL_CHANGES || cmsg->val == DBGL_TEST || cmsg->val == DBGL_ALL ) {

				list_del( prev_list_head, list_pos, &unix_clients );
						
				INIT_LIST_HEAD( &client->list );
									
				list_add_tail( &client->list, &(dbgl_clients[ cmsg->val ]) );
				
				changed_readfds++;
				return;

			} else if (  cmsg->val == DBGL_ROUTES || cmsg->val == DBGL_GATEWAYS || cmsg->val == DBGL_DETAILS  || cmsg->val == DBGL_HNAS  || cmsg->val == DBGL_SERVICES  || cmsg->val == DBGL_NEIGHBORS ) {
				
				debug_orig( cmsg->val, client->fd );
				return;
				
			} else if ( cmsg->val == DBGL_PROFILE ) {
				
#if defined MEMORY_USAGE
				debugMemory( client->fd );
				dprintf( client->fd, "\n" );
#endif
#if defined PROFILE_DATA				
				prof_print( client->fd );
#endif
				return;
				
			}
			
		} else if ( cmsg->type == REQ_DBGL_INPUT ) {
			 
			if ( cmsg->val == DBGL_SYSTEM || cmsg->val == DBGL_CHANGES || cmsg->val == DBGL_TEST || cmsg->val == DBGL_ALL )  {

				buff[cmsg->len] = '\0';
				debug_output( cmsg->val, "%s", cmsg->aux );
				return;
			}
		 
		} else if ( cmsg->type == REQ_INFO ) {
			
			debug_config( client->fd );
			return;
		
		} else if ( cmsg->type == REQ_PURGE ) {
			
			// if there is a gw-client thread: stop it now, it restarts automatically
			del_default_route(); 
									
			// if there is a gw thread: stop it now
			stop_gw_service();
									
			purge_orig( 0 );
		
			if ( gateway_class  &&  (one_way_tunnel || two_way_tunnel)  &&  probe_tun() )
				start_gw_service();

			return;
		
		} else if ( cmsg->type == REQ_1WT ) {
			
			// if there is a gw-client thread: stop it now, it restarts automatically
			del_default_route(); 
									
			// if there is a gw thread: stop it now
			stop_gw_service();
									
			set_init_val( ONE_WAY_TUNNEL_SWITCH, cmsg->val, MIN_ONE_WAY_TUNNEL, MAX_ONE_WAY_TUNNEL, &one_way_tunnel, REQ_NONE );
																	
			debug_output( DBGL_CHANGES, " changing rt_class: %d owt: %d twt: %d gw_class %d \n", 
				      routing_class, one_way_tunnel, two_way_tunnel, gateway_class );
									
			if ( gateway_class  &&  (one_way_tunnel || two_way_tunnel)  &&  probe_tun() )
				start_gw_service();
			return;
		
			
		} else if ( cmsg->type == REQ_2WT ) {
							
			// if there is a gw-client thread: stop it now, it restarts automatically
			del_default_route(); 
									
			// if there is a gw thread: stop it now
			stop_gw_service();
									
			set_init_val( TWO_WAY_TUNNEL_SWITCH, cmsg->val, MIN_TWO_WAY_TUNNEL, MAX_TWO_WAY_TUNNEL, &two_way_tunnel, REQ_NONE );
																	
			debug_output( 3, " changing rt_class: %d owt: %d twt: %d gw_class %d \n", 
				      routing_class, one_way_tunnel, two_way_tunnel, gateway_class );
									
			if ( gateway_class  &&  (one_way_tunnel || two_way_tunnel)  &&  probe_tun() )
				start_gw_service();

			return;

		
		} else if ( cmsg->type == REQ_GW_CLASS ) {
		
			gateway_class = cmsg->val;

			stop_gw_service();
									
			if ( gateway_class  &&  (one_way_tunnel || two_way_tunnel)  &&  probe_tun() ) {

				if ( routing_class > 0 ) {

					routing_class = 0;
		
					del_default_route();
									
					add_del_interface_rules( YES/*del*/, YES/*tunnel*/, NO/*networks*/ );

				}
									
				start_gw_service();
			}
			
			return;

		
		} else if ( cmsg->type == REQ_RT_CLASS ) {
			
			if (  cmsg->val > 0  &&  gateway_class > 0  ) {
				gateway_class = 0;
				stop_gw_service();
			}
				
			if ( routing_class == 0 && cmsg->val > 0 )
				add_del_interface_rules( NO/*del*/, YES/*tunnel*/, NO/*networks*/ );
										
			if ( routing_class > 0 && cmsg->val == 0 )
				add_del_interface_rules( YES/*del*/, YES/*tunnel*/, NO/*networks*/ );
									
			routing_class = cmsg->val;
									
			if ( curr_gateway != NULL )
				del_default_route();
			
			return;

		
		} else if ( cmsg->type == REQ_PREF_GW ) {
			
			pref_gateway = cmsg->ip;

			if ( curr_gateway != NULL )
				del_default_route();
			
			return;

			
		} else if ( cmsg->type == REQ_PWS ) {
								
			struct list_head* i_list_pos;
			
			set_init_val( NBRFSIZE_SWITCH, cmsg->val, MIN_SEQ_RANGE, MAX_SEQ_RANGE, &my_pws, REQ_NONE );
			
			list_for_each( i_list_pos, &if_list ) {

				(list_entry( i_list_pos, struct batman_if, list ))->out.pws = my_pws;
		
			}
			
			return;
			
		} else if ( cmsg->type == REQ_LWS ) {
			
			set_init_val( BIDIRECT_TIMEOUT_SWITCH, cmsg->val, MIN_BIDIRECT_TIMEOUT, MAX_BIDIRECT_TIMEOUT, &my_lws, REQ_NONE );
			
			flush_link_node_seqnos();
				
			return;
			
			
		} else if ( cmsg->type == REQ_TTL_DEGRADE ) {
			
			set_init_val( TTL_DEGRADE_SWITCH, cmsg->val, MIN_TTL_DEGRADE, MAX_TTL_DEGRADE, &ttl_degrade, REQ_NONE );
						
			return;
			
			
		} else if ( cmsg->type == REQ_UNI_PROBES_N ) {
			
			set_init_val( UNI_PROBES_N_SWITCH, cmsg->val, MIN_UNI_PROBES_N, MAX_UNI_PROBES_N, &unicast_probes_num, REQ_NONE );
						
			return;
			
		} else if ( cmsg->type == REQ_UNI_PROBES_IVAL ) {
			
			set_init_val( UNI_PROBES_IVAL_SWITCH, cmsg->val, MIN_UNI_PROBES_IVAL, MAX_UNI_PROBES_IVAL, &unicast_probes_ival, REQ_NONE );
						
			return;
			
		} else if ( cmsg->type == REQ_UNI_PROBES_SIZE ) {
			
			set_init_val( UNI_PROBES_SIZE_SWITCH, cmsg->val, MIN_UNI_PROBES_SIZE, MAX_UNI_PROBES_SIZE, &unicast_probes_size, REQ_NONE );
						
			return;
			
		} else if ( cmsg->type == REQ_UNI_PROBES_WS ) {
			
			struct list_head *list_pos, *link_pos;

			set_init_val( UNI_PROBES_WS_SWITCH, cmsg->val, MIN_UNI_PROBES_WS, MAX_UNI_PROBES_WS, &unicast_probes_ws, REQ_NONE );
			
			list_for_each( link_pos, &link_list ) {

				struct link_node *ln = list_entry(link_pos, struct link_node, list);
				
				list_for_each( list_pos, &if_list ) {

					struct batman_if *bif = list_entry( list_pos, struct batman_if, list );

					struct link_node_dev *lndev = &(ln->lndev[ bif->if_num ]);
					
#ifdef METRICTABLE
					flush_sq_record( &lndev->up_sqr, MAX_UNICAST_PROBING_WORDS );
#endif
					lndev->sum_probe_tp = 0;
				}
				
			}
			
			return;
			
		} else if ( cmsg->type == REQ_OGI ) {
			
			set_init_val( "o", cmsg->val, MIN_ORIGINATOR_INTERVAL, MAX_ORIGINATOR_INTERVAL, &my_ogi, REQ_NONE );
						
			return;
			
		} else if ( cmsg->type == REQ_HNA ) {
			
			prepare_add_del_own_hna( NULL, cmsg->ip, cmsg->val,  cmsg->val1, cmsg->val2, REQ_NONE );
				
			add_del_own_hna( NO /* do not purge */ );
						
			return;
			
		} else if ( cmsg->type == REQ_SRV ) {
			
			prepare_add_del_own_srv( NULL, cmsg->ip, cmsg->val, cmsg->val1, cmsg->val2 );
				
			add_del_own_srv( NO /* do not purge */ );
						
			return;
		
		} else if ( cmsg->type == REQ_FAKE_TIME ) {
				
			fake_start_time ( cmsg->val );
										
			return;
		
		} else if ( cmsg->type == REQ_MAGIC ) {
			
			debug_output( DBGL_SYSTEM, "INFO: changing %s from %d to %d \n", MAGIC_SWITCH, magic_switch, cmsg->val );
			set_init_val( MAGIC_SWITCH, cmsg->val, MIN_MAGIC, MAX_MAGIC, &magic_switch, REQ_NONE );
			
			/*
			int i=0, ret=0;
			
			if ( magic_switch <= 1000 ) {
				
				for (  ; i <= magic_switch; i++ ) {
					
					if ( (ret=system("./test.sh" )) ) {
						break;
					}
				}
				
			} else if ( magic_switch <= 2000 ) {
				
				for (  ; i <= magic_switch - 1000; i++ ) {
				
					if ( (ret=system(" ip r add 1.2.3.4/32 via 103.1.1.1 table 99" )) ) {
						break;
					}
						
					if ( (ret=system(" ip r del 1.2.3.4/32 via 103.1.1.1 table 99" )) ) {
						break;
					}
				}
				
			} else if ( magic_switch <= 3000 ) {
				
				struct in_addr dst_addr, gw_addr;

				inet_pton( AF_INET, "1.2.3.4", &dst_addr );
				inet_pton( AF_INET, "103.1.1.1", &gw_addr );
				
				uint32_t dst = dst_addr.s_addr;
				uint32_t gw = gw_addr.s_addr;

				struct batman_if *bif = list_entry( (&if_list)->next, struct batman_if, list );
				
				for ( i = 0; i < magic_switch - 2000; i++ ) {
					
					add_del_route( dst, 32, gw, 0, bif->if_index, bif->dev, 99, 0, 0, NO );
					add_del_route( dst, 32, gw, bif->addr.sin_addr.s_addr, bif->if_index, bif->dev, 99, 0, 1, NO );
					
				}
			}
			
			debug_output( DBGL_SYSTEM, "INFO: changing %s done, ret=%d. i=%d \n", MAGIC_SWITCH, ret, i );
			*/
			
			return;
			
		} else if ( cmsg->type == REQ_DEFAULT ) {
			
			debug_params( client->fd );

			return;
		
		} else if ( cmsg->type == REQ_END ) {
			
			close( client->fd );
			list_del( prev_list_head, list_pos, &unix_clients );
			debugFree( client, 1201 );
				
			changed_readfds++;
			return;
		
		}
	
	} 
		
	if ( input > 0 )
		debug_output( DBGL_SYSTEM, "ERROR: Drop control msg - rcvd %d bytes incompatible control request via fd %d! version? %d, type? %d, len? %d strerror?: %s   Closing socket\n", input, client->fd, cmsg->version, cmsg->type, cmsg->len, strerror( errno ) );
	
	close( client->fd );
	list_del( prev_list_head, list_pos, &unix_clients );
	debugFree( client, 1201 );
			
	changed_readfds++;
	return;

}

void handle_unix_dbgl_msg( struct list_head* list_pos, struct list_head * prev_list_head, int dbgl )
{
	char buff[MAX_UNIX_MSG_SIZE];
	int input;
	
	struct client_node *client = list_entry( list_pos, struct client_node, list );
	
	errno=0;
	input = read( client->fd, buff, sizeof( buff ) );

	debug_output( DBGL_SYSTEM, "ERROR: rcvd dbgl msg via fd %d, len %d, error %s \n", client->fd, input, strerror( errno ) );
	close( client->fd );
	list_del( prev_list_head, list_pos, &dbgl_clients[dbgl] );
	debugFree( client, 1201 );
	
	changed_readfds++;

	return;

}




static char string_out[ MAX_DBG_STR_SIZE + 1 ];

void debug_log( char *last, ... ) {
	
	va_list ap;
	va_start( ap, last );
	
	if ( debug_system_active ) {
		
		vsyslog( LOG_ERR, last, ap );

	} else {
		
		vsnprintf( string_out, MAX_DBG_STR_SIZE, last, ap );
		printf( "%s", string_out );
		
	}
	
	va_end( ap );
		
	return;

}

#ifndef NODEBUG

void debug_output( int8_t dbgl, char *last, ... )
{
	va_list ap;
	struct list_head *client_pos;
	struct client_node *client_node;
	int16_t dbgl_out[DBGL_MAX+1];
	memset( &dbgl_out, -1, DBGL_MAX+1 );
	int level, i = 0;

	if ( dbgl == DBGL_SYSTEM ) {

		va_start( ap, last );
		vsyslog( LOG_ERR, last, ap );
		va_end( ap );

	}
		
	if ( !debug_system_active ) {
		
		if ( dbgl == DBGL_SYSTEM || debug_level == DBGL_ALL || debug_level == dbgl ) {
			va_start( ap, last );
			vsnprintf( string_out, MAX_DBG_STR_SIZE, last, ap );
			printf( "%s", string_out );
			va_end( ap );
		}
		
		return;
	}

	if ( dbgl == DBGL_SYSTEM ) {
		
		if ( !list_empty( &dbgl_clients[DBGL_SYSTEM     ] ) ) dbgl_out[i++] = DBGL_SYSTEM;
		if ( !list_empty( &dbgl_clients[DBGL_CHANGES    ] ) ) dbgl_out[i++] = DBGL_CHANGES;
		if ( !list_empty( &dbgl_clients[DBGL_ALL        ] ) ) dbgl_out[i++] = DBGL_ALL;
		
	} else if ( dbgl == DBGL_ROUTES ) {
		
		if ( !list_empty( &dbgl_clients[DBGL_ROUTES     ] ) ) dbgl_out[i++] = DBGL_ROUTES;

	} else if ( dbgl == DBGL_GATEWAYS ) {
		
		if ( !list_empty( &dbgl_clients[DBGL_GATEWAYS   ] ) ) dbgl_out[i++] = DBGL_GATEWAYS;
		if ( !list_empty( &dbgl_clients[DBGL_ALL        ] ) ) dbgl_out[i++] = DBGL_ALL;

	} else if ( dbgl == DBGL_CHANGES ) {
	
		if ( !list_empty( &dbgl_clients[DBGL_CHANGES    ] ) ) dbgl_out[i++] = DBGL_CHANGES;
		if ( !list_empty( &dbgl_clients[DBGL_ALL        ] ) ) dbgl_out[i++] = DBGL_ALL;

	} else if ( dbgl == DBGL_TEST ) {
	
		if ( !list_empty( &dbgl_clients[DBGL_TEST       ] ) ) dbgl_out[i++] = DBGL_TEST;
		if ( !list_empty( &dbgl_clients[DBGL_ALL        ] ) ) dbgl_out[i++] = DBGL_ALL;

	} else if ( dbgl == DBGL_ALL ) {
	
		if ( !list_empty( &dbgl_clients[DBGL_ALL        ] ) ) dbgl_out[i++] = DBGL_ALL;
	
	} else if ( dbgl == DBGL_PROFILE ) {
	
		if ( !list_empty( &dbgl_clients[DBGL_PROFILE    ] ) ) dbgl_out[i++] = DBGL_PROFILE;
	
	} else if ( dbgl == DBGL_STATISTICS ) {
	
		if ( !list_empty( &dbgl_clients[DBGL_STATISTICS ] ) ) dbgl_out[i++] = DBGL_STATISTICS;
		if ( !list_empty( &dbgl_clients[DBGL_ALL        ] ) ) dbgl_out[i++] = DBGL_ALL;
	
	} else if ( dbgl == DBGL_DETAILS ) {
	
		if ( !list_empty( &dbgl_clients[DBGL_DETAILS    ] ) ) dbgl_out[i++] = DBGL_DETAILS;
		if ( !list_empty( &dbgl_clients[DBGL_ALL        ] ) ) dbgl_out[i++] = DBGL_ALL;
	
	} else if ( dbgl == DBGL_HNAS ) {
	
		if ( !list_empty( &dbgl_clients[DBGL_HNAS       ] )  ) dbgl_out[i++] = DBGL_HNAS;
		if ( !list_empty( &dbgl_clients[DBGL_ALL        ] )  ) dbgl_out[i++] = DBGL_ALL;
	
	} else if ( dbgl == DBGL_SERVICES ) {
	
		if ( !list_empty( &dbgl_clients[DBGL_SERVICES   ] ) ) dbgl_out[i++] = DBGL_SERVICES;
		if ( !list_empty( &dbgl_clients[DBGL_ALL        ] ) ) dbgl_out[i++] = DBGL_ALL;
	
	} else if ( dbgl == DBGL_NEIGHBORS ) {
	
		if ( !list_empty( &dbgl_clients[DBGL_NEIGHBORS  ] ) ) dbgl_out[i++] = DBGL_NEIGHBORS;
		if ( !list_empty( &dbgl_clients[DBGL_ALL        ] ) ) dbgl_out[i++] = DBGL_ALL;
	
	}

	
	i = 0;
	
	while( (level=dbgl_out[i++]) > -1 ) {	
		
	
		list_for_each( client_pos, (struct list_head *)&(dbgl_clients[level]) ) {

			client_node = list_entry(client_pos, struct client_node, list);

			if ( level == DBGL_CHANGES || level == DBGL_TEST ||  level == DBGL_ALL ||  level == DBGL_PROFILE  )
				dprintf( client_node->fd, "[%10u] ", get_time_msec() );

			va_start( ap, last );
			vsnprintf( string_out, MAX_DBG_STR_SIZE, last, ap );
			dprintf( client_node->fd, "%s", string_out );
			va_end( ap );

		}
	
	}
	
}

#endif
