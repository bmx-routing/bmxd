/*
 * Copyright (C) 2006 BATMAN contributors:
 * Marek Lindner, Axel Neumann
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
#include <sys/time.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#include "../os.h"
#include "../batman.h"



void debug_log( char *format, ... ) {
	va_list args;
	va_start( args, format  );
	vsyslog( LOG_ERR, format, args );
	va_end( args );
}

void debug_output( int8_t debug_prio_arg, char *format, ... ) {

	struct list_head *debug_pos;
	struct debug_level_info *debug_level_info;
	int8_t debug_prio_intern;
	va_list args;
	char tmp_string[MAX_DBG_STR_SIZE + 1]; // TBD: must be checked for overflow when using with sprintf
	
	int i = 0;
	int8_t debug_prio;
	int8_t debug_request[debug_level_max];// = {-1,-1,-1,-1,-1};
	memset( &debug_request, -1, debug_level_max );
	
	if (!log_facility_active) {
		va_start( args, format );
		vprintf( format, args );
		va_end( args );
		return;
	}
	
	
	if ( debug_prio_arg == DBGL_SYSTEM ) {
		
		debug_request[i++] = DBGL_SYSTEM;
		if ( debug_clients.clients_num[DBGL_CHANGES  -1] > 0 ) debug_request[i++] = DBGL_CHANGES;
		if ( debug_clients.clients_num[DBGL_ALL      -1] > 0 ) debug_request[i++] = DBGL_ALL;
		
	} else if ( debug_prio_arg == DBGL_ROUTES ) {
		
		if ( debug_clients.clients_num[DBGL_ROUTES   -1] > 0 ) debug_request[i++] = DBGL_ROUTES;

	} else if ( debug_prio_arg == DBGL_GATEWAYS ) {
		
		if ( debug_clients.clients_num[DBGL_GATEWAYS -1] > 0 ) debug_request[i++] = DBGL_GATEWAYS;
		if ( debug_clients.clients_num[DBGL_ALL      -1] > 0 ) debug_request[i++] = DBGL_ALL;

	} else if ( debug_prio_arg == DBGL_CHANGES ) {
	
		if ( debug_clients.clients_num[DBGL_CHANGES  -1] > 0 ) debug_request[i++] = DBGL_CHANGES;
		if ( debug_clients.clients_num[DBGL_ALL      -1] > 0 ) debug_request[i++] = DBGL_ALL;

	} else if ( debug_prio_arg == DBGL_ALL ) {
	
		if ( debug_clients.clients_num[DBGL_ALL      -1] > 0 ) debug_request[i++] = DBGL_ALL;
	
	} else if ( debug_prio_arg == DBGL_PROFILE ) {
	
		if ( debug_clients.clients_num[DBGL_PROFILE  -1] > 0 ) debug_request[i++] = DBGL_PROFILE;
	
	} else if ( debug_prio_arg == DBGL_STATISTICS ) {
	
		if ( debug_clients.clients_num[DBGL_STATISTICS -1] > 0 ) debug_request[i++] = DBGL_STATISTICS;
		if ( debug_clients.clients_num[DBGL_ALL        -1] > 0 ) debug_request[i++] = DBGL_ALL;
	
	} else if ( debug_prio_arg == DBGL_DETAILS ) {
	
		if ( debug_clients.clients_num[DBGL_DETAILS  -1] > 0 ) debug_request[i++] = DBGL_DETAILS;
		if ( debug_clients.clients_num[DBGL_ALL      -1] > 0 ) debug_request[i++] = DBGL_ALL;
	
	} else if ( debug_prio_arg == DBGL_HNAS ) {
	
		if ( debug_clients.clients_num[DBGL_HNAS     -1] > 0 ) debug_request[i++] = DBGL_HNAS;
		if ( debug_clients.clients_num[DBGL_ALL      -1] > 0 ) debug_request[i++] = DBGL_ALL;
	
	} else if ( debug_prio_arg == DBGL_SERVICES ) {
	
		if ( debug_clients.clients_num[DBGL_SERVICES -1] > 0 ) debug_request[i++] = DBGL_SERVICES;
		if ( debug_clients.clients_num[DBGL_ALL      -1] > 0 ) debug_request[i++] = DBGL_ALL;
	
	}
	i = 0;
	
	while( debug_request[i] >= 0 ) {	
		
		debug_prio = debug_request[i];
		i++;
		
		if ( debug_prio == DBGL_SYSTEM ) {
	
			//if ( debug_level == DBGL_SYSTEM ) {
	
				va_start( args, format );
				vsyslog( LOG_ERR, format, args );
				va_end( args );
	
			//} 
			continue;		
		
		} else {
	
			debug_prio_intern = debug_prio - 1;
	
		}
	
	
		if ( debug_clients.clients_num[debug_prio_intern] > 0 ) {
	
			if ( pthread_mutex_trylock( (pthread_mutex_t *)debug_clients.mutex[debug_prio_intern] ) == 0 ) {
	
				list_for_each( debug_pos, (struct list_head *)debug_clients.fd_list[debug_prio_intern] ) {
	
					debug_level_info = list_entry(debug_pos, struct debug_level_info, list);
	
					if ( debug_prio == DBGL_CHANGES || debug_prio == DBGL_ALL || debug_prio == DBGL_PROFILE  )
						dprintf( debug_level_info->fd, "[%10u] ", get_time_msec() );
	
					if ( ( ( debug_level == DBGL_ROUTES ) || ( debug_level == DBGL_GATEWAYS ) ) && ( debug_level_info->fd == 1 ) && ( strncmp( format, "BOD", 3 ) == 0 ) ) {
	
						system( "clear" );
	
					} else {
	
						if ( ( ( debug_level != DBGL_ROUTES ) && ( debug_level != DBGL_GATEWAYS ) ) || ( debug_level_info->fd != 1 ) || ( strncmp( format, "EOD", 3 ) != 0 ) ) {
	
							va_start( args, format );
							vsnprintf( tmp_string, MAX_DBG_STR_SIZE, format, args );
							dprintf( debug_level_info->fd, "%s", tmp_string );
							va_end( args );
	
						}
	
					}
	
				}
	
			
				if ( pthread_mutex_unlock( (pthread_mutex_t *)debug_clients.mutex[debug_prio_intern] ) < 0 )
					
					debug_log( "Error - could not unlock mutex (debug_output): %s \n", strerror( errno ) );

				
			} else {
	
				debug_log( "Warning - could not trylock mutex (debug_output): %s \n", strerror( EBUSY ) );

			}
	
		}
	}

}
	
	
	
void internal_output(uint32_t sock)
{
	dprintf(sock, "source_version=%s\n", SOURCE_VERSION);
	dprintf(sock, "compat_version=%i\n", COMPAT_VERSION);
	dprintf(sock, "vis_compat_version=%i\n", VIS_COMPAT_VERSION);
	dprintf(sock, "ogm_port=%i\n", ogm_port );
	dprintf(sock, "gw_port=%i\n", my_gw_port );
	dprintf(sock, "vis_port=%i\n", vis_port );
	dprintf(sock, "unix_socket_path=%s\n", unix_path);
	dprintf(sock, "own_ogm_jitter=%i\n", JITTER);
	dprintf(sock, "default_ttl=%i\n", ttl);
	dprintf(sock, "originator_timeout=%i\n", MY_PURGE_TIMEOUT);
	dprintf(sock, "rt_table_interfaces=%i\n", BATMAN_RT_TABLE_INTERFACES);
	dprintf(sock, "rt_table_networks=%i\n", BATMAN_RT_TABLE_NETWORKS);
	dprintf(sock, "rt_table_hosts=%i\n", BATMAN_RT_TABLE_HOSTS);
	dprintf(sock, "rt_table_unreach=%i\n", BATMAN_RT_TABLE_UNREACH);
	dprintf(sock, "rt_table_tunnel=%i\n", BATMAN_RT_TABLE_TUNNEL);
	
	dprintf(sock, "rt_prio_interfaces=%i\n", BATMAN_RT_PRIO_INTERFACES);
	dprintf(sock, "rt_prio_default=%i\n", BATMAN_RT_PRIO_HOSTS);
	dprintf(sock, "rt_prio_networks=%i\n", BATMAN_RT_PRIO_NETWORKS);
	dprintf(sock, "rt_prio_unreach=%i\n", BATMAN_RT_PRIO_UNREACH);
	dprintf(sock, "rt_prio_tunnel=%i\n", BATMAN_RT_PRIO_TUNNEL);
}



void *unix_listen( void *arg ) {

	struct unix_client *unix_client;
	struct debug_level_info *debug_level_info;
	struct list_head *client_list_pos, *i_list_pos, *unix_pos_tmp, *debug_pos, *debug_pos_tmp, *prev_list_head, *prev_list_head_unix;
	struct hna_node *hna_node;
	struct srv_node *srv_node;
	struct batman_if *batman_if;
	struct timeval tv;
	struct sockaddr_un sun_addr;
	struct in_addr tmp_ip_holder;
	int32_t status, max_sock, unix_opts, download_speed, upload_speed;
	int8_t res;
	char buff[MAX_UNIX_REQ_SIZE], str[16];
	fd_set wait_sockets, tmp_wait_sockets;
	socklen_t sun_size = sizeof(struct sockaddr_un);
	uint8_t unix_client_deleted = NO;
	uint32_t tmp_enabled, tmp_netmask, tmp_address;
	uint16_t tmp_port, tmp_ogi;
	int tmp_int;
	uint8_t tmp_seqno;

	INIT_LIST_HEAD_FIRST(unix_if.client_list);

	FD_ZERO(&wait_sockets);
	FD_SET(unix_if.unix_sock, &wait_sockets);

	max_sock = unix_if.unix_sock;

	while ( !is_aborted() ) {

		tv.tv_sec = 0;
		tv.tv_usec = (1000*MAX_SELECT_TIMEOUT_MS);
		memcpy( &tmp_wait_sockets, &wait_sockets, sizeof(fd_set) );

		res = select( max_sock + 1, &tmp_wait_sockets, NULL, NULL, &tv );

		if ( res > 0 ) {

			/* new client */
			if ( FD_ISSET( unix_if.unix_sock, &tmp_wait_sockets ) ) {

				unix_client = debugMalloc( sizeof(struct unix_client), 201 );
				memset( unix_client, 0, sizeof(struct unix_client) );

				if ( ( unix_client->sock = accept( unix_if.unix_sock, (struct sockaddr *)&sun_addr, &sun_size) ) == -1 ) {
					debug_output( 0, "Error - can't accept unix client: %s\n", strerror(errno) );
					continue;
				}

				INIT_LIST_HEAD( &unix_client->list );

				FD_SET( unix_client->sock, &wait_sockets );
				if ( unix_client->sock > max_sock )
					max_sock = unix_client->sock;

				/* make unix socket non blocking */
				unix_opts = fcntl( unix_client->sock, F_GETFL, 0 );
				fcntl( unix_client->sock, F_SETFL, unix_opts | O_NONBLOCK );

				list_add_tail( &unix_client->list, &unix_if.client_list );

				debug_output( 3, "Unix socket: got connection\n" );

			/* client sent data */
			} else {

				max_sock = unix_if.unix_sock;

				prev_list_head_unix = (struct list_head *)&unix_if.client_list;

				list_for_each_safe( client_list_pos, unix_pos_tmp, &unix_if.client_list ) {

					unix_client = list_entry( client_list_pos, struct unix_client, list );

					if ( FD_ISSET( unix_client->sock, &tmp_wait_sockets ) ) {

						status = read( unix_client->sock, buff, sizeof( buff ) );
						
						debug_output( 3, "got request: %d, status %d\n", buff[0], status);
						
						if ( status > 0 ) {

							if ( unix_client->sock > max_sock )
								max_sock = unix_client->sock;

							/* debug_output( 3, "gateway: client sent data via unix socket: %s\n", req_buff ); */

							if ( buff[0] == REQ_DEBUG ) {

								if ( ( status > 2 ) && ( ( buff[2] > 0 ) && ( buff[2] <= debug_level_max ) ) ) {

									// TODO: ??? What is this about ???
									if ( unix_client->debug_level != 0 ) {

										debug_output( 3, "unix_client->debug_level != 0 \n");
										
										prev_list_head = (struct list_head *)debug_clients.fd_list[unix_client->debug_level - 1];

										if ( pthread_mutex_lock( (pthread_mutex_t *)debug_clients.mutex[unix_client->debug_level - 1] ) != 0 )
											debug_output( 0, "Error - could not lock mutex (unix_listen => 1): %s \n", strerror( errno ) );

										list_for_each_safe( debug_pos, debug_pos_tmp, (struct list_head *)debug_clients.fd_list[unix_client->debug_level - 1] ) {

											debug_level_info = list_entry( debug_pos, struct debug_level_info, list );

											if ( debug_level_info->fd == unix_client->sock ) {

												list_del( prev_list_head, debug_pos, debug_clients.fd_list[unix_client->debug_level - 1] );
												debug_clients.clients_num[unix_client->debug_level - 1]--;

												debugFree( debug_pos, 1201 );

												break;

											}

											prev_list_head = &debug_level_info->list;

										}

										if ( pthread_mutex_unlock( (pthread_mutex_t *)debug_clients.mutex[unix_client->debug_level - 1] ) != 0 )
											debug_output( 0, "Error - could not unlock mutex (unix_listen => 1): %s \n", strerror( errno ) );

									}

									if ( unix_client->debug_level != buff[2] ) {
										
										if ( pthread_mutex_lock( (pthread_mutex_t *)debug_clients.mutex[buff[2] - 1] ) != 0 )
											debug_output( 0, "Error - could not lock mutex (unix_listen => 2): %s \n", strerror( errno ) );

										debug_level_info = debugMalloc( sizeof(struct debug_level_info), 202 );
										
										INIT_LIST_HEAD( &debug_level_info->list );
										
										debug_level_info->fd = unix_client->sock;
										
										list_add( &debug_level_info->list, (struct list_head_first *)debug_clients.fd_list[buff[2] - 1] );
										
										debug_clients.clients_num[buff[2] - 1]++;

										unix_client->debug_level = buff[2];

										if ( pthread_mutex_unlock( (pthread_mutex_t *)debug_clients.mutex[buff[2] - 1] ) != 0 )
											debug_output( 0, "Error - could not unlock mutex (unix_listen => 2): %s \n", strerror( errno ) );

									} else {

										unix_client->debug_level = 0;

									}

								}

							} else if ( buff[0] == REQ_INFO ) {

								internal_output(unix_client->sock);
								dprintf( unix_client->sock, "EOD\n" );

							} else if ( buff[0] == REQ_1WT ) {
								
								if ( status > 2  ) {
 								
									struct todo_node *new_todo_node;
										
									if ( pthread_mutex_lock( (pthread_mutex_t *)todo_mutex ) != 0 )
										debug_output( 0, "Error - could not lock todo_mutex: %s \n", strerror( errno ) );
			
									new_todo_node = debugMalloc( sizeof( struct todo_node ), 220 );
										
									memset( new_todo_node, 0,  sizeof( struct todo_node ) );
										
									new_todo_node->todo_type = REQ_1WT;
									new_todo_node->def8  = buff[2];
									
									debug_output( 3, "Unix socket: Requesting change og GW speed \n" );
										
									INIT_LIST_HEAD( &new_todo_node->list );
										
									list_add_tail( &new_todo_node->list, &todo_list );
										
									if ( pthread_mutex_unlock( (pthread_mutex_t *)todo_mutex ) != 0 )
										debug_output( 0, "Error - could not unlock mutex: %s \n", strerror( errno ) );
									
								}
								
								dprintf( unix_client->sock, "EOD\n" );
								
							} else if ( buff[0] == REQ_2WT ) {
								
								if ( status > 2  ) {
 								
									struct todo_node *new_todo_node;
										
									if ( pthread_mutex_lock( (pthread_mutex_t *)todo_mutex ) != 0 )
										debug_output( 0, "Error - could not lock todo_mutex: %s \n", strerror( errno ) );
			
									new_todo_node = debugMalloc( sizeof( struct todo_node ), 220 );
										
									memset( new_todo_node, 0,  sizeof( struct todo_node ) );
										
									new_todo_node->todo_type = REQ_2WT;
									new_todo_node->def8  = buff[2];
									
									debug_output( 3, "Unix socket: Requesting change og GW speed \n" );
										
									INIT_LIST_HEAD( &new_todo_node->list );
										
									list_add_tail( &new_todo_node->list, &todo_list );
										
									if ( pthread_mutex_unlock( (pthread_mutex_t *)todo_mutex ) != 0 )
										debug_output( 0, "Error - could not unlock mutex: %s \n", strerror( errno ) );
									
								}
								
								dprintf( unix_client->sock, "EOD\n" );
							
							} else if ( buff[0] == REQ_GW_CLASS ) {

								if ( status > 2  ) {
									
									struct todo_node *new_todo_node;
										
									if ( pthread_mutex_lock( (pthread_mutex_t *)todo_mutex ) != 0 )
										debug_output( 0, "Error - could not lock todo_mutex: %s \n", strerror( errno ) );
			
									new_todo_node = debugMalloc( sizeof( struct todo_node ), 220 );
										
									memset( new_todo_node, 0,  sizeof( struct todo_node ) );
										
									new_todo_node->todo_type = REQ_GW_CLASS;
									new_todo_node->def8  = buff[2];
									
									debug_output( 3, "Unix socket: Requesting change og GW speed \n" );
										
									INIT_LIST_HEAD( &new_todo_node->list );
										
									list_add_tail( &new_todo_node->list, &todo_list );
										
									if ( pthread_mutex_unlock( (pthread_mutex_t *)todo_mutex ) != 0 )
										debug_output( 0, "Error - could not unlock mutex: %s \n", strerror( errno ) );
									
								}

								dprintf( unix_client->sock, "EOD\n" );

								
							} else if ( buff[0] == REQ_RT_CLASS ) {

								if ( status > 2 && ( buff[2] == 0 || (buff[2] <= 3 && probe_tun(0)) ) ) {
									
									struct todo_node *new_todo_node;
										
									if ( pthread_mutex_lock( (pthread_mutex_t *)todo_mutex ) != 0 )
										debug_output( 0, "Error - could not lock todo_mutex: %s \n", strerror( errno ) );
			
									new_todo_node = debugMalloc( sizeof( struct todo_node ), 220 );
										
									memset( new_todo_node, 0,  sizeof( struct todo_node ) );
										
									new_todo_node->todo_type = REQ_RT_CLASS;
									new_todo_node->def8  = buff[2];
									
									debug_output( 3, "Unix socket: Requesting change to -r %d \n", new_todo_node->def8 );
										
									INIT_LIST_HEAD( &new_todo_node->list );
										
									list_add_tail( &new_todo_node->list, &todo_list );
										
									if ( pthread_mutex_unlock( (pthread_mutex_t *)todo_mutex ) != 0 )
										debug_output( 0, "Error - could not unlock mutex: %s \n", strerror( errno ) );
										
								}
								
								dprintf( unix_client->sock, "EOD\n" );

						
							} else if ( buff[0] == REQ_PREF_GW ) {

								if ( status > 2 ) {

									if ( inet_pton( AF_INET, buff + 2, &tmp_ip_holder ) > 0 ) {

										struct todo_node *new_todo_node;
										
										if ( pthread_mutex_lock( (pthread_mutex_t *)todo_mutex ) != 0 )
										debug_output( 0, "Error - could not lock todo_mutex: %s \n", strerror( errno ) );
			
										new_todo_node = debugMalloc( sizeof( struct todo_node ), 220 );
										
										memset( new_todo_node, 0,  sizeof( struct todo_node ) );
										
										new_todo_node->todo_type = REQ_PREF_GW;
										new_todo_node->def32  = tmp_ip_holder.s_addr;
									
										debug_output( 3, "Unix socket: Requesting new preferred GW \n" );
										
										INIT_LIST_HEAD( &new_todo_node->list );
										
										list_add_tail( &new_todo_node->list, &todo_list );
										
										if ( pthread_mutex_unlock( (pthread_mutex_t *)todo_mutex ) != 0 )
										debug_output( 0, "Error - could not unlock mutex: %s \n", strerror( errno ) );
										
									} else {

										debug_output( 3, "Unix socket: rejected new preferred gw (%s) - invalid IP specified\n", buff + 2 );

									}

								}

								dprintf( unix_client->sock, "EOD\n" );

							} else if ( buff[0] == REQ_PWS ) {
								
								if ( status > 2  &&  ((uint8_t)(buff[2])) >= MIN_SEQ_RANGE  &&  ((uint8_t)(buff[2])) <= MAX_SEQ_RANGE ) {

									my_ws = ((uint8_t)(buff[2]));
									
									debug_output( 3, "Unix socket: changing to %s to %d \n", NBRFSIZE_SWITCH, my_ws );
									
									list_for_each( i_list_pos, &if_list ) {

										batman_if = list_entry( i_list_pos, struct batman_if, list );
		
										batman_if->out.ws     = my_ws;
		
									}
										
								}

								dprintf( unix_client->sock, "EOD\n" );

								
							} else if ( buff[0] == REQ_LWS ) {
								
								if ( status > 2  &&  ((uint8_t)(buff[2])) >= MIN_BIDIRECT_TIMEOUT  &&  ((uint8_t)(buff[2])) <= MAX_BIDIRECT_TIMEOUT ) {

									bidirect_link_to = ((uint8_t)(buff[2]));
									
									debug_output( 3, "Unix socket: changing %s to %d \n",BIDIRECT_TIMEOUT_SWITCH, bidirect_link_to );
									
								}

								dprintf( unix_client->sock, "EOD\n" );

								
							} else if ( buff[0] == REQ_DTD ) {
								
								if ( status > 2  ) {
									
									tmp_int = ((uint8_t)(buff[2]));
									
									if ( tmp_int >= MIN_DUP_DEGRAD  &&  ((uint8_t)(buff[2])) <= MAX_DUP_DEGRAD ) {

										dup_degrad = ((uint8_t)(buff[2]));
										
										debug_output( 3, "Unix socket: changing %s to %d \n",DUP_DEGRAD_SWITCH, dup_degrad );
									}
									
								}

								dprintf( unix_client->sock, "EOD\n" );

								
							} else if ( buff[0] == REQ_OGI ) {
								
								if ( status > 2 ) {
									
									tmp_ogi = strtoul( buff+2, NULL, 10 );
									
									if ( tmp_ogi >= MIN_ORIGINATOR_INTERVAL  &&  tmp_ogi <= MAX_ORIGINATOR_INTERVAL ) {

										my_ogi = tmp_ogi;
										
										debug_output( 3, "Unix socket: changing originator interval to %d \n", my_ogi );
									
									}
									
								}

								dprintf( unix_client->sock, "EOD\n" );

								
							} else if ( buff[0] == REQ_CHANGE_HNA ) {

								if ( status > 8 ) {
									struct todo_node *new_todo_node;
									
									tmp_enabled = strtoul( buff+2, NULL, 10 );
									tmp_netmask = strtoul( buff+4, NULL, 10 );
									tmp_address = strtoul( buff+8, NULL, 10 );
									addr_to_string( tmp_address, str, sizeof (str) );

									
									if ( pthread_mutex_lock( (pthread_mutex_t *)todo_mutex ) != 0 )
										debug_output( 0, "Error - could not lock todo_mutex: %s \n", strerror( errno ) );

									debug_output( 3, "Unix socket: Requesting %s of HNA %s/%d - put this on todo list... \n", tmp_enabled?"adding":"removing", str, tmp_netmask   );
									
									
									new_todo_node = debugMalloc( sizeof( struct todo_node ), 220 );
									
									memset( new_todo_node, 0,  sizeof( struct todo_node ) );
									INIT_LIST_HEAD( &new_todo_node->list );
									new_todo_node->add = tmp_enabled;
									new_todo_node->todo_type = REQ_CHANGE_HNA;
									new_todo_node->key.KEY_FIELD_ANETMASK = tmp_netmask;
									new_todo_node->key.KEY_FIELD_ATYPE = A_TYPE_NETWORK;
									new_todo_node->key.addr = tmp_address;
									
									list_add_tail( &new_todo_node->list, &todo_list );
									
									if ( pthread_mutex_unlock( (pthread_mutex_t *)todo_mutex ) != 0 )
										debug_output( 0, "Error - could not unlock mutex (unix_listen => 2): %s \n", strerror( errno ) );
									
								}

								dprintf( unix_client->sock, "EOD\n" );

							} else if ( buff[0] == REQ_CHANGE_SRV ) {

								if ( status > 10 ) {
									struct todo_node *new_todo_node;
									
									tmp_enabled = strtoul( buff+2,  NULL, 10 );
									tmp_port    = strtoul( buff+4,  NULL, 10 );
									tmp_seqno   = strtoul( buff+10, NULL, 10 );
									tmp_address = strtoul( buff+14, NULL, 10 );
									
									addr_to_string( tmp_address, str, sizeof (str) );
									
									if ( pthread_mutex_lock( (pthread_mutex_t *)todo_mutex ) != 0 )
										debug_output( 0, "Error - could not lock todo_mutex: %s \n", strerror( errno ) );

									debug_output( 3, "Unix socket: Requesting %s of service announcement %s:%d:%d - put this on todo list... \n", tmp_enabled?"adding":"removing", str, tmp_seqno, tmp_port   );
									
									new_todo_node = debugMalloc( sizeof( struct todo_node ), 220 );
									
									memset( new_todo_node, 0,  sizeof( struct todo_node ) );
									
									new_todo_node->add = tmp_enabled;
									new_todo_node->todo_type = REQ_CHANGE_SRV;
									new_todo_node->def16 = tmp_port;
									new_todo_node->def8  = tmp_seqno;
									new_todo_node->def32 = tmp_address;
									
									INIT_LIST_HEAD( &new_todo_node->list );
									
									list_add_tail( &new_todo_node->list, &todo_list );
									
									if ( pthread_mutex_unlock( (pthread_mutex_t *)todo_mutex ) != 0 )
										debug_output( 0, "Error - could not unlock mutex (unix_listen => 2): %s \n", strerror( errno ) );
									
								}

								dprintf( unix_client->sock, "EOD\n" );

							
							} else if ( buff[0] == REQ_FAKE_TIME ) {
								
								if ( status > 2 ) {
									
									struct todo_node *new_todo_node;

									debug_output( 3, "Unix socket: Requesting to fake time by %ld sec \n", strtoul( buff+2,  NULL, 10 ) );
									
									if ( pthread_mutex_lock( (pthread_mutex_t *)todo_mutex ) != 0 )
										debug_output( 0, "Error - could not lock todo_mutex: %s \n", strerror( errno ) );

									
									new_todo_node = debugMalloc( sizeof( struct todo_node ), 220 );
									
									memset( new_todo_node, 0,  sizeof( struct todo_node ) );
									
									new_todo_node->todo_type = REQ_FAKE_TIME;
									
									new_todo_node->def32 = strtoul( buff+2,  NULL, 10 );
									
									INIT_LIST_HEAD( &new_todo_node->list );
									
									list_add_tail( &new_todo_node->list, &todo_list );
									
									if ( pthread_mutex_unlock( (pthread_mutex_t *)todo_mutex ) != 0 )
										debug_output( 0, "Error - could not unlock mutex (unix_listen => 2): %s \n", strerror( errno ) );
																	
								}

								dprintf( unix_client->sock, "EOD\n" );

								
							} else if ( buff[0] == REQ_DEFAULT ) {

								dprintf( unix_client->sock, "%s [not-all-options-displayed]", prog_name );

								if ( routing_class > 0 )
									dprintf( unix_client->sock, " -r %i", routing_class );

								if ( pref_gateway > 0 ) {

									addr_to_string( pref_gateway, str, sizeof (str) );

									dprintf( unix_client->sock, " -p %s", str );

								}

								if ( gateway_class > 0 ) {

									get_gw_speeds( gateway_class, &download_speed, &upload_speed );

									dprintf( unix_client->sock, " -g %i%s/%i%s", ( download_speed > 2048 ? download_speed / 1024 : download_speed ), ( download_speed > 2048 ? "MBit" : "KBit" ), ( upload_speed > 2048 ? upload_speed / 1024 : upload_speed ), ( upload_speed > 2048 ? "MBit" : "KBit" ) );

								}

								//TODO: this needs a mutex !?
								list_for_each( i_list_pos, &my_hna_list ) {

									hna_node = list_entry( i_list_pos, struct hna_node, list );

									addr_to_string( hna_node->key.addr, str, sizeof (str) );
									
									if ( hna_node->enabled )
										dprintf( unix_client->sock, " -a %s/%i", str, hna_node->key.KEY_FIELD_ANETMASK );

								}

								//TODO: this needs a mutex !?
								list_for_each( i_list_pos, &my_srv_list ) {

									srv_node = list_entry( i_list_pos, struct srv_node, list );

									addr_to_string( srv_node->srv_addr, str, sizeof (str) );
									
									if ( srv_node->enabled )
										dprintf( unix_client->sock, " --%s %s:%d:%i", ADD_SRV_SWITCH, str, srv_node->srv_port, srv_node->srv_seqno );

								}
								
								list_for_each( i_list_pos, &if_list ) {

									batman_if = list_entry( i_list_pos, struct batman_if, list );

									dprintf( unix_client->sock, " %s", batman_if->dev );

								}

								dprintf( unix_client->sock, "\nEOD\n" );


							}

						} else {

							if ( status < 0 )
								debug_output( 0, "Error - can't read unix message: %s\n", strerror(errno) );

							if ( unix_client->debug_level != 0 ) {

								prev_list_head = (struct list_head *)debug_clients.fd_list[unix_client->debug_level - 1];

								if ( pthread_mutex_lock( (pthread_mutex_t *)debug_clients.mutex[unix_client->debug_level - 1] ) != 0 )
									debug_output( 0, "Error - could not lock mutex (unix_listen => 3): %s \n", strerror( errno ) );

								list_for_each_safe( debug_pos, debug_pos_tmp, (struct list_head *)debug_clients.fd_list[unix_client->debug_level - 1] ) {

									debug_level_info = list_entry( debug_pos, struct debug_level_info, list );

									if ( debug_level_info->fd == unix_client->sock ) {

										list_del( prev_list_head, debug_pos, debug_clients.fd_list[unix_client->debug_level - 1] );
										debug_clients.clients_num[unix_client->debug_level - 1]--;

										debugFree( debug_pos, 1202 );

										break;

									}

									prev_list_head = &debug_level_info->list;

								}

								if ( pthread_mutex_unlock( (pthread_mutex_t *)debug_clients.mutex[unix_client->debug_level - 1] ) != 0 )
									debug_output( 0, "Error - could not unlock mutex (unix_listen => 3): %s \n", strerror( errno ) );

							}

							debug_output( 3, "Unix client closed connection ...\n" );

							FD_CLR(unix_client->sock, &wait_sockets);
							close( unix_client->sock );

							list_del( prev_list_head_unix, client_list_pos, &unix_if.client_list );
							debugFree( client_list_pos, 1203 );
							unix_client_deleted = YES;

						}

					} else {

						if ( unix_client->sock > max_sock )
							max_sock = unix_client->sock;

					}
					
					if (!unix_client_deleted)
						prev_list_head_unix = &unix_client->list;
					
					unix_client_deleted = NO;

				}

			}

		} else if ( ( res < 0 ) && ( errno != EINTR ) ) {

			debug_output( 0, "Error - can't select: %s\n", strerror(errno) );
			break;

		}

	}

	list_for_each_safe( client_list_pos, unix_pos_tmp, &unix_if.client_list ) {

		unix_client = list_entry( client_list_pos, struct unix_client, list );

		if ( unix_client->debug_level != 0 ) {
			
			prev_list_head = (struct list_head *)debug_clients.fd_list[unix_client->debug_level - 1];
			
			if ( pthread_mutex_lock( (pthread_mutex_t *)debug_clients.mutex[unix_client->debug_level - 1] ) != 0 )
				debug_output( 0, "Error - could not lock mutex (unix_listen => 4): %s \n", strerror( errno ) );
				
			list_for_each_safe( debug_pos, debug_pos_tmp, (struct list_head *)debug_clients.fd_list[unix_client->debug_level - 1] ) {

				debug_level_info = list_entry(debug_pos, struct debug_level_info, list);

				if ( debug_level_info->fd == unix_client->sock ) {

					list_del( prev_list_head, debug_pos, debug_clients.fd_list[unix_client->debug_level - 1] );
					debug_clients.clients_num[unix_client->debug_level - 1]--;

					debugFree( debug_pos, 1204 );

					break;

				}
				
				prev_list_head = &debug_level_info->list;

			}
			
			if ( pthread_mutex_unlock( (pthread_mutex_t *)debug_clients.mutex[unix_client->debug_level - 1] ) != 0 )
				debug_output( 0, "Error - could not unlock mutex (unix_listen => 4): %s \n", strerror( errno ) );
			
		}

		list_del( (struct list_head *)&unix_if.client_list, client_list_pos, &unix_if.client_list );
		debugFree( client_list_pos, 1205 );

	}

	return NULL;

}

