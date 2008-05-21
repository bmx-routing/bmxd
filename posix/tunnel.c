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



#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__Darwin__)
#include <sys/sockio.h>
#endif
#include <net/if.h>
#include <fcntl.h>        /* open(), O_RDWR */


#include "../os.h"
#include "../batman.h"






uint32_t request_tun_ip( struct curr_gw_data *curr_gw_data, struct sockaddr_in *gw_addr, int32_t udp_sock, uint32_t *pref_addr, 
   			uint32_t *ip_lease_stamp, uint32_t *new_ip_stamp,
			char *tun_if, int32_t *tun_fd, int32_t *tun_ifi, struct tun_packet *tp ) 
{

	char pref_str[ADDR_STR_LEN], gw_str[ADDR_STR_LEN];

	addr_to_string( gw_addr->sin_addr.s_addr, gw_str, sizeof(gw_str) );
	addr_to_string( *pref_addr, pref_str, sizeof(pref_str) );
	
	debug_output( 3, "send ip request to gateway: %s, preferred IP: %s \n", gw_str, pref_str );
	
	memset( &tp->tt, 0, sizeof(tp->tt) );
	tp->TP_VERS = COMPAT_VERSION;
	tp->TP_TYPE = TUNNEL_IP_REQUEST;

	if( *pref_addr )
		tp->LEASE_IP = *pref_addr;
	
	if ( sendto( udp_sock, &tp->start, TX_RP_SIZE, 0, (struct sockaddr *)gw_addr, sizeof(struct sockaddr_in) ) < 0 ) {

		debug_output( 0, "Error - can't send ip request to gateway: %s \n", strerror(errno) );
	
	} 

	return 1;
	
}

uint32_t handle_tun_ip_reply( 
  struct curr_gw_data *curr_gw_data, 	//
  struct sockaddr_in *gw_addr, 		//
  int32_t udp_sock, 			//
  uint32_t *pref_addr,			//
  uint32_t *ip_lease_stamp, 		//
  uint32_t *new_ip_stamp,		//
  char *tun_if, 			//
  int32_t *tun_fd, 			//
  int32_t *tun_ifi, 			//
  struct tun_packet *tp,		//
  struct sockaddr_in *sender_addr, 	//
  int32_t rcv_buff_len, 		//
  uint32_t current_time			//
			    )
{
	
	char pref_str[ADDR_STR_LEN], tmp_str[ADDR_STR_LEN], gw_str[ADDR_STR_LEN];
	
	addr_to_string( gw_addr->sin_addr.s_addr, gw_str, sizeof(gw_str) );

	if ( sender_addr->sin_addr.s_addr == gw_addr->sin_addr.s_addr && rcv_buff_len == TX_RP_SIZE && tp->TP_TYPE == TUNNEL_IP_REPLY ) {

		tp->LEASE_LT = ntohs( tp->LEASE_LT );
		
		addr_to_string( *pref_addr, pref_str, sizeof(pref_str) );
		addr_to_string( tp->LEASE_IP, tmp_str, sizeof(tmp_str) );
		debug_output( 3, "Gateway client - got IP %s (preferred: IP %s) from gateway: %s for %d seconds.\n", tmp_str, pref_str, gw_str, tp->LEASE_LT );

		if ( tp->LEASE_LT < MIN_TUNNEL_IP_LEASE_TIME ) {

			curr_gw_data->gw_node->last_failure = current_time;
			curr_gw_data->gw_node->unavail_factor++;
			
			debug_output( 3, "Gateway client - unacceptable virtual IP lifetime, ignoring this GW for %d secs\n",
				      ( curr_gw_data->gw_node->unavail_factor * curr_gw_data->gw_node->unavail_factor * GW_UNAVAIL_TIMEOUT )/1000 );
			
			curr_gateway = NULL;
			return 0;
		}

		if ( *pref_addr == 0 ) {

			if (add_dev_tun( tp->LEASE_IP, tun_if, sizeof(tun_if), tun_fd, tun_ifi ) <= 0 ) {
		
				curr_gw_data->gw_node->last_failure = current_time;
				curr_gw_data->gw_node->unavail_factor++;
				
				debug_output( 3, "Gateway client - could not add tun device, ignoring this GW for %d secs\n", 
					      ( curr_gw_data->gw_node->unavail_factor * curr_gw_data->gw_node->unavail_factor * GW_UNAVAIL_TIMEOUT )/1000 );
				
				curr_gateway = NULL;
				return 0;
			}
	
			add_del_route( 0, 0, 0, 0, *tun_ifi, tun_if, BATMAN_RT_TABLE_TUNNEL, 0, 0 );
			*new_ip_stamp = current_time;

		} else if ( *pref_addr != tp->LEASE_IP ) {
	
			if ( set_tun_addr( udp_sock, tp->LEASE_IP, tun_if ) < 0 ) {
		
				curr_gw_data->gw_node->last_failure = current_time;
				curr_gw_data->gw_node->unavail_factor++;
				
				debug_output( 3, "Gateway client - obtained strange IP, ignoring this GW for %d secs\n", 
					      ( curr_gw_data->gw_node->unavail_factor * curr_gw_data->gw_node->unavail_factor * GW_UNAVAIL_TIMEOUT )/1000 );
				
				curr_gateway = NULL;
				return 0;
			}
	
			/* kernel deletes routes after resetting the interface ip */
			add_del_route( 0, 0, 0, 0, *tun_ifi, tun_if, BATMAN_RT_TABLE_TUNNEL, 0, 0 );
			*new_ip_stamp = current_time;
		}

		*ip_lease_stamp = current_time;
		*pref_addr = tp->LEASE_IP;

		return tp->LEASE_LT;

	} 
		
	debug_output( 0, "Error - can't receive ip request: sender IP, packet type, packet size (%i) do not match \n", rcv_buff_len );
	
	curr_gw_data->gw_node->last_failure = current_time;
	curr_gw_data->gw_node->unavail_factor++;
			
	debug_output( 3, "Gateway client - rcvd invalid reply, ignoring this GW for %d secs\n", 
			( curr_gw_data->gw_node->unavail_factor * curr_gw_data->gw_node->unavail_factor * GW_UNAVAIL_TIMEOUT )/1000 );
			
	curr_gateway = NULL;
	return 0;

}


void *client_to_gw_tun( void *arg ) {

	struct curr_gw_data *curr_gw_data = (struct curr_gw_data *)arg;
	struct sockaddr_in gw_addr, my_addr, sender_addr;
	struct iphdr *iphdr;
	struct timeval tv;
	struct list_head_first packet_list;
	int32_t res, max_sock, udp_sock=0, tun_fd=0, tun_ifi, sock_opts;
	uint32_t addr_len, current_time, ip_lease_stamp = 0, ip_lease_duration = 0, gw_state_stamp = 0, new_ip_stamp = 0, my_tun_addr = 0;
	uint32_t last_invalidip_warning = 0, tun_ip_request_stamp = 0;
	char tun_if[IFNAMSIZ], my_str[ADDR_STR_LEN], is_str[ADDR_STR_LEN], gw_str[ADDR_STR_LEN], str2[ADDR_STR_LEN];
 	uint8_t gw_state = GW_STATE_UNKNOWN, prev_gw_state = GW_STATE_UNKNOWN;
	int32_t tp_data_len, tp_len, send_tun_ip_requests = 0, invalid_tun_ip = 1;
	struct tun_packet tp;
	fd_set wait_sockets;
	uint16_t dns_port = htons( 53 );
	uint8_t disconnect = NO, which_tunnel = 0, which_tunnel_max = 0;
	
	current_time = get_time_msec();

	memset( &tp, 0, sizeof( tp ) );
	
	addr_len = sizeof (struct sockaddr_in);
	
	addr_to_string( curr_gw_data->orig, gw_str, sizeof(gw_str) );

	INIT_LIST_HEAD_FIRST(packet_list);

	memset( &gw_addr, 0, sizeof(struct sockaddr_in) );
	memset( &my_addr, 0, sizeof(struct sockaddr_in) );

	gw_addr.sin_family = AF_INET;
	/* the cached gw_msg stores the network byte order, so no need to transform */
	gw_addr.sin_port = curr_gw_data->gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWPORT;
	gw_addr.sin_addr.s_addr = curr_gw_data->gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWADDR;

	my_addr.sin_family = AF_INET;
	/* the cached gw_msg stores the network byte order, so no need to transform */
	my_addr.sin_port = curr_gw_data->gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWPORT;
	my_addr.sin_addr.s_addr = curr_gw_data->batman_if->addr.sin_addr.s_addr;

	if ( two_way_tunnel > which_tunnel_max && (curr_gw_data->gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWTYPES & TWO_WAY_TUNNEL_FLAG) ){
		
		which_tunnel = TWO_WAY_TUNNEL_FLAG;
		which_tunnel_max = two_way_tunnel;
		
	}
	
	if (one_way_tunnel > which_tunnel_max && (curr_gw_data->gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWTYPES & ONE_WAY_TUNNEL_FLAG) ) {
			
		which_tunnel = ONE_WAY_TUNNEL_FLAG;
		which_tunnel_max = one_way_tunnel;
	
	}
	
	/* connect to server (establish udp tunnel) */
	if ( ( udp_sock = socket( PF_INET, SOCK_DGRAM, 0 ) ) < 0 ) {

		debug_output( 0, "Error - can't create udp socket: %s\n", strerror(errno) );
		curr_gateway = NULL;
		debugFree( arg, 1207 );
		return NULL;

	}

	if ( bind( udp_sock, (struct sockaddr *)&my_addr, sizeof(struct sockaddr_in) ) < 0 ) {

		debug_output( 0, "Error - can't bind tunnel socket: %s\n", strerror(errno) );
		close( udp_sock );
		curr_gateway = NULL;
		debugFree( arg, 1207 );
		return NULL;

	}


	/* make udp socket non blocking */
	sock_opts = fcntl( udp_sock, F_GETFL, 0 );
	fcntl( udp_sock, F_SETFL, sock_opts | O_NONBLOCK );

	

	if ( which_tunnel & ONE_WAY_TUNNEL_FLAG ) {
		
		if (add_dev_tun(  curr_gw_data->batman_if->addr.sin_addr.s_addr, tun_if, sizeof(tun_if), &tun_fd, &tun_ifi ) <= 0 ) {
		
			curr_gw_data->gw_node->last_failure = current_time;
			curr_gw_data->gw_node->unavail_factor++;
			
			debug_output( 3, "Gateway client - could not add tun device, ignoring this GW for %d secs\n",
				      ( curr_gw_data->gw_node->unavail_factor * curr_gw_data->gw_node->unavail_factor * GW_UNAVAIL_TIMEOUT )/1000 );
			
			curr_gateway = NULL;
			close( udp_sock );
			debugFree( arg, 1207 );
			return NULL;
			
		}
		
		curr_gw_data->gw_node->last_failure = current_time;
		curr_gw_data->gw_node->unavail_factor = 0;

		add_del_route( 0, 0, 0, 0, tun_ifi, tun_if, BATMAN_RT_TABLE_TUNNEL, 0, 0 );

		my_tun_addr = curr_gw_data->batman_if->addr.sin_addr.s_addr;
		tun_ip_request_stamp = 0;
		send_tun_ip_requests = 0;
		invalid_tun_ip = 0;
		
	}
	
	while ( ( !is_aborted() ) && ( curr_gateway != NULL ) && ( ! curr_gw_data->gw_node->deleted ) && 
		(which_tunnel & curr_gw_data->gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWTYPES) ) {

		// obtain virtual IP and refresh leased IP  when 90% of lease_duration has expired
		if ( (which_tunnel & TWO_WAY_TUNNEL_FLAG) && 
			LESS_U32( (tun_ip_request_stamp + TUNNEL_IP_REQUEST_TIMEOUT), current_time) &&
			( invalid_tun_ip || LESS_U32((ip_lease_stamp + (((ip_lease_duration * 1000)/10)*9) ), current_time) ) ) {
			
			request_tun_ip( curr_gw_data, &gw_addr, udp_sock, &my_tun_addr, &ip_lease_stamp, &new_ip_stamp, tun_if, &tun_fd, &tun_ifi, &tp );
			tun_ip_request_stamp = current_time;
			send_tun_ip_requests++;
		}

		
		tv.tv_sec = 0;
		tv.tv_usec = (1000*MAX_SELECT_TIMEOUT_MS); //250 question: why so small? to react faster on pthread_join?

		FD_ZERO(&wait_sockets);
		
		if( udp_sock ) 
			FD_SET(udp_sock, &wait_sockets);
		
		if( tun_fd )
			FD_SET(tun_fd, &wait_sockets);

		max_sock = ( udp_sock > tun_fd ? udp_sock : tun_fd );
		
		res = select( max_sock + 1, &wait_sockets, NULL, NULL, &tv );

		current_time = get_time_msec();
	
		if ( ( res < 0 ) && ( errno != EINTR ) ) {

			debug_output( 0, "Error - can't select: %s\n", strerror(errno) );
			break;
		}

		if ( res > 0 ) {

			// udp tunnel message from gateway (to be detunnelled)
			if ( udp_sock && FD_ISSET( udp_sock, &wait_sockets ) ) {
		
				while ( ( tp_len = recvfrom( udp_sock, (unsigned char*)&tp.start, TX_DP_SIZE, 0, (struct sockaddr *)&sender_addr, &addr_len ) ) > 0 ) {
					
					if ( tp_len < TX_RP_SIZE ) {
						
						addr_to_string( sender_addr.sin_addr.s_addr, str2, sizeof(str2) );
						debug_output( 0, "Client node - Received Invalid packet size (%d) via tunnel, from %s ! \n", tp_len, str2 );
						continue;
						
					}

					if ( tp.TP_VERS != COMPAT_VERSION ) {
						
						addr_to_string( sender_addr.sin_addr.s_addr, str2, sizeof(str2) );
						debug_output( 0, "Client node - Received Invalid compat version (%d) via tunnel, from %s ! \n", tp.TP_VERS, str2 );
						continue;
						
					}
		
					tp_data_len = tp_len - sizeof(tp.start);
					
					if ( (which_tunnel & TWO_WAY_TUNNEL_FLAG) && ( sender_addr.sin_addr.s_addr == gw_addr.sin_addr.s_addr ) ) {
		
						// got data from gateway
						if ( tp.TP_TYPE == TUNNEL_DATA ) {
							
							if ( tp_data_len >= sizeof(struct iphdr) && ((struct iphdr *)(tp.IP_PACKET))->version == 4 ) {
		
								if ( write( tun_fd, tp.IP_PACKET, tp_data_len ) < 0 )
									debug_output( 0, "Error - can't write packet: %s\n", strerror(errno) );
		
								if ( !no_unresponsive_check && ((struct iphdr *)(tp.IP_PACKET))->protocol != IPPROTO_ICMP  ) {
							
									gw_state = GW_STATE_VERIFIED;
									gw_state_stamp = current_time;
									
									curr_gw_data->gw_node->last_failure = current_time;
									curr_gw_data->gw_node->unavail_factor = 0;

									
									if( prev_gw_state != gw_state ) {
										debug_output( 3, "changed GW state: from %d to %d, incoming IP protocol: %d\n", prev_gw_state, gw_state, ((struct iphdr *)(tp.IP_PACKET))->protocol );
										prev_gw_state = gw_state;
									}
		
								}
							
							} else {
								
								debug_output( 3, "only IPv4 packets supported so fare !!!\n");
								
							}
							
						} else if ( tp.TP_TYPE == TUNNEL_IP_REPLY ) {
							
							debug_output( 3, "Gateway client - gateway (%s) replyed with virtual IP \n", gw_str );
		
							if ( (ip_lease_duration = handle_tun_ip_reply( curr_gw_data, &gw_addr, udp_sock, &my_tun_addr, &ip_lease_stamp, &new_ip_stamp, tun_if, &tun_fd, &tun_ifi, &tp, &sender_addr, tp_len, current_time )) < MIN_TUNNEL_IP_LEASE_TIME ) {
		
								
								disconnect = YES;
								break;
							}
							
							invalid_tun_ip  = 0;
							send_tun_ip_requests = 0;
							addr_to_string( my_tun_addr,  my_str, sizeof(my_str) );
							debug_output( 3, "Gateway client - refreshed IP %s \n", my_str);
							
								
						// gateway told us that we have no valid IP
						} else if ( tp.TP_TYPE == TUNNEL_IP_INVALID ) {
		
							addr_to_string( my_tun_addr, my_str, sizeof(my_str) );
							debug_output( 3, "Gateway client - gateway (%s) says: IP (%s) is expired \n", gw_str, my_str );
		
							request_tun_ip( curr_gw_data, &gw_addr, udp_sock, &my_tun_addr, &ip_lease_stamp, &new_ip_stamp, tun_if, &tun_fd, &tun_ifi, &tp );
		
							tun_ip_request_stamp = current_time;
							send_tun_ip_requests = 1;
							invalid_tun_ip = 1;

						}
		
					} else {
		
						addr_to_string( sender_addr.sin_addr.s_addr, my_str, sizeof(my_str) );
						debug_output( 0, "Error - ignoring gateway packet from %s! Wrong GW or packet too small (%i)\n", my_str, tp_len );
						if ( which_tunnel & ONE_WAY_TUNNEL_FLAG )
							debug_output( 0, "Gateway client, being in %s mode\n", ONE_WAY_TUNNEL_SWITCH );
		
					}
		
				}
		
				if ( disconnect )
					break;
				
				if ( errno != EWOULDBLOCK ) {
		
					debug_output( 0, "Error - gateway client can't receive packet: %s\n", strerror(errno) );
					break;
		
				}
		
			// Got data to be send to gateway
			} else if ( tun_fd && FD_ISSET( tun_fd, &wait_sockets ) ) {
		
				while ( ( tp_data_len = read( tun_fd, tp.IP_PACKET, sizeof(tp.IP_PACKET) /*TBD: why -2 here? */ ) ) > 0 ) {
					
					tp_len = tp_data_len + sizeof(tp.start);
					
					if ( tp_data_len < sizeof(struct iphdr) || ((struct iphdr *)(tp.IP_PACKET))->version != 4 ) {
						
						debug_output( 0, "Gateway client - Received Invalid packet type via tunnel ! \n" );
						continue;
						
					}
					
					tp.TP_VERS = COMPAT_VERSION;
					tp.TP_TYPE = TUNNEL_DATA;
		
					iphdr = (struct iphdr *)(tp.IP_PACKET);
		
					if ( my_tun_addr == 0 ) {
						
						curr_gw_data->gw_node->last_failure = current_time;
						curr_gw_data->gw_node->unavail_factor++;
						
						debug_output( 0, "Gateway client - No vitual IP! Ignoring this GW for %d secs\n",
								( curr_gw_data->gw_node->unavail_factor * curr_gw_data->gw_node->unavail_factor * GW_UNAVAIL_TIMEOUT )/1000 );
						
								
						disconnect = YES;
						break;
					}
					
					
					if ( (which_tunnel & ONE_WAY_TUNNEL_FLAG) || 
					     ((which_tunnel & TWO_WAY_TUNNEL_FLAG) && !invalid_tun_ip && iphdr->saddr == my_tun_addr) ) {
						
						if ( sendto( udp_sock, (unsigned char*) &tp.start, tp_len, 0, (struct sockaddr *)&gw_addr, sizeof (struct sockaddr_in) ) < 0 ) {
							debug_output( 0, "Error - can't send data to gateway: %s\n", strerror(errno) );
							
						}
					
						// activate unresponsive GW check only based on TCP and DNS data
						if ( (which_tunnel & TWO_WAY_TUNNEL_FLAG) && !no_unresponsive_check && gw_state == GW_STATE_UNKNOWN &&  gw_state_stamp == 0 ) {
					
							if( ( (((struct iphdr *)(tp.IP_PACKET))->protocol == IPPROTO_TCP )) || 
								( (((struct iphdr *)(tp.IP_PACKET))->protocol == IPPROTO_UDP) && 
								(((struct udphdr *)(tp.IP_PACKET + ((struct iphdr *)(tp.IP_PACKET))->ihl*4))->dest == dns_port)  )
								) {
						
									gw_state_stamp = current_time;
					
								}
						}
		
		
					} else if ( last_invalidip_warning == 0 || LESS_U32((last_invalidip_warning + WARNING_PERIOD), current_time) ) {
						
						last_invalidip_warning = current_time;
							
						addr_to_string( my_tun_addr,  my_str, sizeof(my_str) );
						addr_to_string( iphdr->saddr, is_str, sizeof(is_str) );
						debug_output( 3, "Gateway client - IP age: %d,  Invalid outgoing src IP: %s (should be %s)! %s Dropping packet\n", (current_time - new_ip_stamp),  is_str,  my_str, (invalid_tun_ip ? "GW said invalid IP!":"") );
						
					}
				}
				
				if ( disconnect )
					break;
		
				if ( errno != EWOULDBLOCK ) {
		
					debug_output( 0, "Error - gateway client can't read tun data: %s\n", strerror(errno) );
					break;
		
				}
		
			}

		}
		
		// drop connection to gateway if the gateway does not respond 
		if ( send_tun_ip_requests >= MAX_TUNNEL_IP_REQUESTS || 
			(!no_unresponsive_check && 
				   ( gw_state == GW_STATE_UNKNOWN ) && 
				   ( gw_state_stamp != 0 ) && 
				   LESS_U32( ( gw_state_stamp + GW_STATE_UNKNOWN_TIMEOUT ), current_time ) ) ) {
			
			debug_output( 3, "Gateway client - disconnecting from unresponsive gateway (%s) !\n", gw_str );
			
			if( send_tun_ip_requests >= MAX_TUNNEL_IP_REQUESTS )
				debug_output( 3, "Gateway client - Maximum number of tunnel ip requests send !\n" );
			else
				debug_output( 3, "Gateway client - GW seems to be a blackhole! Use --%s to disable this check!\n", NO_UNRESP_CHECK_SWITCH );

			curr_gw_data->gw_node->last_failure = current_time;
			curr_gw_data->gw_node->unavail_factor++;
			
			debug_output( 3, "Gateway client - Ignoring this GW for %d secs\n",
				      ( curr_gw_data->gw_node->unavail_factor * curr_gw_data->gw_node->unavail_factor * GW_UNAVAIL_TIMEOUT )/1000 );

			break;
		}
		
		// change back to unknown state if gateway did not respond in time
		if ( ( gw_state == GW_STATE_VERIFIED ) && LESS_U32( (gw_state_stamp + GW_STATE_VERIFIED_TIMEOUT), current_time ) ) {

			gw_state = GW_STATE_UNKNOWN;
			gw_state_stamp = 0; // the timer is not started before the next packet is send to the GW
			if( prev_gw_state != gw_state ) 
				debug_output( 3, "changed GW state: %d\n", prev_gw_state = gw_state );

		}
		
	}

	debug_output( 3, "terminating client_to_gw_tun thread: is_aborted(): %s, curr_gateway: %ld, deleted: %d \n", (is_aborted()? "YES":"NO"), curr_gateway, curr_gw_data->gw_node->deleted );
	
	// cleanup:
	
	add_del_route( 0, 0, 0, 0, tun_ifi, tun_if, BATMAN_RT_TABLE_TUNNEL, 0, 1 );
	del_dev_tun( tun_fd );

	close( udp_sock );
	curr_gateway = NULL;
	debugFree( arg, 1207 );
	return NULL;

}

void cleanup_leased_tun_ips( uint32_t lt, struct gw_client **gw_client_list, uint32_t my_tun_ip, uint32_t my_tun_netmask ) {
	
	char str[ADDR_STR_LEN], cl_addr[ADDR_STR_LEN];
	uint32_t i, i_max, current_time;
	
	current_time = get_time_msec();
	
	i_max = ntohl( ~my_tun_netmask );

	for ( i = 0; i < i_max; i++ ) {

		if ( gw_client_list[i] != NULL ) {

			if ( LSEQ_U32( ( gw_client_list[i]->last_keep_alive + (lt * 1000) ), current_time ) ) {

				addr_to_string( ((my_tun_ip & my_tun_netmask) | ntohl(i)), str, sizeof(str) );
				addr_to_string( gw_client_list[i]->addr, cl_addr, sizeof(cl_addr) );
				debug_output( 3, "Gateway - TunIP %s of client: %s timed out\n", str, cl_addr );

				debugFree( gw_client_list[i], 1216 );
				gw_client_list[i] = NULL;

			}

		}

	}

}


uint8_t get_ip_addr(uint32_t client_addr, uint32_t *pref_addr, struct gw_client **gw_client_list, uint32_t my_tun_ip, uint32_t my_tun_netmask, uint32_t curr_time ) {

	uint32_t first_free = 0, i, i_max, i_pref, i_random, trick, i_begin, i_end;
	
	i_max = ntohl( ~my_tun_netmask );
	
	if ( (*pref_addr & my_tun_netmask) != (my_tun_ip & my_tun_netmask) )
		*pref_addr = 0;
	
	i_pref = ntohl( *pref_addr ) & ntohl( ~my_tun_netmask );
	
	if ( i_pref >= i_max )
		i_pref = 0;
	
	// try to renew virtual IP lifetime
	if ( i_pref > 0 && gw_client_list[i_pref] != NULL && gw_client_list[i_pref]->addr == client_addr ) {
		
		gw_client_list[i_pref]->last_keep_alive = curr_time;
		return YES;
		
	// client asks for a virtual IP which has already been leased to somebody else
	} else if ( i_pref > 0 && gw_client_list[i_pref] != NULL && gw_client_list[i_pref]->addr != client_addr ) {
		
		*pref_addr = 0;
		i_pref = 0;
		
	}
	
	// try to give clients always the same virtual IP
	i_random = (ntohl(client_addr) % (i_max-1)) + 1;
	
	for ( trick = 0; trick <= 1; trick ++ ) {
	
		if( trick == 0 ) {
			i_begin = i_random;
			i_end = i_max;
		} else {
			i_begin = 1;
			i_end = i_random;
		}
		
		for ( i = i_begin; i < i_end; i++ ) {
		
			if ( gw_client_list[i] != NULL && gw_client_list[i]->addr == client_addr ) {
		
				// take this one! Why give this client another one than last time?.
				gw_client_list[i]->last_keep_alive = curr_time;
				*pref_addr = (my_tun_ip & my_tun_netmask) | htonl( i );
				return YES;
		
			} else if ( first_free == 0 && gw_client_list[i] == NULL ) {
		
				// remember the first randomly-found free virtual IP
				first_free = i;
		
			}
		}
	}
	
	// give client its preferred virtual IP
	if ( i_pref > 0 && gw_client_list[i_pref] == NULL ) {
		
		gw_client_list[i_pref] = debugMalloc( sizeof(struct gw_client), 208 );
		memset( gw_client_list[i_pref], 0, sizeof(struct gw_client) );
		gw_client_list[i_pref]->addr = client_addr;
		gw_client_list[i_pref]->last_keep_alive = curr_time;
		*pref_addr = (my_tun_ip & my_tun_netmask) | htonl( i_pref );
		return YES;
	}
	
	if ( first_free == 0 ) {

		debug_output( 0, "Error - can't get IP for client: maximum number of clients reached\n" );
		*pref_addr = 0;
		return NO;

	}

	gw_client_list[first_free] = debugMalloc( sizeof(struct gw_client), 208 );
	memset( gw_client_list[first_free], 0, sizeof(struct gw_client) );
	gw_client_list[first_free]->addr = client_addr;
	gw_client_list[first_free]->last_keep_alive = curr_time;
	*pref_addr = (my_tun_ip & my_tun_netmask) | htonl( first_free );
	
	return YES;

}



void *gw_listen( void *arg ) {

//	struct batman_if *batman_if = (*((struct gw_listen_arg *)arg)).batman_if;
	struct gw_listen_arg *gw_listen_arg = ((struct gw_listen_arg *)arg);
	
	struct gw_client **gw_client_list = gw_listen_arg->gw_client_list;
	
	struct timeval tv;
	struct sockaddr_in addr, client_addr /*, pack_dest */;
	struct iphdr *iphdr;
	char vstr[16], str[16], str2[16],  tun_dev[IFNAMSIZ];
	int32_t res, max_sock, tun_fd, tun_ifi;
	uint32_t addr_len, purge_timeout, c_time_ms;
	uint32_t my_tun_ip, my_tun_netmask, my_tun_ip_h, my_tun_suffix_mask_h, iph_addr_suffix_h;
	fd_set wait_sockets, tmp_wait_sockets;
	int32_t tp_data_len, tp_len;
	struct tun_packet tp;

	memset( &tp, 0, sizeof( struct tun_packet ) );
	
	my_tun_ip = gw_listen_arg->prefix;
	my_tun_netmask = htonl( 0xFFFFFFFF<<(32-(gw_listen_arg->netmask)) );
	
	addr_to_string( my_tun_ip, str, sizeof(str) );
	addr_to_string( my_tun_netmask, str2, sizeof(str2) );
	debug_output( 3, "gw_listen(): my_tun_ip %s, my_tun_netmask: %s \n", str, str2);
	
	my_tun_ip_h = ntohl( my_tun_ip );
	my_tun_suffix_mask_h = ntohl( ~my_tun_netmask );
	
	addr_len = sizeof (struct sockaddr_in);
	purge_timeout = get_time_msec();


	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(gw_listen_arg->port);

	
	if ( add_dev_tun( my_tun_ip, tun_dev, sizeof(tun_dev), &tun_fd, &tun_ifi ) < 0 ) {
		debugFree( gw_client_list, 1210);
		close( gw_listen_arg->sock );
		gw_listen_arg->sock = 0;
		debugFree( gw_listen_arg, 1223 );
		return NULL;
	}

	add_del_route( my_tun_ip, gw_listen_arg->netmask, 0, 0, tun_ifi, tun_dev, 254, 0, 0 );

	FD_ZERO(&wait_sockets);
	FD_SET(gw_listen_arg->sock, &wait_sockets);
	FD_SET(tun_fd, &wait_sockets);

	max_sock = ( gw_listen_arg->sock > tun_fd ? gw_listen_arg->sock : tun_fd );

	while ( ( !is_aborted() ) && !gw_thread_finish && ( gw_listen_arg->owt || gw_listen_arg->twt ) ) {

		tv.tv_sec = 0;
		tv.tv_usec = (1000*MAX_SELECT_TIMEOUT_MS);
		memcpy( &tmp_wait_sockets, &wait_sockets, sizeof(fd_set) );

		res = select( max_sock + 1, &tmp_wait_sockets, NULL, NULL, &tv );
		
		c_time_ms = get_time_msec();

		if ( res > 0 ) {

			/* is udp packet from GW-Client*/
			if ( FD_ISSET( gw_listen_arg->sock, &tmp_wait_sockets ) ) {

				while ( ( tp_len = recvfrom( gw_listen_arg->sock, (unsigned char*)&tp.start, TX_DP_SIZE, 0, (struct sockaddr *)&addr, &addr_len ) ) > 0 ) {

					if ( tp_len < TX_RP_SIZE ) {
						
						addr_to_string( addr.sin_addr.s_addr, str2, sizeof(str2) );
						debug_output( 0, "Gateway node - Received Invalid packet size (%d) via tunnel, from %s ! \n", tp_len, str2 );
						continue;
						
					}

					if ( tp.TP_VERS != COMPAT_VERSION ) {
						
						addr_to_string( addr.sin_addr.s_addr, str2, sizeof(str2) );
						debug_output( 0, "Gateway node - Received Invalid compat version (%d) via tunnel, from %s ! \n", tp.TP_VERS, str2 );
						continue;
						
					}

					tp_data_len = tp_len - sizeof(tp.start);
				
					if ( tp.TP_TYPE == TUNNEL_DATA ) {
						
						if ( !(tp_data_len >= sizeof(struct iphdr) && ((struct iphdr *)(tp.IP_PACKET))->version == 4 ) ) {
				
							debug_output( 0, "Gateway node - Received Invalid packet type via tunnel ! \n" );
							continue;
				
						}
						
						iphdr = (struct iphdr *)(tp.IP_PACKET);
						
						
						if ( gw_listen_arg->owt &&
						     ( (iphdr->saddr & my_tun_netmask) != my_tun_ip ||
						       iphdr->saddr == addr.sin_addr.s_addr ) ) {
							
							if ( write( tun_fd, tp.IP_PACKET, tp_data_len ) < 0 )  
								debug_output( 0, "Error - can't write packet: %s\n", strerror(errno) );
							
							continue;

						}
						
						
						if ( gw_listen_arg->twt ) {
						
							iph_addr_suffix_h = ntohl( iphdr->saddr ) & ntohl( ~my_tun_netmask );
	
							/* check if client IP is known */
							if ( !((iphdr->saddr & my_tun_netmask) == my_tun_ip &&
									iph_addr_suffix_h > 0 &&
									iph_addr_suffix_h < my_tun_suffix_mask_h &&
									gw_client_list[ iph_addr_suffix_h ] != NULL &&
									gw_client_list[ iph_addr_suffix_h ]->addr == addr.sin_addr.s_addr) ) {
									
								memset( &tp.tt.trt, 0, sizeof(tp.tt.trt));
								tp.TP_VERS = COMPAT_VERSION;
								tp.TP_TYPE = TUNNEL_IP_INVALID;
								
								addr_to_string( addr.sin_addr.s_addr, str, sizeof(str) );
								addr_to_string( iphdr->saddr, vstr, sizeof(vstr) );
	
								debug_output( 0, "Error - got packet from unknown client: %s (virtual ip %s) \n", str, vstr); 
								
								if ( sendto( gw_listen_arg->sock, (unsigned char*)&tp.start, TX_RP_SIZE, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in) ) < 0 )
									debug_output( 0, "Error - can't send invalid ip information to client (%s): %s \n", str, strerror(errno) );
	
								continue;
	
							}
														
							if ( write( tun_fd, tp.IP_PACKET, tp_data_len ) < 0 )  
								debug_output( 0, "Error - can't write packet: %s\n", strerror(errno) );  
							
						}
					
					} else if ( tp.TP_TYPE == TUNNEL_IP_REQUEST && gw_listen_arg->twt ) {
						
						if ( get_ip_addr( addr.sin_addr.s_addr, &tp.LEASE_IP, gw_client_list, my_tun_ip, my_tun_netmask, c_time_ms ) )
							tp.LEASE_LT = htons( gw_listen_arg->lease_time );
						else
							tp.LEASE_LT = 0;
						
						tp.TP_VERS = COMPAT_VERSION;
	
						tp.TP_TYPE = TUNNEL_IP_REPLY;
						
						if ( sendto( gw_listen_arg->sock, &tp.start, TX_RP_SIZE, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in) ) < 0 ) {

							addr_to_string( addr.sin_addr.s_addr, str, sizeof (str) );
							debug_output( 0, "Error - can't send requested ip to client (%s): %s \n", str, strerror(errno) );

						} else {

							addr_to_string( tp.LEASE_IP, vstr, sizeof(vstr) );
							addr_to_string( addr.sin_addr.s_addr, str, sizeof(str) );
							debug_output( 3, "Gateway - assigned %s to client: %s \n", vstr, str );

						}

					}

				}

				if ( errno != EWOULDBLOCK ) {

					debug_output( 0, "Error - gateway can't receive packet: %s\n", strerror(errno) );
					break;

				}

			// /dev/tunX activity 
			} else if ( FD_ISSET( tun_fd, &tmp_wait_sockets ) ) {

				while ( ( tp_data_len = read( tun_fd, tp.IP_PACKET, sizeof(tp.IP_PACKET) ) ) > 0 ) {
					
					tp_len = tp_data_len + sizeof(tp.start);
					
					if ( !(gw_listen_arg->twt) || tp_data_len < sizeof(struct iphdr) || ((struct iphdr *)(tp.IP_PACKET))->version != 4 ) {
					
						debug_output( 0, "Gateway node - Received Invalid packet type for client tunnel ! \n" );
						continue;
					
					}
							
					iphdr = (struct iphdr *)(tp.IP_PACKET);
							
					iph_addr_suffix_h = ntohl( iphdr->daddr ) & ntohl( ~my_tun_netmask );

					/* check whether client IP is known */
					if ( !((iphdr->daddr & my_tun_netmask) == my_tun_ip &&
						iph_addr_suffix_h > 0 &&
						iph_addr_suffix_h < my_tun_suffix_mask_h &&
						gw_client_list[ iph_addr_suffix_h ] != NULL ) ) {
									
						addr_to_string( iphdr->daddr, vstr, sizeof(vstr) );

						debug_output( 0, "Error - got packet for unknown virtual ip %s \n", vstr); 
								
						continue;
					}
					
					client_addr.sin_addr.s_addr = gw_client_list[ iph_addr_suffix_h ]->addr;

					tp.TP_VERS = COMPAT_VERSION;
					
					tp.TP_TYPE = TUNNEL_DATA;

					if ( sendto( gw_listen_arg->sock, &tp.start, tp_len, 0, (struct sockaddr *)&client_addr, sizeof(struct sockaddr_in) ) < 0 )
						debug_output( 0, "Error - can't send data to client (%s): %s \n", str, strerror(errno) );

				}

				if ( errno != EWOULDBLOCK ) {

					debug_output( 0, "Error - gateway can't read tun data: %s\n", strerror(errno) );
					break;

				}

			}

		} else if ( ( res < 0 ) && ( errno != EINTR ) ) {

			debug_output( 0, "Error - can't select: %s\n", strerror(errno) );
			break;

		}


		/* close unresponsive client connections (free unused IPs) */

		if ( LESS_U32( (purge_timeout + 5000), c_time_ms ) ) {

			purge_timeout = c_time_ms;

			cleanup_leased_tun_ips( gw_listen_arg->lease_time, gw_client_list, my_tun_ip, my_tun_netmask );

		}

	}

	/* delete tun device and routes on exit */
	add_del_route( my_tun_ip, gw_listen_arg->netmask, 0, 0, tun_ifi, tun_dev, 254, 0, 1 );

	del_dev_tun( tun_fd );

	cleanup_leased_tun_ips(0, gw_client_list, my_tun_ip, my_tun_netmask );
	
	debugFree( gw_client_list, 1210);
	close( gw_listen_arg->sock );
	gw_listen_arg->sock = 0;
	debugFree( gw_listen_arg, 1223 );
	return NULL;

}
