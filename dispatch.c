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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>


#include "os.h"
#include "batman.h"
#include "originator.h"
#include "metrics.h"
#include "control.h"
#include "dispatch.h"


SIMPEL_LIST( send_list );

void init_dispatch( void ) {
	//INIT_LIST_HEAD_FIRST( send_list );
}

void cleanup_dispatch( void )
{
	
	struct send_node *send_node;
	struct list_head *list_pos_tmp, *list_pos;
	
	list_for_each_safe( list_pos, list_pos_tmp, &send_list ) {

		send_node = list_entry( list_pos, struct send_node, list );

		list_del( (struct list_head *)&send_list, list_pos, &send_list );

		debugFree( send_node->ogm_buff, 1105 );
		debugFree( send_node, 1106 );

	}
	
}

void strip_packet(  struct msg_buff *mb, unsigned char *pos, int32_t udp_len )
{
	
	int16_t left_pos, ext_type, done_pos, ext_pos;
	struct ext_packet *ext_array;
	
	while ( udp_len >= sizeof( struct bat_packet_common ) && udp_len >= ((struct bat_packet_common *)pos)->size<<2 ) {
	
		if ( ((struct bat_packet_common *)pos)->bat_type == BAT_TYPE_OGM  ) {
			
			((struct bat_packet_ogm *)pos)->seqno = ntohs( ((struct bat_packet_ogm *)pos)->seqno ); /* network to host order for our 16bit seqno. */
	
			mb->ogm = (struct bat_packet_ogm *)pos;
			addr_to_string( mb->ogm->orig, mb->orig_str, sizeof(mb->orig_str) );
			
			
			/* process optional gateway extension messages */
		
			left_pos  = (udp_len - sizeof(struct bat_packet_ogm)) / sizeof(struct ext_packet);
			done_pos  = 0;
		
			mb->gw_array = NULL;
			mb->gw_array_len   = 0;
		
			mb->hna_array = NULL;
			mb->hna_array_len = 0;
	
			mb->srv_array = NULL;
			mb->srv_array_len = 0;
		
			mb->vis_array = NULL;
			mb->vis_array_len = 0;
		
			mb->pip_array = NULL;
			mb->pip_array_len = 0;
	
			ext_type = 0;
		
			ext_array = (struct ext_packet *) (pos + sizeof(struct bat_packet_ogm) + (done_pos * sizeof(struct ext_packet)) );
			ext_pos = 0;
		
			while ( done_pos < left_pos && 
						     (done_pos * sizeof(struct ext_packet))  <  ((((struct bat_packet_common *)pos)->size)<<2) &&
						     ((ext_array)[0]).EXT_FIELD_MSG == YES && 
						     ext_type <= EXT_TYPE_MAX ) 
			{
			
				while( (ext_pos + done_pos) < left_pos && ((ext_array)[ext_pos]).EXT_FIELD_MSG == YES ) {
				
					if ( ((ext_array)[ext_pos]).EXT_FIELD_TYPE == ext_type  ) {
					
						(ext_pos)++;
					
					} else if ( ((ext_array)[ext_pos]).EXT_FIELD_TYPE > ext_type  ) {
					
						break;
					
					} else {
					
						debug_output( 0, "ERROR - Drop packet: rcvd incompatible extension message order: size? %i, ext_type %d, via NB %s, originator? %s. \n",  
								udp_len, ((ext_array)[ext_pos]).EXT_FIELD_TYPE, mb->neigh_str, mb->orig_str );
						return;
					}
					
				}
	
				done_pos = done_pos + ext_pos;
			
				if ( ext_pos != 0 ) {
				
					if ( ext_type == EXT_TYPE_GW ) {
					
						mb->gw_array = ext_array;
						mb->gw_array_len = ext_pos;
					
					} else if ( ext_type == EXT_TYPE_HNA ) {
					
						mb->hna_array = ext_array;
						mb->hna_array_len = ext_pos;
					
					} else if ( ext_type == EXT_TYPE_SRV ) {
					
						mb->srv_array = ext_array;
						mb->srv_array_len = ext_pos;
					
					} else if ( ext_type == EXT_TYPE_VIS ) {
					
						mb->vis_array = ext_array;
						mb->vis_array_len = ext_pos;
					
					} else if ( ext_type == EXT_TYPE_PIP ) {
					
						mb->pip_array = ext_array;
						mb->pip_array_len = ext_pos;
					
					}
				
				}
		
				ext_array = (struct ext_packet *) (pos + sizeof(struct bat_packet_ogm) + (done_pos * sizeof(struct ext_packet)) );
				ext_pos = 0;
				ext_type++;
			}
		

			s_received_ogms++;


			if ( (sizeof(struct bat_packet_ogm) + (done_pos * sizeof(struct ext_packet)))  !=  ((((struct bat_packet_common *)pos)->size)<<2) ) {

				udp_len = udp_len - ((((struct bat_packet_common *)pos)->size)<<2);
				pos = pos + ((((struct bat_packet_common *)pos)->size)<<2);

				debug_output( 0, "ERROR - Drop packet! Received corrupted packet size: processed bytes: %d , indicated bytes %d, batman flags. %X,  gw_array_len %d, hna_array_len: %d, srv_array_len %d, pip_array_len %d, remaining bytes %d \n", (sizeof(struct bat_packet_ogm) + (done_pos * sizeof(struct ext_packet))), ((((struct bat_packet_common *)pos)->size)<<2), ((struct bat_packet_ogm *)pos)->flags, mb->gw_array_len, mb->hna_array_len, mb->srv_array_len, mb->pip_array_len, udp_len );

				return;

			}


			debug_output( 4, "Received ogm: flags. %X,  gw_array_len %d, hna_array_len: %d, srv_array_len %d, pip_array_len %d, remaining bytes %d \n", (mb->ogm)->flags, mb->gw_array_len, mb->hna_array_len, mb->srv_array_len, mb->pip_array_len, udp_len );

			/* prepare for next ogm and attached extension messages */
			udp_len = udp_len - ((((struct bat_packet_common *)pos)->size)<<2);
			pos = pos + ((((struct bat_packet_common *)pos)->size)<<2);

			process_ogm( mb );
			continue;
			
		} else 	if ( ((struct bat_packet_common *)pos)->bat_type == BAT_TYPE_UPRQ  ) {
			
			mb->uprq = (struct bat_packet_uprq *)pos;
			
			udp_len = udp_len - ((((struct bat_packet_common *)pos)->size)<<2);
			pos = pos + ((((struct bat_packet_common *)pos)->size)<<2);
			
			process_unicast_probe( mb );
			continue;
		
		} else {
			
			
			addr_to_string( ((struct bat_packet_ogm *)pos)->orig, mb->orig_str, sizeof(mb->orig_str) );
			
			udp_len = udp_len - ((((struct bat_packet_common *)pos)->size)<<2) ;
			
			debug_output( 0, "WARNING - Drop single unkown bat_type bat_type %X, size %i, via NB %s, originator? %s, remaining len %d. Maybe you need an update\n",  
				      ((struct bat_packet_common *)pos)->bat_type,
					(((struct bat_packet_common *)pos)->size)<<2,
					   mb->neigh_str, mb->orig_str, udp_len );
			
			pos = pos + ((((struct bat_packet_common *)pos)->size)<<2) ;
		
			continue;
			
		}

	}

}	


void process_packet( struct msg_buff *mb, unsigned char *pos, uint32_t rcvd_neighbor)
{
	prof_start( PROF_process_packet );

	int32_t check_len, check_done, udp_len;
	unsigned char *check_pos;
	
	
	if ( mb->total_length <= 0 ) {
		debug_output( 0, "Error - Invalid packet (%d): %s\n", mb->total_length );
		cleanup_all( CLEANUP_FAILURE );
	}
	
	addr_to_string( rcvd_neighbor, mb->neigh_str, sizeof(mb->neigh_str) );
	
	// immediately drop my own packets
	if ( rcvd_neighbor == mb->iif->addr.sin_addr.s_addr ) {
		
		debug_output( 4, "Drop packet: received my own broadcast iif %s, %s \n", mb->iif->dev , mb->neigh_str );

		prof_stop( PROF_process_packet );
		return;
	}


	
	// immediately drop invalid packets...
	// we acceppt longer packets than specified by pos->size to allow padding for equal packet sizes
	if ( mb->total_length < (sizeof(struct bat_header) + sizeof(struct bat_packet_common))  ||
		    ((((struct bat_header *)pos)->size)<<2) < (sizeof(struct bat_header) + sizeof(struct bat_packet_common)) ||
		    (((struct bat_header *)pos)->version) != COMPAT_VERSION  ||
		    ((((struct bat_header *)pos)->size)<<2) > mb->total_length )
	{
	
		if ( mb->total_length >= (sizeof(struct bat_header) /*+ sizeof(struct bat_packet_common) */) )
			debug_output( 0, "WARNING - Drop packet: rcvd incompatible batman packet (version? %i, link_flags? %X, reserved? %X, size? %i), rcvd udp_len %d via NB %s. My version is %d \n", 
				      ((struct bat_header *)pos)->version,
					((struct bat_header *)pos)->link_flags,
					  ((struct bat_header *)pos)->reserved,
					    ((struct bat_header *)pos)->size,
					      mb->total_length, mb->neigh_str, COMPAT_VERSION );
			
		else
			debug_output( 0, "Error - Rcvd to small packet, rcvd udp_len %i, via NB %s.\n", mb->total_length, mb->neigh_str );
		
		prof_stop( PROF_process_packet );
		return;
	}
	
	
	s_received_aggregations++;

	mb->link_flags = ((struct bat_header *)pos)->link_flags;
	mb->neigh = rcvd_neighbor;

	debug_output( DBGL_ALL, "Rcvd packet:(version? %i, link_flags? %X, reserved? %X, size? %i), rcvd udp_len %d via NB %s %s %s \n", 
			((struct bat_header *)pos)->version, 
			((struct bat_header *)pos)->link_flags,
			((struct bat_header *)pos)->reserved,
			((struct bat_header *)pos)->size,
				mb->total_length, mb->neigh_str, mb->iif->dev, mb->unicast?"UNICAST":"BRC"    );


	check_len = udp_len = ((((struct bat_header *)pos)->size)<<2) - sizeof( struct bat_header );
	check_pos = pos = pos + sizeof(struct bat_header);
	
	
	// immediately drop non-plausibile packets...
	check_done = 0;

	while ( check_done < check_len ) {

		if ( check_len < sizeof( struct bat_packet_common ) ) {

			debug_output(0, "ERROR - Recvfrom returned with absolutely to small packet length %d !!!! \n", check_len );
			cleanup_all( CLEANUP_FAILURE );
		}

		if ( 	(((struct bat_packet_common *)check_pos)->ext_msg) != 0 ||
						(((struct bat_packet_common *)check_pos)->size)    == 0 ||
						((((struct bat_packet_common *)check_pos)->size)<<2) > check_len  ) 
		{

			if (	(((struct bat_packet_common *)check_pos)->ext_msg) == 0 &&
								((((struct bat_packet_common *)check_pos)->size)<<2) >= sizeof( struct bat_packet_ogm ) &&
								check_len >= sizeof( struct bat_packet_ogm )  )
				addr_to_string( ((struct bat_packet_ogm *)check_pos)->orig, mb->orig_str, sizeof(mb->orig_str) );

			else
				addr_to_string( 0, mb->orig_str, sizeof(mb->orig_str) );

			debug_output(0, "ERROR - Drop jumbo packet: rcvd incorrect size or order: ext_msg %d, reserved %X, OGM size field %d aggregated OGM size %i, via IF: %s, NB %s, Originator? %s. \n",  ((struct bat_packet_common *)check_pos)->ext_msg, ((struct bat_packet_common *)check_pos)->reserved1, ((((struct bat_packet_common *)check_pos)->size)), check_len, mb->iif->dev, mb->neigh_str, mb->orig_str);

			prof_stop( PROF_process_packet );
			return;
			
		}

		check_done = check_done + ((((struct bat_packet_common *)check_pos)->size)<<2) ;
		check_pos  = check_pos  + ((((struct bat_packet_common *)check_pos)->size)<<2) ;

	}

	if ( check_len != check_done ) {

		debug_output(0, "ERROR - Drop jumbo packet: End of packet does not match indicated size \n");

		prof_stop( PROF_process_packet );
		return;

	}

	strip_packet( mb, pos, udp_len );
	
	prof_stop( PROF_process_packet );
	
}


void wait4Event( uint32_t timeout ) {
	
	static unsigned char packet_in[2001];
	struct msg_buff msg_buff;
	struct msg_buff *mb = &msg_buff;
	struct client_node *client;
	int i;
	
	uint32_t last_get_time_result = 0;
	
	struct sockaddr_in addr;
	uint32_t addr_len = sizeof(struct sockaddr_in);

	uint32_t return_time = batman_time + timeout;
	struct timeval tv;
	struct list_head *list_pos, *list_tmp, *prev_list_head;
	int selected;
	fd_set tmp_wait_set;
		
	debug_output(4, "wait4Event()  timeout %d \n", timeout );
	
loop4Event:
	while (return_time > batman_time) {
			
		if ( changed_readfds ) {
				
			set_readfds();
			changed_readfds = 0;
			
		}
	
		memcpy( &tmp_wait_set, &receive_wait_set, sizeof(fd_set) );
			
		tv.tv_sec  =   (return_time - batman_time) / 1000;
		tv.tv_usec = ( (return_time - batman_time) % 1000 ) * 1000;
			
		selected = select( receive_max_sock + 1, &tmp_wait_set, NULL, NULL, &tv );
			
		s_returned_select++;
	
		batman_time = get_time( YES, &(mb->tv_stamp) );
			
		if ( batman_time < last_get_time_result ) {
				
			last_get_time_result = batman_time;
			debug_output( 0, "WARNING - Detected Timeoverlap...\n" );
			return;
				
		}
	
		last_get_time_result = batman_time;
					
		if ( selected < 0 && errno != EINTR ) {
			
			debug_output( 0, "Error - can't select: %s\n", strerror(errno) );
			cleanup_all( CLEANUP_FAILURE );
				
		}
	
		if ( selected <= 0 ) {
	
			//Often select returns just a few milliseconds before being scheduled
			if ( return_time < batman_time + 10 ) {
					
					//cheating time :-)
				batman_time = return_time;
				return;
					
			}
					
			if ( return_time < batman_time )
				debug_output( 3, "select() returned %d without reason!! return_time %d, curr_time %d\n", selected, return_time, batman_time );
				
			goto loop4Event;
		}
			
	
			
		// check for received packets...
		list_for_each( list_pos, &if_list ) {
			
			mb->iif = list_entry( list_pos, struct batman_if, list );
					
			if ( !mb->iif->is_lo && FD_ISSET( mb->iif->udp_recv_sock, &tmp_wait_set ) ) {
	
				mb->unicast = NO;
				mb->total_length = recvfrom( mb->iif->udp_recv_sock, packet_in, sizeof(packet_in) - 1, 0, (struct sockaddr *)&addr, &addr_len );
				
				ioctl(mb->iif->udp_recv_sock, SIOCGSTAMP, &(mb->tv_stamp)) ;
					
				process_packet( mb, packet_in, addr.sin_addr.s_addr );
	
				goto loop4Event;
	
			} 
				
				
			if ( !mb->iif->is_lo && FD_ISSET( mb->iif->udp_send_sock, &tmp_wait_set ) ) {
				
				mb->unicast = YES; 
					
				struct msghdr msghdr;
				struct iovec iovec;
				char buf[4096];
				struct cmsghdr *cp;
				struct timeval *tv_stamp = NULL;
	
				iovec.iov_base = packet_in;
				iovec.iov_len = sizeof(packet_in) - 1;
				
				msghdr.msg_name = (struct sockaddr *)&addr;
				msghdr.msg_namelen = addr_len;
				msghdr.msg_iov = &iovec;
				msghdr.msg_iovlen = 1;
				msghdr.msg_control = buf;
				msghdr.msg_controllen = sizeof( buf );
				msghdr.msg_flags = 0;
				
				mb->total_length = recvmsg( mb->iif->udp_send_sock, &msghdr, MSG_DONTWAIT  );
					
#ifdef SO_TIMESTAMP
				for (cp = CMSG_FIRSTHDR(&msghdr); cp; cp = CMSG_NXTHDR(&msghdr, cp)) {
						
					if ( 	cp->cmsg_type == SO_TIMESTAMP && 
						cp->cmsg_level == SOL_SOCKET && 
						cp->cmsg_len >= CMSG_LEN(sizeof(struct timeval)) )  {
	
						tv_stamp = (struct timeval*)CMSG_DATA(cp);
						break;
									}
				}
#endif
				if ( tv_stamp == NULL ) {
						
					ioctl( mb->iif->udp_send_sock, SIOCGSTAMP, &(mb->tv_stamp) );
					//debug_output(DBGL_SYSTEM, "WARNING, NO SO_TIMESTAMP found !!! \n");
						
				} else {
						
					timercpy( tv_stamp, &(mb->tv_stamp) );
						
				}
					
				process_packet( mb, packet_in, addr.sin_addr.s_addr );
					
				goto loop4Event;
					
			}
	
		}
			
			
		// check for new control clients...
		if ( FD_ISSET( unix_sock, &tmp_wait_set ) ) {
				
			debug_output( DBGL_ALL, "Select indicated new control client... \n" );
				
			accept_unix_client();
				
			goto loop4Event;
				
		}
			
	
		// check for all connected control clients...
			
		prev_list_head = (struct list_head *)&unix_clients;
	
		list_for_each_safe( list_pos, list_tmp, &unix_clients ) {
			
			client = list_entry( list_pos, struct client_node, list );
				
			if ( FD_ISSET( client->fd, &tmp_wait_set ) ) {
					
				debug_output( DBGL_ALL, "wait4Event(): got msg from control client \n");
					
				handle_unix_control_msg( list_pos, prev_list_head );
					
				goto loop4Event;
				
			} else {
				prev_list_head = (struct list_head *)&client->list;
			}
		
		}
	
			
		// check for connected debug clients...
		for ( i = 0; i < DBGL_MAX; i++ ) {
			
			prev_list_head = (struct list_head *)&dbgl_clients[i];
				
			list_for_each_safe( list_pos, list_tmp, &dbgl_clients[i] ) {
				
				client = list_entry( list_pos, struct client_node, list );
					
				if ( FD_ISSET( client->fd, &tmp_wait_set ) ) {
						
					debug_output( DBGL_ALL, "wait4Event(): got msg from dbgl client \n");
					
					handle_unix_dbgl_msg( list_pos, prev_list_head, i );
	
					goto loop4Event;
				
				} else {
					prev_list_head = (struct list_head *)&client->list;
				}
		
			}
		}
	
			
		// check for changed interface status...
		if ( FD_ISSET( ifevent_sk, &tmp_wait_set ) ) {
				
			debug_output( 3, "select() indicated changed interface status! Going to check interfaces! \n" );
				
			recv_ifevent_netlink_sk( );
				
			check_interfaces();
				
			goto loop4Event;
				
		}
	
	
		debug_output( 3, "select() returned with  %d unhandled event(s)!! return_time %d, curr_time %d \n", selected, return_time, batman_time );
		return;
	}
	
	return;
}



void schedule_own_ogm( struct batman_if *batman_if, uint32_t current_time ) {

	struct send_node *send_node_new, *send_packet_tmp = NULL;
	struct list_head *list_pos, *prev_list_head;
	
	struct link_node *ln;
	struct list_head *link_pos;


	send_node_new = debugMalloc( sizeof(struct send_node), 501 );
	memset( send_node_new, 0, sizeof( struct send_node) );

	INIT_LIST_HEAD( &send_node_new->list );

	
	send_node_new->send_time = current_time + my_ogi - (my_ogi/(2*aggregations_per_ogi));
	
	debug_output( 4, "schedule_own_ogm(): for %s seqno %d at %d \n", batman_if->dev, batman_if->out.seqno, send_node_new->send_time );
	
	
	send_node_new->if_outgoing = batman_if;
	send_node_new->own = 1;

	/* only primary interfaces send usual extension messages */
	if (  batman_if->if_num == 0  ) {
		
		//TBD: Do we really need sizeof(unsigned char) ???
		
		send_node_new->ogm_buff_len = calc_ogm_if_size( 0 );
		
		send_node_new->ogm_buff = debugMalloc( send_node_new->ogm_buff_len , 502 );

		memcpy( send_node_new->ogm_buff, (unsigned char *)&batman_if->out, sizeof(struct bat_packet_ogm) );
		
		
		if ( my_gw_ext_array_len > 0 )
			memcpy( send_node_new->ogm_buff + sizeof(struct bat_packet_ogm), 
				(unsigned char *)my_gw_ext_array, 
				 my_gw_ext_array_len * sizeof(struct ext_packet) );
		
		if ( my_hna_ext_array_len > 0 )
			memcpy( send_node_new->ogm_buff + sizeof(struct bat_packet_ogm) + (my_gw_ext_array_len * sizeof(struct ext_packet)), 
				(unsigned char *)my_hna_ext_array, 
				 my_hna_ext_array_len * sizeof(struct ext_packet) );
		
		if ( my_srv_ext_array_len > 0 )
			memcpy( send_node_new->ogm_buff + sizeof(struct bat_packet_ogm) + 
					((my_gw_ext_array_len + my_hna_ext_array_len) * sizeof(struct ext_packet)), 
				(unsigned char *)my_srv_ext_array, 
				 my_srv_ext_array_len * sizeof(struct ext_packet) );

	/* all non-primary interfaces send primary-interface extension message */
	} else {

		send_node_new->ogm_buff_len = calc_ogm_if_size( 1 );
		
		send_node_new->ogm_buff = debugMalloc( send_node_new->ogm_buff_len , 502 );

		memcpy( send_node_new->ogm_buff, (unsigned char *)&batman_if->out, sizeof(struct bat_packet_ogm) );

		memcpy( send_node_new->ogm_buff + sizeof(struct bat_packet_ogm), 
			(unsigned char *)my_pip_ext_array, 
			 my_pip_ext_array_len * sizeof(struct ext_packet) );

	}

	
	/* change sequence number to network order */
	((struct bat_packet_ogm *)send_node_new->ogm_buff)->seqno = htons( ((struct bat_packet_ogm *)send_node_new->ogm_buff)->seqno );
	
	((struct bat_packet_ogm *)send_node_new->ogm_buff)->size = (calc_ogm_if_size( batman_if->if_num ))/4;

	
	prev_list_head = (struct list_head *)&send_list;

	list_for_each( list_pos, &send_list ) {

		send_packet_tmp = list_entry( list_pos, struct send_node, list );

		if ( send_packet_tmp->send_time > send_node_new->send_time ) {

			list_add_before( prev_list_head, list_pos, &send_node_new->list );
			break;

		}

		prev_list_head = &send_packet_tmp->list;

	}

	if ( ( send_packet_tmp == NULL ) || ( send_packet_tmp->send_time <= send_node_new->send_time ) )
		list_add_tail( &send_node_new->list, &send_list );

	batman_if->out.seqno++;

	list_for_each( link_pos, &link_list ) {

		ln = list_entry(link_pos, struct link_node, list);
		
		ln->lndev[ batman_if->if_num ].last_rtq_sqn = 
				update_bits(  0, batman_if->out.seqno - OUT_SEQNO_OFFSET,
					      &(ln->lndev[ batman_if->if_num ].rtq_sqr), ln->lndev[ batman_if->if_num ].last_rtq_sqn, 1, my_lws,
					      DBGL_ALL  );
		
	}
	
}



void schedule_rcvd_ogm( uint8_t unidirectional, uint8_t directlink, uint8_t cloned, uint16_t neigh_id, struct msg_buff *mb ) {

	prof_start( PROF_schedule_rcvd_ogm );
	struct send_node *send_node_new, *send_packet_tmp = NULL;
	struct list_head *list_pos, *prev_list_head;
	int ext_msg_size;
	
	debug_output( 4, "schedule_rcvd_ogm():  \n" );

	if ( !( ( (mb->ogm)->ttl == 1 && directlink) || (mb->ogm)->ttl > 1 ) ){

		debug_output( 4, "ttl exceeded \n" );

	} else {

		send_node_new = debugMalloc( sizeof(struct send_node), 504 );
		memset( send_node_new, 0, sizeof( struct send_node) );

		INIT_LIST_HEAD( &send_node_new->list );


		/* primary-interface-extension messages do not need to be rebroadcastes */
		/* other extension messages only if not unidirectional and ttl > 1 */
		
		ext_msg_size = ( !unidirectional  &&  (mb->ogm)->ttl > 1 ) ? 
				(((mb->gw_array_len) + (mb->hna_array_len) + (mb->srv_array_len) + (mb->vis_array_len) ) * sizeof( struct ext_packet)) : 0 ;
		
		send_node_new->ogm_buff_len = sizeof(struct bat_packet_ogm) + ext_msg_size;
		
		
		
		send_node_new->ogm_buff = debugMalloc( send_node_new->ogm_buff_len, 505 );
		
		memcpy( send_node_new->ogm_buff, (mb->ogm), sizeof(struct bat_packet_ogm) );
		
		if ( ext_msg_size  &&  (mb->gw_array_len) > 0 )
			memcpy( send_node_new->ogm_buff + sizeof(struct bat_packet_ogm), (unsigned char *)(mb->gw_array), ((mb->gw_array_len) * sizeof( struct ext_packet)) );

		if ( ext_msg_size  &&  (mb->hna_array_len) > 0 )
			memcpy( send_node_new->ogm_buff + sizeof(struct bat_packet_ogm) + 
					(((mb->gw_array_len) ) * sizeof( struct ext_packet)),
					   (unsigned char *)(mb->hna_array), ((mb->hna_array_len) * sizeof( struct ext_packet)) );
		
		if ( ext_msg_size  &&  (mb->srv_array_len) > 0 )
			memcpy( send_node_new->ogm_buff + sizeof(struct bat_packet_ogm) + 
					(((mb->gw_array_len) + (mb->hna_array_len)) * sizeof( struct ext_packet)), 
					   (unsigned char *)(mb->srv_array), ((mb->srv_array_len) * sizeof( struct ext_packet)) );

		if ( ext_msg_size  &&  (mb->vis_array_len) > 0 )
			memcpy( send_node_new->ogm_buff + sizeof(struct bat_packet_ogm) + 
					(((mb->gw_array_len) + (mb->hna_array_len) + (mb->srv_array_len)) * sizeof( struct ext_packet)), 
					    (unsigned char *)(mb->vis_array), ((mb->vis_array_len) * sizeof( struct ext_packet)) );
		
		
		/* primary interface annoucements must not be rebroadcasted */
		/*
		if ( (mb->pip_array_len) > 0 )
			memcpy( send_node_new->ogm_buff + sizeof(struct bat_packet_ogm) + 
		(((mb->gw_array_len) + (mb->hna_array_len) + (mb->srv_array_len) + (mb->vis_array_len)) * sizeof( struct ext_packet)), 
		(unsigned char *)(mb->pip_array), ((mb->pip_array_len) * sizeof( struct ext_packet)) );
		*/
		
		((struct bat_packet_ogm *)send_node_new->ogm_buff)->ttl--;
		((struct bat_packet_ogm *)send_node_new->ogm_buff)->prev_hop_id = neigh_id;
		
		((struct bat_packet_ogm *)send_node_new->ogm_buff)->size = (send_node_new->ogm_buff_len)>>2;

		send_node_new->send_time = (batman_time);
		send_node_new->own = 0;

		send_node_new->if_outgoing = mb->iif;

		((struct bat_packet_ogm *)send_node_new->ogm_buff)->flags = 0x00;
		
		if ( unidirectional ) {

			((struct bat_packet_ogm *)send_node_new->ogm_buff)->flags = 
					((struct bat_packet_ogm *)send_node_new->ogm_buff)->flags | ( UNIDIRECTIONAL_FLAG | DIRECTLINK_FLAG );

		} else if ( directlink ) {

			((struct bat_packet_ogm *)send_node_new->ogm_buff)->flags = 
					((struct bat_packet_ogm *)send_node_new->ogm_buff)->flags | DIRECTLINK_FLAG;

		} 
		
		if ( cloned ) {
			((struct bat_packet_ogm *)send_node_new->ogm_buff)->flags = 
					((struct bat_packet_ogm *)send_node_new->ogm_buff)->flags | CLONED_FLAG;
		}			

		
		/* change sequence number to network order */
		((struct bat_packet_ogm *)send_node_new->ogm_buff)->seqno = htons( ((struct bat_packet_ogm *)send_node_new->ogm_buff)->seqno );
		

		prev_list_head = (struct list_head *)&send_list;

		list_for_each( list_pos, &send_list ) {

			send_packet_tmp = list_entry( list_pos, struct send_node, list );

			if ( send_packet_tmp->send_time > send_node_new->send_time ) {

				list_add_before( prev_list_head, list_pos, &send_node_new->list );
				break;

			}

			prev_list_head = &send_packet_tmp->list;

		}

		if ( ( send_packet_tmp == NULL ) || ( send_packet_tmp->send_time <= send_node_new->send_time ) )
			list_add_tail( &send_node_new->list, &send_list );

		
	}

	prof_stop( PROF_schedule_rcvd_ogm );

}


void send_aggregated_ogms( int *cycle ) {
	struct list_head *if_pos;
	struct batman_if *batman_if;

	uint8_t iftype;

	(*cycle)++;
	
	/* send all the aggregated packets (which fit into max packet size) */
	
	/* broadcast via lan interfaces first */
	for ( iftype = 0; iftype <= 1; iftype++ ) {
		
		list_for_each(if_pos, &if_list) {
		
			batman_if = list_entry(if_pos, struct batman_if, list);
		
			if ( batman_if->is_wlan == iftype && batman_if->packet_out_len > sizeof( struct bat_header ) ) {
				
				((struct bat_header*)&(batman_if->packet_out))->version = COMPAT_VERSION;
				
				if (unicast_probes_num) 
					((struct bat_header*)&(batman_if->packet_out))->link_flags |= UNICAST_PROBES_CAP;
				else 
					((struct bat_header*)&(batman_if->packet_out))->link_flags &= ~UNICAST_PROBES_CAP;
				
				((struct bat_header*)&(batman_if->packet_out))->size = (batman_if->packet_out_len)/4;
				
				
				if ( batman_if->packet_out_len > MAX_PACKET_OUT_SIZE  ||  (batman_if->packet_out_len)%4 != 0) {
					
					debug_output( 0, "Error - trying to send strange packet length %d oktets.\n", batman_if->packet_out_len );
					cleanup_all( CLEANUP_FAILURE );
					
				}
				
				if (batman_if->if_active && !batman_if->is_lo)
					send_udp_packet( batman_if->packet_out, batman_if->packet_out_len, &batman_if->broad, batman_if->udp_send_sock );
					
				s_broadcasted_aggregations++;
				
				if ( *cycle > 1 )
					s_broadcasted_cp_aggregations++;
				
				batman_if->packet_out_len = sizeof( struct bat_header );
				
			}
		
		}

	}
}

void debug_send_list( int sock ) {
	
	struct list_head *list_pos;
	char str[ADDR_STR_LEN];
	
	dprintf( sock, "Outstanding OGM for sending: \n" );

	list_for_each( list_pos, &send_list ) {
		
		struct send_node *send_node = list_entry( list_pos, struct send_node, list );
		struct bat_packet_ogm *ogm = ((struct bat_packet_ogm *)(send_node->ogm_buff));
		
		addr_to_string( ogm->orig, str, sizeof(str) );
		
		dprintf( sock, "%-15s   (seqno %5d  ttl %3d)  at %u \n", str, send_node->send_time, ntohs(ogm->seqno), ogm->ttl );
	}
	
	return;
}

void send_outstanding_ogms() {

	prof_start( PROF_send_outstanding_ogms );
	struct send_node *send_node;
	struct list_head *send_pos, *if_pos, *send_temp, *prev_list_head;

	struct batman_if *batman_if;
	static char orig_str[ADDR_STR_LEN];
	uint8_t directlink, unidirectional, cloned, ttl, send_ogm_only_via_owning_if;
	int16_t aggregated_size;
	
	int dbg_if_out = 0, cycle = 0;
#define	MAX_DBG_IF_SIZE 200
	static char dbg_if_str[ MAX_DBG_IF_SIZE ];
	
	uint32_t send_time = batman_time;
	

	if ( list_empty( &send_list )  ||  GREAT_U32( (list_entry( (&send_list)->next, struct send_node, list ))->send_time, send_time ) )
		return;	
	
	debug_output( 4, "send_outstanding_ogms(): now %u, aggregations_po %d, send_list holds packets to send \n", send_time, aggregations_per_ogi );

	
	aggregated_size = sizeof( struct bat_header );
	
	list_for_each( send_pos, &send_list ) {
		
		send_node = list_entry( send_pos, struct send_node, list );
		
		if ( aggregated_size > sizeof(struct bat_header)  &&  (aggregated_size + send_node->ogm_buff_len) > MAX_PACKET_OUT_SIZE  ) {

			send_aggregated_ogms( &cycle );
			
			debug_output( 4, "send_outstanding_ogms(): cycle %d, max aggregated size %d \n\n", cycle,  aggregated_size );
			
			aggregated_size = sizeof( struct bat_header );
			
		}
		
		if ( LSEQ_U32( send_node->send_time, send_time )  &&  (aggregated_size + send_node->ogm_buff_len) <= MAX_PACKET_OUT_SIZE ) {
			
			if ( send_node->send_bucket == 0 )
				send_node->send_bucket =  ((int32_t)(rand_num( 100 )));

			send_node->iteration++;	
			send_node->send = YES;
			send_node->done = YES;
			
			// keep care to not aggregate more packets than would fit into max packet size
			aggregated_size+= send_node->ogm_buff_len;
			
			addr_to_string( ((struct bat_packet_ogm *)send_node->ogm_buff)->orig, orig_str, ADDR_STR_LEN );

			directlink =     (((struct bat_packet_ogm *)send_node->ogm_buff)->flags & DIRECTLINK_FLAG );
			unidirectional = (((struct bat_packet_ogm *)send_node->ogm_buff)->flags & UNIDIRECTIONAL_FLAG );
			cloned =         (((struct bat_packet_ogm *)send_node->ogm_buff)->flags & CLONED_FLAG );

			ttl = ((struct bat_packet_ogm *)send_node->ogm_buff)->ttl;
			send_ogm_only_via_owning_if = ( (send_node->own && send_node->if_outgoing->send_ogm_only_via_owning_if) ? 1 : 0 );
			
			
			if ( directlink  &&  send_node->if_outgoing == NULL  ) {
	
				debug_output( 0, "Error - can't forward packet with IDF: outgoing iface not specified \n" );
				cleanup_all( CLEANUP_FAILURE );
	
			}
			
			/* rebroadcast only to allow neighbor to detect bidirectional link */
			if ( send_node->iteration == 1 && directlink && !cloned && ( unidirectional || ttl == 0 ) ) {
				
				
				dbg_if_out = dbg_if_out + snprintf( (dbg_if_str + dbg_if_out), (MAX_DBG_IF_SIZE - dbg_if_out), " %-12s  (NBD)", send_node->if_outgoing->dev );

				//TODO: send only pure bat_packet_ogm, no extension headers.
				memcpy( (send_node->if_outgoing->packet_out + send_node->if_outgoing->packet_out_len), send_node->ogm_buff, send_node->ogm_buff_len );

				s_broadcasted_ogms++;
				
				send_node->if_outgoing->packet_out_len+= send_node->ogm_buff_len;
			

			/* (re-) broadcast to propagate existence of path to OG*/
			} else if ( !unidirectional && ttl > 0 ) {
				
	
				list_for_each(if_pos, &if_list) {

					batman_if = list_entry(if_pos, struct batman_if, list);

					if ( ( send_node->send_bucket < batman_if->if_send_clones ) && 
						( !send_ogm_only_via_owning_if || send_node->if_outgoing == batman_if ) ) { 
					
						if ( (send_node->send_bucket + 100) < batman_if->if_send_clones )
							send_node->done = NO;
						
						
						memcpy( (batman_if->packet_out + batman_if->packet_out_len), send_node->ogm_buff, send_node->ogm_buff_len );
						
						
						if ( ( directlink ) && ( send_node->if_outgoing == batman_if ) )
							((struct bat_packet_ogm *)(batman_if->packet_out + batman_if->packet_out_len))->flags = 
								((struct bat_packet_ogm *)(batman_if->packet_out + batman_if->packet_out_len))->flags | DIRECTLINK_FLAG;
						else
							((struct bat_packet_ogm *)(batman_if->packet_out + batman_if->packet_out_len))->flags = 
								((struct bat_packet_ogm *)(batman_if->packet_out + batman_if->packet_out_len))->flags & ~DIRECTLINK_FLAG;
						
						
						s_broadcasted_ogms++;
							
						batman_if->packet_out_len+= send_node->ogm_buff_len;
						
						dbg_if_out = dbg_if_out + snprintf( (dbg_if_str + dbg_if_out), (MAX_DBG_IF_SIZE - dbg_if_out), " %-12s", batman_if->dev );
						
						if (send_ogm_only_via_owning_if && send_node->if_outgoing == batman_if)
							dbg_if_out = dbg_if_out + snprintf( (dbg_if_str + dbg_if_out), (MAX_DBG_IF_SIZE - dbg_if_out), "  (npIF)" );

						
					}
				}
				
				
				((struct bat_packet_ogm *)send_node->ogm_buff)->flags = 
						((struct bat_packet_ogm *)send_node->ogm_buff)->flags | CLONED_FLAG;
				
			}
			
			send_node->send_bucket = send_node->send_bucket + 100;

			debug_output( 4, "Sending packet (originator %-16s, seqno %5d, TTL %2d, IDF %d, UDF %d, CLF %d) iter %d len %3d agg_size %3d IFs %s \n", orig_str, ntohs( ((struct bat_packet_ogm *)send_node->ogm_buff)->seqno ), ((struct bat_packet_ogm *)send_node->ogm_buff)->ttl, directlink, unidirectional, cloned, send_node->iteration, send_node->ogm_buff_len, aggregated_size, dbg_if_str );
				
			dbg_if_out = 0;
			
		} else {
			
			if ( LSEQ_U32( send_node->send_time, send_time )  &&  aggregated_size <= sizeof( struct bat_header ) ) {
			
				debug_output( 0, "Error - Drop Packet, single packet to large to fit maximum packet size scheduled time %d, now %d, agg_size %d, next_len %d !! \n", send_node->send_time,  send_time, aggregated_size,  send_node->ogm_buff_len );
				
				send_node->iteration++;	
				send_node->send = YES;
				send_node->done = YES;

			}
			
			break; // for now we are done, 
			
		}
		
	}
	
	
	if ( aggregated_size > sizeof( struct bat_header ) ) {
	
		send_aggregated_ogms( &cycle );
		
		debug_output( 4, "send_outstanding_ogms(): cycle %d, max aggregated size %d \n\n", cycle,  aggregated_size );
	
	}

	
	
	/* remove all the send packets from send_list, set new timer for un-finished clones... */
	
	prev_list_head = (struct list_head *)&send_list;
	
	list_for_each_safe( send_pos, send_temp, &send_list ) {
	
		send_node = list_entry( send_pos, struct send_node, list );
	
		if ( send_node->send == YES ) {
					
			// to trigger the scheduling of the next own OGMs at the end of this function
			if (  send_node->own  &&  send_node->iteration == 1  )
				send_node->if_outgoing->send_own = 1;
				
			if ( send_node->done ) {
			
				list_del( prev_list_head, send_pos, &send_list );
				
				debugFree( send_node->ogm_buff, 1501 );
				debugFree( send_node, 1502 );
				
			} else {
				
				send_node->send_time = send_time + 1;
				send_node->send = NO;
				send_node->done = NO;
				
				prev_list_head = &send_node->list;	
				
			}
				
		} else {
				
			//wo dont want a small, but later packet to be removed.
			break;
				
		}
				
	}
	
	
	
	/* if own OGMs have been send during this call, reschedule them now */
	
	list_for_each(if_pos, &if_list) {
			
		batman_if = list_entry(if_pos, struct batman_if, list);
				
		if ( batman_if->send_own ) 
			schedule_own_ogm( batman_if, send_time );

		batman_if->send_own = 0;
				
	}

	
	prof_stop( PROF_send_outstanding_ogms );

}




