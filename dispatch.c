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
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "batman.h"
#include "os.h"
#include "originator.h"
#include "metrics.h"
#include "control.h"
#include "dispatch.h"


SIMPEL_LIST( send_list );

SIMPEL_LIST( todo_list );


void init_dispatch( void ) {
}

void cleanup_dispatch( void )
{
	
	struct list_head *list_pos_tmp, *list_pos;
	
	list_for_each_safe( list_pos, list_pos_tmp, &send_list ) {

		struct send_node *send_node = list_entry( list_pos, struct send_node, list );

		list_del( (struct list_head *)&send_list, list_pos, &send_list );

		debugFree( send_node->ogm_buff, 1105 );
		debugFree( send_node, 1106 );

	}
	
	list_for_each_safe( list_pos, list_pos_tmp, &todo_list ) {

		struct todo_node *todo_node = list_entry( list_pos, struct todo_node, list );

		list_del( (struct list_head *)&todo_list, list_pos, &todo_list );

		if ( todo_node->data )
			debugFree( todo_node->data, 1109 );
		debugFree( todo_node, 1109 );

	}

}


void register_task( uint32_t timeout, void (* task) (void *), void *data ) {
	
	struct list_head *list_pos;
	
	struct todo_node *tn = debugMalloc( sizeof( struct todo_node ), 109 );
	
	INIT_LIST_HEAD( &tn->list );
	tn->expire = batman_time + timeout;
	tn->task = task;
	tn->data = data;
	
	
	struct list_head *prev_list_head = (struct list_head *)&todo_list;
	struct todo_node *tmp_tn = NULL;
	
	list_for_each( list_pos, &todo_list ) {

		tmp_tn = list_entry( list_pos, struct todo_node, list );

		if ( GREAT_U32(tmp_tn->expire, tn->expire) ) {

			list_add_before( prev_list_head, list_pos, &tn->list );
			break;

		}

		prev_list_head = &tmp_tn->list;

	}

	if ( ( tmp_tn == NULL ) || ( LSEQ_U32(tmp_tn->expire, tn->expire) ) )
		list_add_tail( &tn->list, &todo_list );
	
}


uint32_t whats_next( void /*(** task) (void *),  void **data */ ) {
	
	struct list_head *list_pos, *tmp_pos, *prev_pos = (struct list_head*)&todo_list;
		
	list_for_each_safe( list_pos, tmp_pos, &todo_list ) {
			
		struct todo_node *tn = list_entry( list_pos, struct todo_node, list );
			
		if ( LSEQ_U32( tn->expire, batman_time )  ) {
			
			list_del( prev_pos, list_pos, &todo_list );
			
			(*(tn->task)) (tn->data);
			
			debugFree( tn, 1109 );
			
			if ( tn->data )
				debugFree( tn->data, 1109 );
			
			return 0;
			
		} else {
			
			return tn->expire - batman_time;
			
		}

	}
	
	return 100; // check me again in 100 ms
	
}


void send_aggregated_ogms( void ) {
	
	struct list_head *if_pos;
	struct batman_if *batman_if;

	uint8_t iftype;

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



void send_outstanding_ogms( void *data ) {

	prof_start( PROF_send_outstanding_ogms );
	struct send_node *send_node;
	struct list_head *send_pos, *if_pos, *send_temp, *prev_list_head;

	struct batman_if *batman_if;
	static char orig_str[ADDR_STR_LEN];
	uint8_t directlink, unidirectional, cloned, ttl, send_ogm_only_via_owning_if;
	int16_t aggregated_size;
	
	int dbg_if_out = 0;
#define	MAX_DBG_IF_SIZE 200
	static char dbg_if_str[ MAX_DBG_IF_SIZE ];
	
	uint16_t aggr_interval = 
			(my_ogi/aggregations_per_ogi > MAX_AGGREGATION_INTERVAL_MS) ? MAX_AGGREGATION_INTERVAL_MS :  (my_ogi/aggregations_per_ogi);

	register_task( (aggr_interval + rand_num( aggr_interval/2 )) - (aggr_interval/4), send_outstanding_ogms, NULL );

	
	if ( list_empty( &send_list )  ||  GREAT_U32( (list_entry( (&send_list)->next, struct send_node, list ))->send_time, batman_time ) )
		return;	
	
	debug_all( "send_outstanding_ogms(): now %u, aggregations_po %d, send_list holds packets to send \n", batman_time, aggregations_per_ogi );

	
	aggregated_size = sizeof( struct bat_header );
	
	prev_list_head = (struct list_head *)&send_list;
	
	list_for_each_safe( send_pos, send_temp, &send_list ) {
	
		send_node = list_entry( send_pos, struct send_node, list );
		
		if ( aggregated_size > sizeof(struct bat_header)  &&  (aggregated_size + send_node->ogm_buff_len) > MAX_PACKET_OUT_SIZE  ) {

			send_aggregated_ogms();
			
			debug_all( "send_outstanding_ogms(): cycle %d, max aggregated size %d \n\n", aggregated_size );
			
			aggregated_size = sizeof( struct bat_header );
			
		}
		
		if ( LSEQ_U32( send_node->send_time, batman_time ) ) { 
			
			send_node->iteration++;	
			//send_node->send = YES;
			uint8_t send_node_done = YES;
	
			if ( aggregated_size + send_node->ogm_buff_len  <=  MAX_PACKET_OUT_SIZE ) {
			
				if ( send_node->send_bucket == 0 )
					send_node->send_bucket =  ((int32_t)(rand_num( 100 )));
	
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
					memcpy( send_node->if_outgoing->packet_out + send_node->if_outgoing->packet_out_len,
							send_node->ogm_buff, send_node->ogm_buff_len );
	
					s_broadcasted_ogms++;
					
					send_node->if_outgoing->packet_out_len+= send_node->ogm_buff_len;
				
	
					/* (re-) broadcast to propagate existence of path to OG*/
				} else if ( !unidirectional && ttl > 0 ) {
					
		
					list_for_each(if_pos, &if_list) {
	
						batman_if = list_entry(if_pos, struct batman_if, list);
	
						if ( ( send_node->send_bucket < batman_if->if_send_clones ) && 
										( !send_ogm_only_via_owning_if || send_node->if_outgoing == batman_if ) ) { 
						
							if ( (send_node->send_bucket + 100) < batman_if->if_send_clones )
								send_node_done = NO;
							
							
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
	
				debug_all( "Sending packet (originator %-16s, seqno %5d, TTL %2d, IDF %d, UDF %d, CLF %d) iter %d len %3d agg_size %3d IFs %s \n", orig_str, ntohs( ((struct bat_packet_ogm *)send_node->ogm_buff)->seqno ), ((struct bat_packet_ogm *)send_node->ogm_buff)->ttl, directlink, unidirectional, cloned, send_node->iteration, send_node->ogm_buff_len, aggregated_size, dbg_if_str );
					
				dbg_if_out = 0;
				
			} else if (  aggregated_size <= sizeof( struct bat_header ) ) {
				
				debug_output( 0, "Error - Drop Packet, single packet to large to fit maximum packet size scheduled time %d, now %d, agg_size %d, next_len %d !! \n", send_node->send_time,  batman_time, aggregated_size,  send_node->ogm_buff_len );
					
			}
			
					
			// trigger the scheduling of the next own OGMs at the end of this function
			if (  send_node->own  &&  send_node->iteration == 1  )
				send_node->if_outgoing->send_own = 1;
			
			// remove all the finished packets from send_list
			if ( send_node_done ) {
		
				list_del( prev_list_head, send_pos, &send_list );
			
				debugFree( send_node->ogm_buff, 1501 );
				debugFree( send_node, 1502 );
			
			} else {
			
				prev_list_head = &send_node->list;	
			
			}
			
			
		} else {
			
			break; // for now we are done, 
			
		}
		
	}
	
	
	if ( aggregated_size > sizeof( struct bat_header ) ) {
	
		send_aggregated_ogms();
		
		debug_all( "send_outstanding_ogms(): cycle %d, max aggregated size %d \n\n", aggregated_size );
	
	}

	
	// if own OGMs have been send during this call, schedule next one now
	
	list_for_each(if_pos, &if_list) {
			
		batman_if = list_entry(if_pos, struct batman_if, list);
				
		if ( batman_if->send_own ) 
			schedule_own_ogm( batman_if, batman_time );

		batman_if->send_own = 0;
				
	}

	
	prof_stop( PROF_send_outstanding_ogms );

}



static inline void schedule_rcvd_ogm( uint16_t context, uint16_t neigh_id, struct msg_buff *mb ) {

	prof_start( PROF_schedule_rcvd_ogm );
	
	struct send_node *send_node_new, *send_packet_tmp = NULL;
	struct list_head *list_pos, *prev_list_head;
	int ext_msg_size;
	uint8_t cloned = context & HAS_CLONED_FLAG ? YES : NO;
	uint8_t with_unidirectional_flag = 0;
	uint8_t directlink = 0;
	
	debug_all( "schedule_rcvd_ogm():  \n" );

	
	if ( !(context & IS_ASOCIAL) ) {

		/* is single hop (direct) neighbour */
		if ( context & IS_DIRECT_NEIGH ) {

			directlink = 1;
			/* it is our best route towards him */
			if ( (context & IS_ACCEPTED) && (context & IS_BEST_NEIGH) ) {

				/* mark direct link on incoming interface */
				//schedule_rcvd_ogm( 0, 1, context, orig_neigh_node->primary_orig_node->id4him, mb );
				
				debug_all( "Schedule packet: rebroadcast neighbour packet with direct link flag \n" );

			/* if an unidirectional direct neighbour sends us a packet or
			 * if a bidirectional neighbour sends us a packet who is not our best link to him: 
			*	- retransmit it with unidirectional flag to tell him that we get his packets */
			} else if ( !(context & HAS_CLONED_FLAG) ) {

				with_unidirectional_flag = 1;
				//schedule_rcvd_ogm( 1, 1, context, orig_neigh_node->primary_orig_node->id4him, mb );

				debug_all( "Schedule packet: rebroadcast neighbour packet with direct link and unidirectional flag \n" );

			} else {

				debug_all( "Drop packet: no reason to re-broadcast! \n" );
				prof_stop( PROF_schedule_rcvd_ogm );
				return;

			}

			/* multihop originator */
		} else if ( (context & IS_ACCEPTED) && (context & IS_BEST_NEIGH) ) {

			//schedule_rcvd_ogm( 0, 0, context, orig_neigh_node->primary_orig_node->id4him, mb );

			debug_all( "Schedule packet: rebroadcast originator packet \n" );

		} else {

			debug_all( "Drop multihop originator packet, not accepted or not via best link ! \n");
			prof_stop( PROF_schedule_rcvd_ogm );
			return;

		}

	} else {
		/* we are an asocial mobile device and dont want to forward other nodes packet */
		if( (context & IS_DIRECT_NEIGH) && !(context & HAS_CLONED_FLAG) ) {

			with_unidirectional_flag = 1; directlink = 1;
			//schedule_rcvd_ogm( 1, 1, context, orig_neigh_node->primary_orig_node->id4him, mb );

			debug_all( "Schedule packet: with mobile device policy: rebroadcast neighbour packet with direct link and unidirectional flag \n" );

		} else {
			debug_all( "Drop packet, mobile devices rebroadcast almost nothing :-( \n" );
			prof_stop( PROF_schedule_rcvd_ogm );
			return;

		}

	}

	
	if ( !( ( (mb->ogm)->ttl == 1 && directlink) || (mb->ogm)->ttl > 1 ) ){

		debug_all( "ttl exceeded \n" );
		prof_stop( PROF_schedule_rcvd_ogm );
		return;

	}


	send_node_new = debugMalloc( sizeof(struct send_node), 504 );
	memset( send_node_new, 0, sizeof( struct send_node) );

	INIT_LIST_HEAD( &send_node_new->list );


	/* primary-interface-extension messages do not need to be rebroadcastes */
	/* other extension messages only if not unidirectional and ttl > 1 */
	
	ext_msg_size = ( !with_unidirectional_flag  &&  (mb->ogm)->ttl > 1 ) ? 
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
	
	
	
	((struct bat_packet_ogm *)send_node_new->ogm_buff)->ttl--;
	((struct bat_packet_ogm *)send_node_new->ogm_buff)->prev_hop_id = neigh_id;
	
	((struct bat_packet_ogm *)send_node_new->ogm_buff)->size = (send_node_new->ogm_buff_len)>>2;

	send_node_new->send_time = batman_time;
	send_node_new->own = 0;

	send_node_new->if_outgoing = mb->iif;

	((struct bat_packet_ogm *)send_node_new->ogm_buff)->flags = 0x00;
	
	if ( with_unidirectional_flag ) {

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

		if ( GREAT_U32(send_packet_tmp->send_time, send_node_new->send_time) ) {

			list_add_before( prev_list_head, list_pos, &send_node_new->list );
			break;

		}

		prev_list_head = &send_packet_tmp->list;

	}

	if ( ( send_packet_tmp == NULL ) || ( LSEQ_U32(send_packet_tmp->send_time, send_node_new->send_time) ) )
		list_add_tail( &send_node_new->list, &send_list );

		
	prof_stop( PROF_schedule_rcvd_ogm );

}


static inline void process_ogm( struct msg_buff *mb )
{
	
	struct list_head *list_pos;
	struct orig_node *orig_neigh_node, *orig_node; 
	struct batman_if *batman_if;
	
	struct batman_if *if_incoming = mb->iif;
	uint32_t neigh = mb->neigh;
	struct bat_packet_ogm *ogm = mb->ogm;

	static char orig_str[ADDR_STR_LEN], neigh_str[ADDR_STR_LEN], ifaddr_str[ADDR_STR_LEN];
	
	addr_to_string( ogm->orig, orig_str, sizeof(orig_str) );
	addr_to_string( neigh, neigh_str, sizeof(neigh_str) );
	addr_to_string( if_incoming->addr.sin_addr.s_addr, ifaddr_str, sizeof(ifaddr_str) );

	
	uint16_t context = (asocial_device && IS_ASOCIAL) /*| ... */;
	
	context |= (ogm->flags & UNIDIRECTIONAL_FLAG) ? HAS_UNIDIRECT_FLAG : 0;
	context |= (ogm->flags & DIRECTLINK_FLAG) ? HAS_DIRECTLINK_FLAG : 0;
	context |= (ogm->flags & CLONED_FLAG) ? HAS_CLONED_FLAG : 0;
	context |= (ogm->orig == neigh) ? IS_DIRECT_NEIGH : 0;
	

	debug_all( "Received BATMAN packet via NB: %s , IF: %s %s (from OG: %s, seqno %d, TTL %d, V %d, UDF %d, IDF %d, DPF %d, direct_neigh %d) \n", neigh_str, if_incoming->dev, ifaddr_str, orig_str, ogm->seqno, ogm->ttl, COMPAT_VERSION, (context & HAS_UNIDIRECT_FLAG), (context & HAS_DIRECTLINK_FLAG), (context & HAS_CLONED_FLAG), (context & IS_DIRECT_NEIGH) );

	
	list_for_each( list_pos, &if_list ) {

		batman_if = list_entry( list_pos, struct batman_if, list );

		if ( neigh == batman_if->addr.sin_addr.s_addr ) {
			
			debug_all( "Drop packet: received my own broadcast (sender: %s) \n", neigh_str );
			return;

		}
		
		if ( neigh == batman_if->broad.sin_addr.s_addr ) {
			
			debug_all( "Drop packet: ignoring all packets with broadcast source IP (sender: %s) \n", neigh_str );
			return;
		}
		
		if ( ogm->orig == batman_if->addr.sin_addr.s_addr ) {
			
			context |=  IS_MY_ORIG;
			break;
			
		}

	}
	
	
	if ( context & IS_MY_ORIG ) {
		
		orig_neigh_node = get_orig_node( neigh );

		debug_all( "received my own OGM via NB, lastTxIfSeqno: %d, currRxSeqno: %d, prevRxSeqno: %d, currRxSeqno-prevRxSeqno %d, link_node %s \n", ( if_incoming->out.seqno - OUT_SEQNO_OFFSET ), ogm->seqno, 0, 0, (orig_neigh_node->link_node ? "exist":"NOT exists") /*, orig_neigh_node->bidirect_link[if_incoming->if_num], ogm->seqno - orig_neigh_node->bidirect_link[if_incoming->if_num] */ );

		if ( (context & HAS_DIRECTLINK_FLAG) &&
							( if_incoming->addr.sin_addr.s_addr == ogm->orig ) &&
							( ogm->seqno != ( if_incoming->out.seqno - OUT_SEQNO_OFFSET ) ) ) {
		
			debug_output( 3, "WARNING: to late reception of own OGM via NB %s, lastTxIfSeqno: %d, currRxSeqno: %d \n", neigh_str, ( if_incoming->out.seqno - OUT_SEQNO_OFFSET ), ogm->seqno  );

		}							   

		/* neighbour has to indicate direct link and it has to come via the corresponding interface */
		/* if received seqno equals last send seqno save new seqno for bidirectional check */
		if ( (context & HAS_DIRECTLINK_FLAG) &&
						( if_incoming->addr.sin_addr.s_addr == ogm->orig ) &&
						( !(context & HAS_CLONED_FLAG) ) &&
						( ogm->seqno == ( if_incoming->out.seqno - OUT_SEQNO_OFFSET ) ) &&
						( orig_neigh_node->link_node != NULL ) &&
						( orig_neigh_node->primary_orig_node != NULL )  ){
	
			orig_neigh_node->link_node->lndev[if_incoming->if_num].last_rtq_sqn = 
					update_bits(	((0x01)<<(OGM_BITS_SIZE-1)), ogm->seqno,
							&(orig_neigh_node->link_node->lndev[ if_incoming->if_num ].rtq_sqr),
							orig_neigh_node->link_node->lndev[ if_incoming->if_num ].last_rtq_sqn, 1, my_lws,
							DBGL_ALL );
				

			if ( orig_neigh_node->primary_orig_node->id4me != ogm->prev_hop_id ) {
		
				if( orig_neigh_node->primary_orig_node->id4me != 0 ) 
					debug_output( 0, "WARNING: received changed prev_hop_id from neighbor %s !!!!!!!\n", neigh_str );
			
				orig_neigh_node->primary_orig_node->id4me = ogm->prev_hop_id;
			}
	
			debug_all( "indicating bidirectional link - updating bidirect_link seqno \n");
	
		} else {
	
			debug_all( "NOT indicating bidirectional link - NOT updating bidirect_link seqno \n");
	
		}
	
		debug_all( "Drop packet: originator packet from myself (via neighbour) \n" );
		return;

	} 
	
	if ( context & HAS_UNIDIRECT_FLAG ) {
		debug_all( "Drop packet: originator packet with unidirectional flag \n" );
		return;
	} 
		
	orig_node = get_orig_node( ogm->orig );

	/* if sender is a direct neighbor the sender ip equals originator ip */
	orig_neigh_node = ( (context & IS_DIRECT_NEIGH) ? orig_node : get_orig_node( neigh ) );

	/* drop packet if sender is not a direct neighbor and if we have no route towards the rebroadcasting neighbor */
	if ( !(context & IS_DIRECT_NEIGH)  &&  orig_neigh_node->router == NULL  ) {

		debug_all( "Drop packet: OGM via unkown neighbor! \n" );
		return;

	} 
	
	if ( !(context & IS_DIRECT_NEIGH)  &&  ( orig_neigh_node->primary_orig_node == NULL ||
					orig_neigh_node->primary_orig_node->id4me == 0 ||
					orig_neigh_node->primary_orig_node->id4me == ogm->prev_hop_id ) ) {

		debug_all( "Drop packet: OGM %s via NB %s %s !!!! \n",
				orig_str, neigh_str, 
				( ( orig_neigh_node->primary_orig_node == NULL || orig_neigh_node->primary_orig_node->id4me == 0 ) ? 
		"with unknown primaryOG" :" via two-hop loop " )
				);
		return;
		
	} 

	if ( ogm->ttl == 0 ) {

		debug_all( "Drop packet: TTL of zero! \n" );
		return;

	} 

	if ( ((uint16_t)( ogm->seqno - orig_node->last_valid_sqn )) > ((uint16_t)( FULL_SEQ_RANGE - orig_node->pws )) ) {

		debug_output( 3, "WARNING: Drop packet: OGM from %s, via NB %s, with old seqno! rcvd sqno %i  new pws %d  (old pws %d)  ttl %d  last rcvd seqno %i  (last valid seqno %i)  largest_ttl %d  time %d ! Maybe OGM-aggregation is to radical!?\n", orig_str, neigh_str, ogm->seqno, ogm->pws, orig_node->pws, ogm->ttl, orig_node->last_valid_sqn, orig_node->last_accepted_sqn, orig_node->last_accept_largest_ttl, orig_node->last_valid );
		return;

	} 

	if ( /* this originator IP is known and*/ 
		orig_node->last_valid != 0 && 
		/* seqno is more than 10 times out of timeout */
		    ((uint16_t)( ogm->seqno - orig_node->last_valid_sqn )) > ((uint16_t)(10 * dad_timeout)) && 
		/* but we have received an ogm in less than timeout sec */
		LESS_U32( batman_time, (orig_node->last_valid + (1000 * dad_timeout)) ) 
	   )  {

		debug_output( 0, "Drop packet: DAD alert! OGM from %s via NB %s with out of range seqno! rcvd sqno %i, last accepted seqno: %i at %d!\n              Maybe two nodes are using this IP!? Waiting %d more seconds before reinitialization...\n", orig_str, neigh_str, ogm->seqno, orig_node->last_valid_sqn, orig_node->last_valid, ((orig_node->last_valid + (1000 * dad_timeout)) - batman_time)/1000 );

		return;

	}

	if ( alreadyConsidered( orig_node, ogm->seqno, neigh, if_incoming ) ) {

		debug_all( "Drop packet: Already considered this OGM and SEQNO via this link neighbor ! \n" );
		return;

	}

	if ( (context & HAS_CLONED_FLAG) && orig_neigh_node->primary_orig_node == NULL ) {

		debug_all( "Drop packet: First contact with neighbor MUST be without duplicated flag ! \n" );
		return;

	} 

	
	// OK! OGM seems valid..
	context |= IS_VALID;
	orig_node->last_valid_sqn = ogm->seqno; 
	orig_node->last_valid = batman_time;

	
	update_primary_orig( orig_node, mb );

	update_link( orig_node, ogm->seqno, if_incoming, context, mb->link_flags );

	
	if ( !( orig_node->last_accepted_sqn == ogm->seqno ) )
		context |= IS_NEW;

	if ( orig_neigh_node->link_node != NULL && orig_neigh_node->link_node->lndev[if_incoming->if_num].rtq_sqr.vcnt > 0 )
		context |= IS_BIDIRECTIONAL;

	
	uint16_t rand_num_hundret = rand_num( 100 );

	if ( (context & IS_BIDIRECTIONAL) && ( (context & IS_NEW) || 
				( dup_ttl_limit > 0  && 
				orig_node->last_accepted_sqn == ogm->seqno  &&
				orig_node->last_accept_largest_ttl < ogm->ttl + dup_ttl_limit  &&
				rand_num_hundret < dup_rate  && /* using the same rand_num_hundret is important */
				rand_num_hundret < (100 - (ttl_degrade * (orig_node->last_accept_largest_ttl - ogm->ttl) ))
				)
			) )
			context |= IS_ACCEPTABLE;


	int tq_rate_value = tq_rate( orig_neigh_node, if_incoming, my_lws );

	// finally we only accept OGMs with probability TQ of its incoming link
	// tq_power() returns value between [0..my_lws]. return value of my_lws means 100% acceptance 
	
	if ( (context & IS_ACCEPTABLE)  &&  rand_num_hundret <= (tq_power( tq_rate_value, my_lws )*99)/my_lws + (MAX_ASYMMETRIC_WEIGHT - asymmetric_weight) )
		context |= IS_ACCEPTED;

	if ( context & IS_ACCEPTED )
		s_accepted_ogms++;

	struct neigh_node *nn = update_orig( orig_node, orig_neigh_node, context, mb );

	/* MUST be after update_orig to represent the lates statistics */
	if ( orig_node->router == nn )
		context |= IS_BEST_NEIGH;

	debug_all( "  OGM accepted %s  (acceptable %s)  brc %d  bidirectLink %s  new %s  BNTOG %s  asocial %s  tq %d, asymmetric_w %d  lSqno %d  cSeqno %d  lTtl %d  cTtl %d  ttl_limit %d  rand100 %d   dup_rat: %d  ttl_degrade %d  !\n", 
			( context & IS_ACCEPTED   ? "Y" : "N" ), 
			( context & IS_ACCEPTABLE ? "Y" : "N" ), 
			 nn->accepted_sqr.vcnt,
			( context & IS_BIDIRECTIONAL ? "Y" : "N" ), 
			( context & IS_NEW ? "Y" : "N" ), 
			( context & IS_BEST_NEIGH ? "Y" : "N" ), 
			( context & IS_ASOCIAL ? "Y" : "N" ), 
			  tq_rate_value, asymmetric_weight, orig_node->last_accepted_sqn, ogm->seqno ,orig_node->last_accept_largest_ttl, ogm->ttl, dup_ttl_limit, rand_num_hundret, dup_rate, ttl_degrade );

	schedule_rcvd_ogm( context, orig_neigh_node->primary_orig_node->id4him, mb );

	return;
}


static inline void strip_packet(  struct msg_buff *mb, unsigned char *pos, int32_t udp_len )
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


			debug_all( "Received ogm: flags. %X,  gw_array_len %d, hna_array_len: %d, srv_array_len %d, pip_array_len %d, remaining bytes %d \n", (mb->ogm)->flags, mb->gw_array_len, mb->hna_array_len, mb->srv_array_len, mb->pip_array_len, udp_len );

			/* prepare for next ogm and attached extension messages */
			udp_len = udp_len - ((((struct bat_packet_common *)pos)->size)<<2);
			pos = pos + ((((struct bat_packet_common *)pos)->size)<<2);

			process_ogm( mb );
			continue;
			
		} else if ( ((struct bat_packet_common *)pos)->bat_type == BAT_TYPE_UPRQ  ) {
			
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
		
		debug_all( "Drop packet: received my own broadcast iif %s, %s \n", mb->iif->dev , mb->neigh_str );

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

	debug_all( "Rcvd packet:(version? %i, link_flags? %X, reserved? %X, size? %i), rcvd udp_len %d via NB %s %s %s \n", 
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
	while ( GREAT_U32(return_time, batman_time) ) {
			
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
			if ( LESS_U32( return_time, (batman_time + 10) ) ) {
					
					//cheating time :-)
				batman_time = return_time;
				return;
					
			}
					
			if ( LESS_U32( return_time, batman_time ) )
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
				
			debug_all( "Select indicated new control client... \n" );
				
			accept_unix_client();
				
			goto loop4Event;
				
		}
			
	
		// check for all connected control clients...
			
		prev_list_head = (struct list_head *)&unix_clients;
	
		list_for_each_safe( list_pos, list_tmp, &unix_clients ) {
			
			client = list_entry( list_pos, struct client_node, list );
				
			if ( FD_ISSET( client->fd, &tmp_wait_set ) ) {
					
				debug_all( "wait4Event(): got msg from control client \n");
					
				handle_unix_control_msg( list_pos, prev_list_head );
					
				goto loop4Event;
				
			} else {
				prev_list_head = (struct list_head *)&client->list;
			}
		
		}
	
			
		// check for connected debug clients...
		for ( i = DBGL_MIN; i <= DBGL_MAX; i++ ) {
			
			prev_list_head = (struct list_head *)&dbgl_clients[i];
				
			list_for_each_safe( list_pos, list_tmp, &dbgl_clients[i] ) {
				
				client = list_entry( list_pos, struct client_node, list );
					
				if ( FD_ISSET( client->fd, &tmp_wait_set ) ) {
						
					debug_all( "wait4Event(): got msg from dbgl client \n");
					
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
	
	debug_all( "schedule_own_ogm(): for %s seqno %d at %d \n", batman_if->dev, batman_if->out.seqno, send_node_new->send_time );
	
	
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

		if ( GREAT_U32(send_packet_tmp->send_time, send_node_new->send_time) ) {

			list_add_before( prev_list_head, list_pos, &send_node_new->list );
			break;

		}

		prev_list_head = &send_packet_tmp->list;

	}

	if ( ( send_packet_tmp == NULL ) || ( LSEQ_U32(send_packet_tmp->send_time, send_node_new->send_time) ) )
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







