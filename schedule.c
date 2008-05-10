/* Copyright (C) 2006 B.A.T.M.A.N. contributors:
 * Simon Wunderlich, Marek Lindner, Axel Neumann
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



#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "os.h"
#include "batman.h"
#include "originator.h"
#include "schedule.h"



void schedule_own_packet( struct batman_if *batman_if, uint32_t current_time ) {

	struct forw_node *forw_node_new, *forw_packet_tmp = NULL;
	struct list_head *list_pos, *prev_list_head;
	
	struct link_node *ln;
	struct list_head *link_pos;


	forw_node_new = debugMalloc( sizeof(struct forw_node), 501 );
	memset( forw_node_new, 0, sizeof( struct forw_node) );

	INIT_LIST_HEAD( &forw_node_new->list );

	
	if ( aggregations_po )
		forw_node_new->send_time = current_time + my_ogi - (my_ogi/(2*aggregations_po));
	else
		forw_node_new->send_time = current_time + my_ogi + rand_num( 2 * JITTER ) - JITTER;
	
	debug_output( 4, "schedule_own_packet(): for %s seqno %d at %d \n", batman_if->dev, batman_if->out.seqno, forw_node_new->send_time );
	
	
	forw_node_new->if_outgoing = batman_if;
	forw_node_new->own = 1;

	/* only primary interfaces send usual extension messages */
	if (  batman_if->if_num == 0  ) {
		
		//TBD: Do we really need sizeof(unsigned char) ???
		
		forw_node_new->pack_buff_len = calc_ogm_if_size( 0 );
		
		forw_node_new->pack_buff = debugMalloc( forw_node_new->pack_buff_len , 502 );

		memcpy( forw_node_new->pack_buff, (unsigned char *)&batman_if->out, sizeof(struct bat_packet) );
		
		
		if ( my_gw_ext_array_len > 0 )
			memcpy( forw_node_new->pack_buff + sizeof(struct bat_packet), (unsigned char *)my_gw_ext_array, my_gw_ext_array_len * sizeof(struct ext_packet) );
		
		if ( my_hna_ext_array_len > 0 )
			memcpy( forw_node_new->pack_buff + sizeof(struct bat_packet) + (my_gw_ext_array_len * sizeof(struct ext_packet)), (unsigned char *)my_hna_ext_array, my_hna_ext_array_len * sizeof(struct ext_packet) );
		
		if ( my_srv_ext_array_len > 0 )
			memcpy( forw_node_new->pack_buff + sizeof(struct bat_packet) + ((my_gw_ext_array_len + my_hna_ext_array_len) * sizeof(struct ext_packet)), (unsigned char *)my_srv_ext_array, my_srv_ext_array_len * sizeof(struct ext_packet) );

	/* all non-primary interfaces send primary-interface extension message */
	} else {

		forw_node_new->pack_buff_len = calc_ogm_if_size( 1 );
		
		forw_node_new->pack_buff = debugMalloc( forw_node_new->pack_buff_len , 502 );

		memcpy( forw_node_new->pack_buff, (unsigned char *)&batman_if->out, sizeof(struct bat_packet) );

		memcpy( forw_node_new->pack_buff + sizeof(struct bat_packet), (unsigned char *)my_pip_ext_array, my_pip_ext_array_len * sizeof(struct ext_packet) );

	}

	
	/* change sequence number to network order */
	((struct bat_packet *)forw_node_new->pack_buff)->seqno = htons( ((struct bat_packet *)forw_node_new->pack_buff)->seqno );
	
	((struct bat_packet *)forw_node_new->pack_buff)->size = (calc_ogm_if_size( batman_if->if_num ))/4;

	
	prev_list_head = (struct list_head *)&forw_list;

	list_for_each( list_pos, &forw_list ) {

		forw_packet_tmp = list_entry( list_pos, struct forw_node, list );

		if ( forw_packet_tmp->send_time > forw_node_new->send_time ) {

			list_add_before( prev_list_head, list_pos, &forw_node_new->list );
			break;

		}

		prev_list_head = &forw_packet_tmp->list;

	}

	if ( ( forw_packet_tmp == NULL ) || ( forw_packet_tmp->send_time <= forw_node_new->send_time ) )
		list_add_tail( &forw_node_new->list, &forw_list );

	batman_if->out.seqno++;

	list_for_each( link_pos, &link_list ) {

		ln = list_entry(link_pos, struct link_node, list);
		
		purge_old_bits( ( &ln->bi_link_bits[ batman_if->if_num * MAX_NUM_WORDS ] ),
				   ( ( batman_if->out.seqno - OUT_SEQNO_OFFSET ) - ln->last_bi_link_seqno[batman_if->if_num] ), 0, bidirect_link_to );
	
		ln->last_bi_link_seqno[batman_if->if_num] = ( batman_if->out.seqno - OUT_SEQNO_OFFSET );
		
		ln->rcvd_bi_link_packets[batman_if->if_num] = bit_packet_count( ( &ln->bi_link_bits[ batman_if->if_num * MAX_NUM_WORDS ] ), bidirect_link_to );
		
	}
	
}



void schedule_forward_packet( uint8_t unidirectional, uint8_t directlink, uint8_t cloned, uint16_t neigh_id ) {

	prof_start( PROF_schedule_forward_packet );
	struct forw_node *forw_node_new, *forw_packet_tmp = NULL;
	struct list_head *list_pos, *prev_list_head;
	int ext_msg_size;
	
	debug_output( 4, "schedule_forward_packet():  \n" );

	if ( !( ( (*received_ogm)->ttl == 1 && directlink) || (*received_ogm)->ttl > 1 ) ){

		debug_output( 4, "ttl exceeded \n" );

	} else {

		forw_node_new = debugMalloc( sizeof(struct forw_node), 504 );
		memset( forw_node_new, 0, sizeof( struct forw_node) );

		INIT_LIST_HEAD( &forw_node_new->list );


		/* primary-interface-extension messages do not need to be rebroadcastes */
		/* other extension messages only if not unidirectional and ttl > 1 */
		
		ext_msg_size = ( !unidirectional  &&  (*received_ogm)->ttl > 1 ) ? 
				(((*received_gw_pos) + (*received_hna_pos) + (*received_srv_pos) + (*received_vis_pos) ) * sizeof( struct ext_packet)) : 0 ;
		
		forw_node_new->pack_buff_len = sizeof(struct bat_packet) + ext_msg_size;
		
		
		
		forw_node_new->pack_buff = debugMalloc( forw_node_new->pack_buff_len, 505 );
		
		memcpy( forw_node_new->pack_buff, (*received_ogm), sizeof(struct bat_packet) );
		
		if ( ext_msg_size  &&  (*received_gw_pos) > 0 )
			memcpy( forw_node_new->pack_buff + sizeof(struct bat_packet), (unsigned char *)(*received_gw_array), ((*received_gw_pos) * sizeof( struct ext_packet)) );

		if ( ext_msg_size  &&  (*received_hna_pos) > 0 )
			memcpy( forw_node_new->pack_buff + sizeof(struct bat_packet) + 
					(((*received_gw_pos) ) * sizeof( struct ext_packet)),
					   (unsigned char *)(*received_hna_array), ((*received_hna_pos) * sizeof( struct ext_packet)) );
		
		if ( ext_msg_size  &&  (*received_srv_pos) > 0 )
			memcpy( forw_node_new->pack_buff + sizeof(struct bat_packet) + 
					(((*received_gw_pos) + (*received_hna_pos)) * sizeof( struct ext_packet)), 
					   (unsigned char *)(*received_srv_array), ((*received_srv_pos) * sizeof( struct ext_packet)) );

		if ( ext_msg_size  &&  (*received_vis_pos) > 0 )
			memcpy( forw_node_new->pack_buff + sizeof(struct bat_packet) + 
					(((*received_gw_pos) + (*received_hna_pos) + (*received_srv_pos)) * sizeof( struct ext_packet)), 
					    (unsigned char *)(*received_vis_array), ((*received_vis_pos) * sizeof( struct ext_packet)) );
		
		
		/* primary interface annoucements must not be rebroadcasted */
		/*
		if ( (*received_pip_pos) > 0 )
			memcpy( forw_node_new->pack_buff + sizeof(struct bat_packet) + 
					(((*received_gw_pos) + (*received_hna_pos) + (*received_srv_pos) + (*received_vis_pos)) * sizeof( struct ext_packet)), 
					    (unsigned char *)(*received_pip_array), ((*received_pip_pos) * sizeof( struct ext_packet)) );
		*/
		
		((struct bat_packet *)forw_node_new->pack_buff)->ttl--;
		//((struct bat_packet *)forw_node_new->pack_buff)->prev_hop = (*received_neigh);
		((struct bat_packet *)forw_node_new->pack_buff)->prev_hop_id = neigh_id;
		
		((struct bat_packet *)forw_node_new->pack_buff)->size = (forw_node_new->pack_buff_len)>>2;

		forw_node_new->send_time = (*received_batman_time) + rand_num( rebrc_delay );
		forw_node_new->own = 0;

		forw_node_new->if_outgoing = *received_if_incoming;

		((struct bat_packet *)forw_node_new->pack_buff)->flags = 0x00;
		
		if ( unidirectional ) {

			((struct bat_packet *)forw_node_new->pack_buff)->flags = 
					((struct bat_packet *)forw_node_new->pack_buff)->flags | ( UNIDIRECTIONAL_FLAG | DIRECTLINK_FLAG );

		} else if ( directlink ) {

			((struct bat_packet *)forw_node_new->pack_buff)->flags = 
					((struct bat_packet *)forw_node_new->pack_buff)->flags | DIRECTLINK_FLAG;

		} 
		
		if ( cloned ) {
			((struct bat_packet *)forw_node_new->pack_buff)->flags = 
					((struct bat_packet *)forw_node_new->pack_buff)->flags | CLONED_FLAG;
		}			

		
		/* change sequence number to network order */
		((struct bat_packet *)forw_node_new->pack_buff)->seqno = htons( ((struct bat_packet *)forw_node_new->pack_buff)->seqno );
		

		prev_list_head = (struct list_head *)&forw_list;

		list_for_each( list_pos, &forw_list ) {

			forw_packet_tmp = list_entry( list_pos, struct forw_node, list );

			if ( forw_packet_tmp->send_time > forw_node_new->send_time ) {

				list_add_before( prev_list_head, list_pos, &forw_node_new->list );
				break;

			}

			prev_list_head = &forw_packet_tmp->list;

		}

		if ( ( forw_packet_tmp == NULL ) || ( forw_packet_tmp->send_time <= forw_node_new->send_time ) )
			list_add_tail( &forw_node_new->list, &forw_list );

		
	}

	prof_stop( PROF_schedule_forward_packet );

}


void send_aggregated_packets( int *cycle ) {
	struct list_head *if_pos;
	struct batman_if *batman_if;
//	char fake_arg[ADDR_STR_LEN + 12], ifaddr_str[ADDR_STR_LEN];

	uint8_t iftype;

	(*cycle)++;
	
	/* send all the aggregated packets (which fit into max packet size) */
	
	/* broadcast via lan interfaces first */
	for ( iftype = 0; iftype <= 1; iftype++ ) {
		
		list_for_each(if_pos, &if_list) {
		
			batman_if = list_entry(if_pos, struct batman_if, list);
		
			if ( batman_if->is_wlan == iftype && batman_if->packet_out_len > sizeof( struct bat_header ) ) {
				
				((struct bat_header*)&(batman_if->packet_out))->version = COMPAT_VERSION;
				((struct bat_header*)&(batman_if->packet_out))->size = (batman_if->packet_out_len)/4;
				
				if ( batman_if->packet_out_len > MAX_PACKET_OUT_SIZE  ||  (batman_if->packet_out_len)%4 != 0) {
					
					debug_output( 0, "Error - trying to send strange packet length %d oktets.\n", batman_if->packet_out_len );
					restore_and_exit(0);
					
				}
				
				if ( send_udp_packet( batman_if->packet_out, batman_if->packet_out_len, &batman_if->broad, batman_if->udp_send_sock, batman_if ) < 0 ) {
					
					//check_interfaces();
/*					
					deactivate_interface( batman_if );
					
					if ( batman_if->if_num != 0 ) {
						addr_to_string( batman_if->addr.sin_addr.s_addr, ifaddr_str, sizeof(ifaddr_str) );
						sprintf( fake_arg, "%s/32", ifaddr_str);
						prepare_add_del_own_hna( fake_arg, YES, A_TYPE_INTERFACE );
						add_del_own_hna( NO );	
					}

					purge_orig( 0 );
*/					
				}
				
				s_broadcasted_aggregations++;
				
				if ( *cycle > 1 )
					s_broadcasted_cp_aggregations++;
				
				batman_if->packet_out_len = sizeof( struct bat_header );
				
			}
		
		}

	}
}


void send_outstanding_packets() {

	prof_start( PROF_send_outstanding_packets );
	struct forw_node *forw_node;
	struct list_head *forw_pos, *if_pos, *forw_temp, *prev_list_head;

	struct batman_if *batman_if;
	static char orig_str[ADDR_STR_LEN];
	uint8_t directlink, unidirectional, cloned, ttl, send_ogm_only_via_owning_if;
	int16_t aggregated_size;
	
	int dbg_if_out = 0, cycle = 0;
#define	MAX_DBG_IF_SIZE 200
	static char dbg_if_str[ MAX_DBG_IF_SIZE ];
	
	uint32_t send_time = *received_batman_time;
	

	if ( list_empty( &forw_list )  ||  GREAT_U32( (list_entry( (&forw_list)->next, struct forw_node, list ))->send_time, send_time ) )
		return;	
	
	debug_output( 4, "send_outstanding_packets(): now %u, aggregations_po %d, forw_list holds packets to send \n", send_time, aggregations_po );

	
	aggregated_size = sizeof( struct bat_header );
	
	list_for_each( forw_pos, &forw_list ) {
		
		forw_node = list_entry( forw_pos, struct forw_node, list );
		
		if ( aggregated_size > sizeof( struct bat_header ) && 
				   ( aggregations_po == 0  ||  (aggregated_size + forw_node->pack_buff_len) > MAX_PACKET_OUT_SIZE )  ) {

			send_aggregated_packets( &cycle );
			
			debug_output( 4, "send_outstanding_packets(): cycle %d, max aggregated size %d \n\n", cycle,  aggregated_size );
			
			aggregated_size = sizeof( struct bat_header );
			
		}
		
		if ( LSEQ_U32( forw_node->send_time, send_time )  &&  (aggregated_size + forw_node->pack_buff_len) <= MAX_PACKET_OUT_SIZE ) {
			
			if ( forw_node->send_bucket == 0 )
				forw_node->send_bucket =  ((int32_t)(rand_num( 100 )));

			forw_node->iteration++;	
			forw_node->send = YES;
			forw_node->done = YES;
			
			// keep care to not aggregate more packets than would fit into max packet size
			aggregated_size+= forw_node->pack_buff_len;
			
			addr_to_string( ((struct bat_packet *)forw_node->pack_buff)->orig, orig_str, ADDR_STR_LEN );

			directlink =     (((struct bat_packet *)forw_node->pack_buff)->flags & DIRECTLINK_FLAG );
			unidirectional = (((struct bat_packet *)forw_node->pack_buff)->flags & UNIDIRECTIONAL_FLAG );
			cloned =         (((struct bat_packet *)forw_node->pack_buff)->flags & CLONED_FLAG );

			ttl = ((struct bat_packet *)forw_node->pack_buff)->ttl;
			send_ogm_only_via_owning_if = ( (forw_node->own && forw_node->if_outgoing->send_ogm_only_via_owning_if) ? 1 : 0 );
			
			
			if ( directlink  &&  forw_node->if_outgoing == NULL  ) {
	
				debug_output( 0, "Error - can't forward packet with IDF: outgoing iface not specified \n" );
				restore_and_exit(0);
	
			}
			
			/* rebroadcast only to allow neighbor to detect bidirectional link */
			if ( forw_node->iteration == 1 && directlink && !cloned && ( unidirectional || ttl == 0 ) ) {
				
				
				dbg_if_out = dbg_if_out + snprintf( (dbg_if_str + dbg_if_out), (MAX_DBG_IF_SIZE - dbg_if_out), " %-12s  (NBD)", forw_node->if_outgoing->dev );

				//TODO: send only pure bat_packet, no extension headers.
				memcpy( (forw_node->if_outgoing->packet_out + forw_node->if_outgoing->packet_out_len), forw_node->pack_buff, forw_node->pack_buff_len );

				s_broadcasted_ogms++;
				
				forw_node->if_outgoing->packet_out_len+= forw_node->pack_buff_len;
			

			/* (re-) broadcast to propagate existence of path to OG*/
			} else if ( !unidirectional && ttl > 0 ) {
				
	
				list_for_each(if_pos, &if_list) {

					batman_if = list_entry(if_pos, struct batman_if, list);

					if ( ( forw_node->send_bucket < batman_if->if_send_clones ) && 
						( !send_ogm_only_via_owning_if || forw_node->if_outgoing == batman_if ) ) { 
					
						if ( (forw_node->send_bucket + 100) < batman_if->if_send_clones )
							forw_node->done = NO;
						
						
						memcpy( (batman_if->packet_out + batman_if->packet_out_len), forw_node->pack_buff, forw_node->pack_buff_len );
						
						
						if ( ( directlink ) && ( forw_node->if_outgoing == batman_if ) )
							((struct bat_packet *)(batman_if->packet_out + batman_if->packet_out_len))->flags = 
								((struct bat_packet *)(batman_if->packet_out + batman_if->packet_out_len))->flags | DIRECTLINK_FLAG;
						else
							((struct bat_packet *)(batman_if->packet_out + batman_if->packet_out_len))->flags = 
								((struct bat_packet *)(batman_if->packet_out + batman_if->packet_out_len))->flags & ~DIRECTLINK_FLAG;
						
						
						s_broadcasted_ogms++;
							
						batman_if->packet_out_len+= forw_node->pack_buff_len;
						
						dbg_if_out = dbg_if_out + snprintf( (dbg_if_str + dbg_if_out), (MAX_DBG_IF_SIZE - dbg_if_out), " %-12s", batman_if->dev );
						
						if (send_ogm_only_via_owning_if && forw_node->if_outgoing == batman_if)
							dbg_if_out = dbg_if_out + snprintf( (dbg_if_str + dbg_if_out), (MAX_DBG_IF_SIZE - dbg_if_out), "  (npIF)" );

						
					}
				}
				
				
				((struct bat_packet *)forw_node->pack_buff)->flags = 
						((struct bat_packet *)forw_node->pack_buff)->flags | CLONED_FLAG;
				
			}
			
			forw_node->send_bucket = forw_node->send_bucket + 100;

			debug_output( 4, "Sending packet (originator %-16s, seqno %5d, TTL %2d, IDF %d, UDF %d, CLF %d) iter %d len %3d agg_size %3d IFs %s \n", orig_str, ntohs( ((struct bat_packet *)forw_node->pack_buff)->seqno ), ((struct bat_packet *)forw_node->pack_buff)->ttl, directlink, unidirectional, cloned, forw_node->iteration, forw_node->pack_buff_len, aggregated_size, dbg_if_str );
				
			dbg_if_out = 0;
			
		} else {
			
			if ( LSEQ_U32( forw_node->send_time, send_time )  &&  aggregated_size <= sizeof( struct bat_header ) ) {
			
				debug_output( 0, "Error - Drop Packet, single packet to large to fit maximum packet size scheduled time %d, now %d, agg_size %d, next_len %d !! \n", forw_node->send_time,  send_time, aggregated_size,  forw_node->pack_buff_len );
				
				forw_node->iteration++;	
				forw_node->send = YES;
				forw_node->done = YES;

				//restore_and_exit(0);
				
			}
			
			break; // for now we are done, 
			
		}
		
	}
	
	
	if ( aggregated_size > sizeof( struct bat_header ) ) {
	
		send_aggregated_packets( &cycle );
		
		debug_output( 4, "send_outstanding_packets(): cycle %d, max aggregated size %d \n\n", cycle,  aggregated_size );
	
	}

	
	
	/* remove all the send packets from forw_list, set new timer for un-finished clones... */
	
	prev_list_head = (struct list_head *)&forw_list;
	
	list_for_each_safe( forw_pos, forw_temp, &forw_list ) {
	
		forw_node = list_entry( forw_pos, struct forw_node, list );
	
		if ( forw_node->send == YES ) {
					
			// to trigger the scheduling of the next own OGMs at the end of this function
			if (  forw_node->own  &&  forw_node->iteration == 1  )
				forw_node->if_outgoing->send_own = 1;
				
			if ( forw_node->done ) {
			
				list_del( prev_list_head, forw_pos, &forw_list );
				
				debugFree( forw_node->pack_buff, 1501 );
				debugFree( forw_node, 1502 );
				
			} else {
				
				forw_node->send_time = send_time + 1;
				forw_node->send = NO;
				forw_node->done = NO;
				
				prev_list_head = &forw_node->list;	
				
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
			schedule_own_packet( batman_if, send_time );

		batman_if->send_own = 0;
				
	}

	
	prof_stop( PROF_send_outstanding_packets );

}


