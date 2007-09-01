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
#include "os.h"
#include "batman.h"
#include "schedule.h"



void schedule_own_packet( struct batman_if *batman_if ) {

	struct forw_node *forw_node_new, *forw_packet_tmp = NULL;
	struct list_head *list_pos, *prev_list_head;


	forw_node_new = debugMalloc( sizeof(struct forw_node), 501 );

	INIT_LIST_HEAD( &forw_node_new->list );

	forw_node_new->send_time = get_time() + originator_interval - JITTER + rand_num( 2 * JITTER );
	forw_node_new->if_outgoing = batman_if;
	forw_node_new->own = 1;

	if ( num_hna > 0 ) {

		forw_node_new->pack_buff = debugMalloc( sizeof(struct bat_packet) + num_hna * 5 * sizeof(unsigned char), 502 );
		memcpy( forw_node_new->pack_buff, (unsigned char *)&batman_if->out, sizeof(struct bat_packet) );
		memcpy( forw_node_new->pack_buff + sizeof(struct bat_packet), hna_buff, num_hna * 5 * sizeof(unsigned char) );
		forw_node_new->pack_buff_len = sizeof(struct bat_packet) + num_hna * 5 * sizeof(unsigned char);
	
	} else {

		forw_node_new->pack_buff = debugMalloc( sizeof(struct bat_packet), 503 );
		memcpy( forw_node_new->pack_buff, &batman_if->out, sizeof(struct bat_packet) );
		forw_node_new->pack_buff_len = sizeof(struct bat_packet);

	}

	
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

}



void schedule_forward_packet( struct bat_packet *in, uint8_t unidirectional, uint8_t directlink, uint8_t cloned, unsigned char *hna_recv_buff, int16_t hna_buff_len, struct batman_if *if_outgoing ) {

	prof_start( PROF_schedule_forward_packet );
	struct forw_node *forw_node_new;

	debug_output( 4, "schedule_forward_packet():  \n" );

	if ( !( ( in->ttl == 1 && directlink) || in->ttl > 1 ) ){

		debug_output( 4, "ttl exceeded \n" );

	} else {

		forw_node_new = debugMalloc( sizeof(struct forw_node), 504 );

		INIT_LIST_HEAD( &forw_node_new->list );

		if ( hna_buff_len > 0 ) {

			forw_node_new->pack_buff = debugMalloc( sizeof(struct bat_packet) + hna_buff_len, 505 );
			memcpy( forw_node_new->pack_buff, in, sizeof(struct bat_packet) );
			memcpy( forw_node_new->pack_buff + sizeof(struct bat_packet), hna_recv_buff, hna_buff_len );
			forw_node_new->pack_buff_len = sizeof(struct bat_packet) + hna_buff_len;

		} else {

			forw_node_new->pack_buff = debugMalloc( sizeof(struct bat_packet), 506 );
			memcpy( forw_node_new->pack_buff, in, sizeof(struct bat_packet) );
			forw_node_new->pack_buff_len = sizeof(struct bat_packet);

		}


		((struct bat_packet *)forw_node_new->pack_buff)->ttl--;
		forw_node_new->send_time = get_time();
		forw_node_new->own = 0;

		forw_node_new->if_outgoing = if_outgoing;

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

		list_add( &forw_node_new->list, &forw_list );

	}

	prof_stop( PROF_schedule_forward_packet );

}



void send_outstanding_packets() {

	prof_start( PROF_send_outstanding_packets );
	struct forw_node *forw_node;
	struct list_head *forw_pos, *if_pos, *temp;
	struct batman_if *batman_if;
	static char orig_str[ADDR_STR_LEN];
	uint8_t directlink;
	uint8_t unidirectional;
	uint8_t ttl, send_ogm_only_via_owning_if;
	
	uint32_t curr_time;


	if ( list_empty( &forw_list ) )
		return;

	curr_time = get_time();

	list_for_each_safe( forw_pos, temp, &forw_list ) {

		forw_node = list_entry( forw_pos, struct forw_node, list );

		if ( forw_node->send_time <= curr_time ) {

			addr_to_string( ((struct bat_packet *)forw_node->pack_buff)->orig, orig_str, ADDR_STR_LEN );

			directlink = ( ( ((struct bat_packet *)forw_node->pack_buff)->flags & DIRECTLINK_FLAG ) ? 1 : 0 );
			unidirectional = ( ( ((struct bat_packet *)forw_node->pack_buff)->flags & UNIDIRECTIONAL_FLAG ) ? 1 : 0 );
			ttl = ((struct bat_packet *)forw_node->pack_buff)->ttl;
			send_ogm_only_via_owning_if = ( (forw_node->own && forw_node->if_outgoing->send_ogm_only_via_owning_if) ? 1 : 0 );
			
			/* change sequence number to network order */
			((struct bat_packet *)forw_node->pack_buff)->seqno = htons( ((struct bat_packet *)forw_node->pack_buff)->seqno );

			/* rebroadcast only to allow neighbor to detect bidirectional link */
			if ( unidirectional || ( directlink && ttl == 0 ) ) {

				if ( forw_node->if_outgoing != NULL ) {

					debug_output( 4, "Forwarding packet (originator %s, seqno %d, TTL %d) on interface %s\n", orig_str, ntohs( ((struct bat_packet *)forw_node->pack_buff)->seqno ), ((struct bat_packet *)forw_node->pack_buff)->ttl, forw_node->if_outgoing->dev );

					if ( send_udp_packet( forw_node->pack_buff, forw_node->pack_buff_len, &forw_node->if_outgoing->broad, forw_node->if_outgoing->udp_send_sock ) < 0 )
						restore_and_exit(0);

				} else {

					debug_output( 0, "Error - can't forward packet with UDF/IDF: outgoing iface not specified \n" );

				}

			/* (re-) broadcast to propagate existence of path to OG*/
			} else {
				
				int32_t send_bucket = -((int32_t)(rand_num( 100 )));
				
				while ( send_bucket <= send_clones ) {
					
					send_bucket = send_bucket + 100;
					
					if ( ( directlink ) && ( forw_node->if_outgoing == NULL ) ) {
	
						debug_output( 0, "Error - can't forward packet with IDF: outgoing iface not specified \n" );
						restore_and_exit(0);
	
					} else {
	
						list_for_each(if_pos, &if_list) {
	
							batman_if = list_entry(if_pos, struct batman_if, list);
	
							if ( !send_ogm_only_via_owning_if || forw_node->if_outgoing == batman_if ) { 
							
								if ( ( directlink ) && ( forw_node->if_outgoing == batman_if ) ) {
									((struct bat_packet *)forw_node->pack_buff)->flags = 
											((struct bat_packet *)forw_node->pack_buff)->flags | DIRECTLINK_FLAG;
								} else {
									((struct bat_packet *)forw_node->pack_buff)->flags = 
											((struct bat_packet *)forw_node->pack_buff)->flags & ~DIRECTLINK_FLAG;
								}
		
								debug_output( 4, "Forwarding packet (originator %s, seqno %d, TTL %d) on interface %s\n", orig_str, ntohs( ((struct bat_packet *)forw_node->pack_buff)->seqno ), ((struct bat_packet *)forw_node->pack_buff)->ttl, batman_if->dev );
		
								/* OGMs for non-primary interfaces do not send hna information */
								if ( ( forw_node->own ) && ( ((struct bat_packet *)forw_node->pack_buff)->orig != ((struct batman_if *)if_list.next)->addr.sin_addr.s_addr ) ) {
		
									if ( send_udp_packet( forw_node->pack_buff, sizeof(struct bat_packet), &batman_if->broad, batman_if->udp_send_sock ) < 0 )
										restore_and_exit(0);
		
								} else {
		
									if ( send_udp_packet( forw_node->pack_buff, forw_node->pack_buff_len, &batman_if->broad, batman_if->udp_send_sock ) < 0 )
										restore_and_exit(0);
		
								}
	
							}
						}
						
					((struct bat_packet *)forw_node->pack_buff)->flags = 
							((struct bat_packet *)forw_node->pack_buff)->flags | CLONED_FLAG;
					
					}
				
				}

			}

			list_del( (struct list_head *)&forw_list, forw_pos, &forw_list );

			if ( forw_node->own )
				schedule_own_packet( forw_node->if_outgoing );

			debugFree( forw_node->pack_buff, 1501 );
			debugFree( forw_node, 1502 );

		} else {

			break;

		}

	}

	prof_stop( PROF_send_outstanding_packets );

}


