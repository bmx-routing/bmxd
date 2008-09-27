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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "os.h"
#include "batman.h"
#include "metrics.h"
#include "control.h"
#include "dispatch.h"
#include "originator.h"


SIMPEL_LIST( pifnb_list );
SIMPEL_LIST( link_list );

void init_originator( void ) {
	
//	INIT_LIST_HEAD_FIRST( pifnb_list );
//	INIT_LIST_HEAD_FIRST( link_list );

}


/* this function finds or creates an originator entry for the given address if it does not exits */
struct orig_node *get_orig_node( uint32_t addr ) {

	prof_start( PROF_get_orig_node );
	struct orig_node *orig_node;
	struct hashtable_t *swaphash;
	static char orig_str[ADDR_STR_LEN];

	
	orig_node = ((struct orig_node *)hash_find( orig_hash, &addr ));

	if ( orig_node != NULL ) {

		orig_node->last_aware = batman_time;
		prof_stop( PROF_get_orig_node );
		return orig_node;

	}


	addr_to_string( addr, orig_str, ADDR_STR_LEN );
	debug_output( 4, "Creating new originator: %s \n", orig_str );

	orig_node = debugMalloc( sizeof(struct orig_node), 402 );
	memset(orig_node, 0, sizeof(struct orig_node));
	INIT_LIST_HEAD_FIRST( orig_node->neigh_list );

	orig_node->orig = addr;
	orig_node->last_aware = batman_time;

	orig_node->router = NULL;
//	orig_node->batman_if = NULL;
	orig_node->link_node = NULL;
	
	orig_node->ca10ogis = 10 * DEFAULT_ORIGINATOR_INTERVAL;
	orig_node->pws = DEF_SEQ_RANGE;
	
	hash_add( orig_hash, orig_node );

	if ( orig_hash->elements * 4 > orig_hash->size ) {

		swaphash = hash_resize( orig_hash, orig_hash->size * 2 );

		if ( swaphash == NULL ) {

			debug_output( 0, "Couldn't resize hash table \n" );
			cleanup_all( CLEANUP_FAILURE );

		}

		orig_hash = swaphash;

	}

	prof_stop( PROF_get_orig_node );
	return orig_node;

}



void flush_neigh_node_seqnos( struct orig_node *orig_node ) {
	struct list_head *neigh_pos;
	struct neigh_node *tmp_neigh_node = NULL;

	list_for_each( neigh_pos, &orig_node->neigh_list ) {

		tmp_neigh_node = list_entry( neigh_pos, struct neigh_node, list );
				
		flush_sq_record( &tmp_neigh_node->accepted_sqr, MAX_REC_WORDS );
		
		//flush_sq_record( &tmp_neigh_node->vld_sqr, MAX_REC_WORDS );

	}
	
}

struct neigh_node *init_neigh_node( struct orig_node *orig_node, uint32_t neigh, struct batman_if *iif, uint16_t seqno, uint32_t last_aware )
{
	debug_output( 4, "Creating new last-hop neighbour of originator\n" );

	struct neigh_node *neigh_node = debugMalloc( sizeof (struct neigh_node), 403 );
	memset( neigh_node, 0, sizeof(struct neigh_node) );
	INIT_LIST_HEAD( &neigh_node->list );

	neigh_node->accepted_sqr.bits = debugMalloc( MAX_REC_WORDS * sizeof(REC_BITS_TYPE), 486 );
	flush_sq_record( &neigh_node->accepted_sqr, MAX_REC_WORDS );
	
	//neigh_node->vld_sqr.bits = debugMalloc( MAX_REC_WORDS * sizeof(REC_BITS_TYPE), 487 );
	//flush_sq_record( &neigh_node->vld_sqr, MAX_REC_WORDS );
	
	neigh_node->addr = neigh;
	neigh_node->if_incoming = iif;
	neigh_node->last_considered_seqno = seqno;
	neigh_node->last_aware = last_aware;
	
	list_add_tail( &neigh_node->list, &orig_node->neigh_list );
	return neigh_node;

}

void free_neigh_node( struct neigh_node *neigh_node )
{
	debugFree( neigh_node->accepted_sqr.bits, 1486 );
	//debugFree( neigh_node->vld_sqr.bits, 1487 );

	memset( neigh_node, 123, sizeof( struct neigh_node ) );
	debugFree( neigh_node, 1403 );
}

void update_orig( struct orig_node *orig_node, struct orig_node *orig_neigh_node, uint8_t acceppted, struct msg_buff *mb ) {

	prof_start( PROF_update_originator );
	
	struct list_head *neigh_pos;
	struct neigh_node *neigh_node = NULL, *tmp_neigh_node = NULL, *best_neigh_node = NULL;
	uint8_t max_packet_count = 0 /*, is_new_seqno = 0*/; // TBD: check max_packet_count for overflows if MAX_SEQ_RANGE > 256
	struct bat_packet_ogm *in = mb->ogm;
	
	int16_t hna_count;
	struct hna_key key;
	struct hna_hash_node *hash_node;
	static char addr_str[ADDR_STR_LEN], orig_str[ADDR_STR_LEN], blocker_str[ADDR_STR_LEN], hna_str[ADDR_STR_LEN];
	
	addr_to_string( orig_node->orig, orig_str, ADDR_STR_LEN );
	debug_output( 4, "update_originator(): Updating originator (%s) entry of received packet,  \n", orig_str );

	/* it seems we missed a lot of packets or the other host restarted */
	
	
	/* only used for debugging purposes */
	if (  orig_node->first_valid_sec == 0 /* ||  
		     ((int16_t)(in->seqno - orig_node->last_accept_seqno)) > orig_node->ws  ||  
		     ((int16_t)(in->seqno - orig_node->last_accept_seqno)) < -(orig_node->ws) */  )
		orig_node->first_valid_sec = get_time_sec();
	
	
	
	list_for_each( neigh_pos, &orig_node->neigh_list ) {

		tmp_neigh_node = list_entry( neigh_pos, struct neigh_node, list );

		if ( ( tmp_neigh_node->addr == mb->neigh ) && ( tmp_neigh_node->if_incoming == mb->iif ) ) {

			neigh_node = tmp_neigh_node;

		} else {

			update_bits( 0, in->seqno,  &tmp_neigh_node->accepted_sqr, orig_node->last_accepted_sqn, 1, orig_node->pws,  DBGL_ALL );
			
			/* if we got more packets via this neighbour or same amount of packets if it is currently our best neighbour (to avoid route flipping) */
			if ( ( tmp_neigh_node->accepted_sqr.vcnt > max_packet_count ) || ( ( orig_node->router == tmp_neigh_node ) && 
				( tmp_neigh_node->accepted_sqr.vcnt >= max_packet_count ) ) ) {

				max_packet_count = tmp_neigh_node->accepted_sqr.vcnt;
				best_neigh_node = tmp_neigh_node;

			}

		}

	}

	if ( neigh_node == NULL ) {

		debug_output( 0, "WARNING, Creating new last-hop neighbour of originator, This should already have happened during alreadyConsidered() \n" );

		neigh_node = init_neigh_node( orig_node, mb->neigh, mb->iif, in->seqno, batman_time );
		

	} else {

		debug_output( 4, "Updating existing last-hop neighbour of originator\n" );

	}

	SQ_TYPE new_seqno = update_bits( acceppted?((0x01)<<(OGM_BITS_SIZE-1)):0, in->seqno,
					 &neigh_node->accepted_sqr,  orig_node->last_accepted_sqn, 1, orig_node->pws,
					  DBGL_ALL );
	
	if ( neigh_node->accepted_sqr.vcnt > max_packet_count ) {

		max_packet_count = neigh_node->accepted_sqr.vcnt;
		best_neigh_node  = neigh_node;

	}
	
	/* check for duplicate/blocked hna announcements */
	if ( best_neigh_node == neigh_node  &&  mb->hna_array_len > 0 ) {

		debug_output( 4, "HNA information received (%i HNA networks): \n", mb->hna_array_len );
		hna_count = 0;

		while ( hna_count < mb->hna_array_len ) {
					
			key.addr               = ((mb->hna_array)[hna_count]).EXT_HNA_FIELD_ADDR;
			key.KEY_FIELD_ANETMASK = ((mb->hna_array)[hna_count]).EXT_HNA_FIELD_NETMASK;
			key.KEY_FIELD_ATYPE    = ((mb->hna_array)[hna_count]).EXT_HNA_FIELD_TYPE;
	
			hash_node = get_hna_node( &key );
	
			addr_to_string( key.addr, hna_str, ADDR_STR_LEN );

			if ( hash_node->status == HNA_HASH_NODE_MYONE || 
				(hash_node->status == HNA_HASH_NODE_OTHER && hash_node->orig != orig_node) ) 
			{
		
				if ( hash_node->orig != NULL )
					addr_to_string( hash_node->orig->orig, blocker_str, ADDR_STR_LEN );
				else 
					sprintf( blocker_str, "myself");
							
				
				debug_output( 3, "Dropping packet, purging packet bits, del route... ! hna: %s/%d type %d, announced by %s is blocked by %s !\n",
						hna_str, key.KEY_FIELD_ANETMASK, key.KEY_FIELD_ATYPE, orig_str, blocker_str );
				
				flush_neigh_node_seqnos( orig_node );
				
				update_routes( orig_node, NULL, NULL, 0 );
				
				/* restart gateway selection if this was our current gw */
				if (  curr_gateway != NULL  &&  curr_gateway->orig_node == orig_node  ) {
	
					debug_output( 3, "Restart gateway selection. Current GW %s disqualified...\n", orig_str );
	
					del_default_route();
				}
				
				return;
				
			} else {

				if (  key.KEY_FIELD_ANETMASK > 0  &&  key.KEY_FIELD_ANETMASK <= 32  &&  key.KEY_FIELD_ATYPE <= A_TYPE_MAX )
					debug_output( 4, "  hna: %s/%i, type %d\n", hna_str, key.KEY_FIELD_ANETMASK, key.KEY_FIELD_ATYPE );
				else
					debug_output( 4, "  hna: %s/%i, type %d -> ignoring (invalid netmask or type) \n", hna_str, key.KEY_FIELD_ANETMASK, key.KEY_FIELD_ATYPE );

			}

			hna_count++;
		}
	}	
	
	if ( orig_node->last_accepted_sqn != in->seqno ) {

		/* estimated average originaotr interval of this node */
		if ( GREAT_SQ( in->seqno, orig_node->last_accepted_sqn )  &&  orig_node->last_accept_time > 0  &&  orig_node->last_accept_time < batman_time ) {
			
			orig_node->ca10ogis += ((batman_time - orig_node->last_accept_time) / (in->seqno - orig_node->last_accepted_sqn)) -
						(orig_node->ca10ogis/10);
		
		}
		
		orig_node->last_accept_time =  batman_time;
		
		
		//if ( orig_node->last_valid_seqno_largest_ttl != in->ttl )
		debug_output( 4, "updating changed largest_ttl: oldSeqno %d, newSeqno %d, old TTL %d new TTL %d \n", 
			      orig_node->last_accepted_sqn, in->seqno, orig_node->last_accept_largest_ttl,  in->ttl  );
		
		orig_node->last_accept_largest_ttl = in->ttl;
		
		orig_node->last_accepted_sqn = in->seqno;
		
	}

	if ( new_seqno != orig_node->last_accepted_sqn )
		debug_output(DBGL_SYSTEM, "ERROR - update_orig(): new_seqno %d != last_accepted_seqno2 %d !\n", new_seqno, orig_node->last_accepted_sqn );
	
	/* remember the largest ttl (shortest path) seen with this seqno */
	if ( orig_node->last_accepted_sqn == in->seqno && in->ttl > orig_node->last_accept_largest_ttl )
		orig_node->last_accept_largest_ttl = in->ttl;
	
	
	orig_node->last_valid = batman_time;

	
	/* only evaluate and change recorded attributes and route if arrived via best neighbor */
	if ( best_neigh_node == neigh_node ) {

		orig_node->last_reserved_someting = in->reserved_someting;
		
		if ( in->pws >= MIN_SEQ_RANGE  &&  in->pws <= MAX_SEQ_RANGE  &&  orig_node->pws != in->pws ) {
		
			debug_output( 0, "window size of OG %s changed from %d to %d, flushing packets and route!!!! \n", orig_str, orig_node->pws, in->pws );
		
			orig_node->pws = in->pws;
			
			flush_neigh_node_seqnos( orig_node );
				
			update_routes( orig_node, NULL, NULL, 0 );
		
		} else {
			
			update_routes( orig_node, best_neigh_node, mb->hna_array, mb->hna_array_len );
		
		}
	

		orig_node->last_path_ttl = in->ttl;
	
	
		
		
		/* may be service announcements changed */
		if ( ( mb->srv_array_len != orig_node->srv_array_len ) || ( ( mb->srv_array_len > 0 )  && 
				     ( memcmp( orig_node->srv_array, mb->srv_array, mb->srv_array_len * sizeof(struct ext_packet) ) != 0 ) ) ) 
		{

			debug_output( 3, "announced services changed\n");
		
			if ( orig_node->srv_array_len > 0 )
				add_del_other_srv( orig_node, NULL, 0 );

			if ( ( mb->srv_array_len > 0 ) && ( mb->srv_array != NULL ) )
				add_del_other_srv( orig_node, mb->srv_array, mb->srv_array_len );

		}
		
		
		/* may be GW announcements changed */
		
		if ( orig_node->gw_msg  &&  orig_node->gw_msg->EXT_GW_FIELD_GWFLAGS  &&  mb->gw_array_len == 0) {
		
			// remove cached gw_msg
			update_gw_list( orig_node, 0, NULL );
		
		} else if ( orig_node->gw_msg == NULL  &&  mb->gw_array_len > 0  &&  mb->gw_array != NULL ) {
		
			// memorize new gw_msg
			update_gw_list( orig_node, mb->gw_array_len, mb->gw_array  );
		 
		} else if ( orig_node->gw_msg != NULL  &&  mb->gw_array_len > 0  &&  mb->gw_array != NULL  &&  memcmp( orig_node->gw_msg, mb->gw_array, sizeof(struct ext_packet) ) ) {
			
			// update existing gw_msg
			update_gw_list( orig_node, mb->gw_array_len, mb->gw_array  );
		}
	
		/* restart gateway selection if we have more packets and routing class 3 */
		if ( routing_class == 3  &&  curr_gateway != NULL  &&  orig_node->gw_msg  &&  orig_node->gw_msg->EXT_GW_FIELD_GWFLAGS  &&  (orig_node->gw_msg->EXT_GW_FIELD_GWTYPES & ((two_way_tunnel?TWO_WAY_TUNNEL_FLAG:0) | (one_way_tunnel?ONE_WAY_TUNNEL_FLAG:0)))  ) {

			if ( ( curr_gateway->orig_node != orig_node ) && (pref_gateway == 0 || pref_gateway == orig_node->orig ) && ( (curr_gateway->orig_node->router->accepted_sqr.vcnt + gw_change_hysteresis) <= orig_node->router->accepted_sqr.vcnt ) ) {
			
				addr_to_string( curr_gateway->orig_node->orig, addr_str, ADDR_STR_LEN );
			
				debug_output( 3, "Restart gateway selection. Routing class 3 and %d OGMs from GW %s (compared to %d from GW %s)\n",
					      orig_node->router->accepted_sqr.vcnt, orig_str, curr_gateway->orig_node->router->accepted_sqr.vcnt, addr_str );
			
				del_default_route();
		
			}
		}

		
	}
	
	prof_stop( PROF_update_originator );

}



void free_pifnb_node( struct orig_node *orig_node ) {
	struct pifnb_node *pn;
	struct list_head *pifnb_pos, *pifnb_pos_tmp, *prev_list_head;
	
	if ( orig_node->id4him == 0 ) {
		debug_output( 0, "Error - free_pifnb_node(): requested to free pifnb_node with id4him of zero\n");
		cleanup_all( CLEANUP_FAILURE );
	}
	
	prev_list_head = (struct list_head *)&pifnb_list;

	list_for_each_safe( pifnb_pos, pifnb_pos_tmp, &pifnb_list ) {

		pn = list_entry(pifnb_pos, struct pifnb_node, list);

		if ( pn->pog == orig_node ) {
			
			list_del( prev_list_head, pifnb_pos, &pifnb_list );
			
			orig_node->id4him = 0;
			
			debugFree( pn, 1428 );

			break;

		} else {

			prev_list_head = &pn->list;

		}
	}
	
	if ( orig_node->id4him != 0 ) {
		debug_output( 0, "Error - free_pifnb_node(): requested to free non-existent pifnb_node \n");
		cleanup_all( CLEANUP_FAILURE );
	}
	
	
}


void init_pifnb_node( struct orig_node *orig_node ) {
	struct pifnb_node *pn, *pn_tmp = NULL;
	struct list_head *list_pos, *prev_list_head;
	
	if ( orig_node->id4him != 0 ) {
		debug_output( 0, "Error - init_pifnb_node(): requested to init already existing pifnb_node\n");
		cleanup_all( CLEANUP_FAILURE );
	}
	
	pn = debugMalloc( sizeof(struct pifnb_node), 428 );
	memset( pn, 0, sizeof(struct pifnb_node) );
	
	INIT_LIST_HEAD( &pn->list );
	
	pn->pog = orig_node;
	
	
	orig_node->id4him = 1;
	
	prev_list_head = (struct list_head *)&pifnb_list;

	list_for_each( list_pos, &pifnb_list ) {

		pn_tmp = list_entry( list_pos, struct pifnb_node, list );

		if ( pn_tmp->pog->id4him > orig_node->id4him ) {

			list_add_before( prev_list_head, list_pos, &pn->list );
			break;

		}
		
		if ( orig_node->id4him == MAX_ID4HIM ) {
			debug_output( 0, "Error - init_pifnb_node(): Max numbers of pifnb_nodes reached !!\n");
			cleanup_all( CLEANUP_FAILURE );
		}
		
		(orig_node->id4him)++;
		
		prev_list_head = &pn_tmp->list;

	}

	if ( ( pn_tmp == NULL ) || ( pn_tmp->pog->id4him <= orig_node->id4him ) )
		list_add_tail( &pn->list, &pifnb_list );

	
}



void free_link_node( struct orig_node *orig_node ) {
	struct link_node *ln;
	struct list_head *link_pos, *link_pos_tmp, *prev_list_head;
	int i;
	
	if ( orig_node->link_node == NULL ) {
		debug_output( 0, "Error - free_link_node(): requested to free non-existing link_node\n");
		cleanup_all( CLEANUP_FAILURE );
	}
	
	stop_link_probes( orig_node->link_node );
	
	for ( i = 0; i < found_ifs; i++ ) {
		debugFree( orig_node->link_node->lndev[i].rtq_sqr.bits, 1488 );
		debugFree( orig_node->link_node->lndev[i].rq_sqr.bits, 1489 );
		debugFree( orig_node->link_node->lndev[i].up_sqr.bits, 1487 );
	}
		
	debugFree( orig_node->link_node->lndev, 1408 );
	
	prev_list_head = (struct list_head *)&link_list;
			
	list_for_each_safe( link_pos, link_pos_tmp, &link_list ) {

		ln = list_entry(link_pos, struct link_node, list);

		if ( ln->orig_node == orig_node ) {

			list_del( prev_list_head, link_pos, &link_list );
			break;

		} else {

			prev_list_head = &ln->list;

		}
	}
	
	debugFree( orig_node->link_node, 1428 );
	
	orig_node->link_node = NULL;
}


void flush_link_node_seqnos( void ) {
	struct list_head *ln_pos;
	struct link_node *ln = NULL;
	int i;
	
	list_for_each( ln_pos, &link_list ) {

		ln = list_entry( ln_pos, struct link_node, list );
		
		for ( i = 0; i < found_ifs; i++ ) {
						
			flush_sq_record( &(ln->lndev[i].rtq_sqr), MAX_REC_WORDS );

			flush_sq_record( &(ln->lndev[i].rq_sqr), MAX_REC_WORDS );
			
		}
	}
}

void init_link_node( struct orig_node *orig_node, SQ_TYPE in_seqno ) {
	
	struct link_node *ln;
	struct list_head *list_pos;
	
	if ( orig_node->link_node != NULL ) {
		debug_output( 0, "Error - init_link_node(): requested to init already existing link_node\n");
		cleanup_all( CLEANUP_FAILURE );
	}
	
	ln = orig_node->link_node = debugMalloc( sizeof(struct link_node), 428 );
	memset( ln, 0, sizeof(struct link_node) );
	
	ln->orig_node = orig_node;
	
	ln->last_rq_sqn = in_seqno-1;
	
	ln->lndev = debugMalloc( found_ifs * sizeof( struct link_node_dev ), 408 );
	memset( ln->lndev, 0, found_ifs * sizeof( struct link_node_dev ) );
	
	list_for_each( list_pos, &if_list ) {

		struct batman_if *bif = list_entry( list_pos, struct batman_if, list );
		
		struct link_node_dev *lndev = &( ln->lndev[ bif->if_num ] );
		
		lndev->rtq_sqr.bits = debugMalloc( MAX_REC_WORDS * sizeof(REC_BITS_TYPE), 488 );
		
		flush_sq_record( &lndev->rtq_sqr, MAX_REC_WORDS );
		
		lndev->last_rtq_sqn = bif->out.seqno - OUT_SEQNO_OFFSET;
		
		
		lndev->rq_sqr.bits = debugMalloc( MAX_REC_WORDS * sizeof(REC_BITS_TYPE), 489 );
		
		flush_sq_record( &lndev->rq_sqr, MAX_REC_WORDS );
		
		
		//testing the new metrics stuff...
		lndev->up_sqr.bits = debugMalloc( MAX_UNICAST_PROBING_WORDS * sizeof(REC_BITS_TYPE), 487 );
		
		flush_sq_record( &lndev->up_sqr, MAX_UNICAST_PROBING_WORDS );
	
		
	}
	
	
	list_add_tail ( &ln->list, &link_list );
	
	/* this actually just postpones the problem to the moment of wrap-arounds but 
	* its probably less confusing if it happens later than right at the beginning!
	* if orig_node->bidirect_link[i] is regulary updated with
	*  ((SQ_TYPE) (if_incoming->out.bat_packet_ogm.seqno - OUT_SEQNO_OFFSET - my_lws)); 
	* it may work !
	*
	* we have started with randomized seqno anyway:
	for ( i=0; i < found_ifs; i++ ) {
		ln->bidirect_link[i] = ((SQ_TYPE) (0 - OUT_SEQNO_OFFSET - MAX_BIDIRECT_TIMEOUT) ); 
	}
	*/
	
}



void purge_orig( uint32_t curr_time ) {

	prof_start( PROF_purge_originator );
	struct hash_it_t *hashit = NULL;
	struct list_head *neigh_pos, *neigh_temp, *prev_list_head;
	struct list_head *gw_pos, *gw_pos_tmp;
	struct orig_node *orig_node;
	struct neigh_node *neigh_node;
	struct gw_node *gw_node;
	static char orig_str[ADDR_STR_LEN], neigh_str[ADDR_STR_LEN];
	struct list_head *if_pos;
	struct batman_if *batman_if;
	uint8_t free_ln;
	
	/* for all origins... */
	while ( orig_hash  &&  (hashit = hash_iterate( orig_hash, hashit )) ) {

		orig_node = hashit->bucket->data;
		
		/* purge outdated originators completely */
		
		if ( curr_time == 0 || LESS_U32( orig_node->last_aware + PURGE_TIMEOUT , curr_time  )  ) {

			addr_to_string( orig_node->orig, orig_str, ADDR_STR_LEN );
			debug_output( 4, "originator timeout: %s, last_valid %u, last_aware %u  \n", orig_str, orig_node->last_valid, orig_node->last_aware );

			hash_remove_bucket( orig_hash, hashit );

			
			/* remove gw record of this node */
			prev_list_head = (struct list_head *)&gw_list;

			list_for_each_safe( gw_pos, gw_pos_tmp, &gw_list ) {

				gw_node = list_entry(gw_pos, struct gw_node, list);

				if ( gw_node->orig_node == orig_node ) {
			
					if( gw_node == curr_gateway )
						del_default_route();
					
					addr_to_string( gw_node->orig_node->orig, orig_str, ADDR_STR_LEN );
					debug_output( 3, "removing gateway %s from gateway list \n", orig_str );

					list_del( prev_list_head, gw_pos, &gw_list );
					debugFree( gw_pos, 1405 );

					break;

				} else {

					prev_list_head = &gw_node->list;

				}

			}

			if( orig_node->gw_msg != NULL ) {
				debugFree( orig_node->gw_msg, 1123 );
				orig_node->gw_msg = NULL;
			}

			update_routes( orig_node, NULL, NULL, 0 );
			
			if ( orig_node->srv_array_len > 0 )
				add_del_other_srv( orig_node, NULL, 0 );

			
			/* for all neighbours towards this originator ... */
			list_for_each_safe( neigh_pos, neigh_temp, &orig_node->neigh_list ) {

				neigh_node = list_entry(neigh_pos, struct neigh_node, list);
				
				list_del( (struct list_head *)&orig_node->neigh_list, neigh_pos, &orig_node->neigh_list );
				free_neigh_node( neigh_node );
			}
			
			
			/* remove link information of node */
			
			if ( orig_node->link_node != NULL )
				free_link_node( orig_node );
			
			if ( orig_node->id4him != 0 )
				free_pifnb_node( orig_node );
			
			debugFree( orig_node, 1402 );
								

		} else {

			/* purge selected outdated originator elements */
			
			
			/* purge outdated links */
		
			if ( orig_node->link_node != NULL ) {
			
				free_ln = YES;
		
				list_for_each( if_pos, &if_list ) {
				
					batman_if = list_entry( if_pos, struct batman_if, list );
				
					
					if ( orig_node->link_node->lndev[ batman_if->if_num ].rq_sqr.vcnt > 0 ) {
						free_ln = NO;
						break;
					}
				
					if ( orig_node->link_node->lndev[ batman_if->if_num ].rtq_sqr.vcnt > 0 ) {
						free_ln = NO;
						break;
					}
				
				}
			
				if ( free_ln )
					free_link_node( orig_node );
			
			}
					

			
			/* purge outdated PrimaryInterFace NeighBor Identifier */
			if ( orig_node->id4him > 0  &&  orig_node->last_link + PURGE_TIMEOUT < curr_time  )
				free_pifnb_node( orig_node );
			
			
			
			/* purge outdated neighbor nodes, except our best-ranking neighbor */
			
			prev_list_head = (struct list_head *)&orig_node->neigh_list;

			/* for all neighbours towards this originator ... */
			list_for_each_safe( neigh_pos, neigh_temp, &orig_node->neigh_list ) {

				neigh_node = list_entry( neigh_pos, struct neigh_node, list );

				if (  neigh_node->last_aware + PURGE_TIMEOUT < curr_time  &&  orig_node->router != neigh_node  ) {

					addr_to_string( orig_node->orig, orig_str, ADDR_STR_LEN );
					addr_to_string( neigh_node->addr, neigh_str, ADDR_STR_LEN );
					debug_output( 4, "Neighbour timeout: originator %s, neighbour: %s, last_aware %u \n", orig_str, neigh_str, neigh_node->last_aware );
					
					list_del( prev_list_head, neigh_pos, &orig_node->neigh_list );
					
					free_neigh_node( neigh_node );

				} else {
					
					prev_list_head = &neigh_node->list;

				}

			}

		}

	}

	
	/* purge outdated gateways */

	prev_list_head = (struct list_head *)&gw_list;

	list_for_each_safe( gw_pos, gw_pos_tmp, &gw_list ) {

		gw_node = list_entry(gw_pos, struct gw_node, list);

		if ( gw_node->deleted ) {
			
			if( gw_node->orig_node != NULL && gw_node->orig_node->gw_msg != NULL ) {
				
				debugFree( gw_node->orig_node->gw_msg, 1123 );
				gw_node->orig_node->gw_msg = NULL;
				
			}
			
			if( gw_node == curr_gateway )
				del_default_route();

			list_del( prev_list_head, gw_pos, &gw_list );
			debugFree( gw_pos, 1405 );

		} else {

			prev_list_head = &gw_node->list;

		}

	}

	prof_stop( PROF_purge_originator );

}







void update_primary_orig( struct orig_node *orig_node, struct msg_buff *mb ) {
	static char orig_str[ADDR_STR_LEN], prev_pip_str[ADDR_STR_LEN], new_pip_str[ADDR_STR_LEN];
	
	addr_to_string( orig_node->orig, orig_str, sizeof(orig_str) );
	
	
	if ( mb->pip_array != NULL ) {
		
		if ( orig_node->primary_orig_node != NULL ) { 
			
			if ( orig_node->primary_orig_node->orig != (mb->pip_array)->EXT_PIP_FIELD_ADDR ) { 
				
				addr_to_string( orig_node->primary_orig_node->orig, prev_pip_str, sizeof(prev_pip_str) );
				addr_to_string( (mb->pip_array)->EXT_PIP_FIELD_ADDR, new_pip_str, sizeof(new_pip_str) );

				debug_output( 0, "WARNING: neighbor %s changed his primary interface from %s to %s !!!!!!!! \n", orig_str, prev_pip_str, new_pip_str );
				
				if ( orig_node->primary_orig_node->id4him != 0 )
					free_pifnb_node( orig_node->primary_orig_node );
				
				orig_node->primary_orig_node = get_orig_node( (mb->pip_array)->EXT_PIP_FIELD_ADDR );
			
			}
			
		} else {
		
			orig_node->primary_orig_node = get_orig_node( (mb->pip_array)->EXT_PIP_FIELD_ADDR );
			
		}
		
	} else {
		
		if ( orig_node->primary_orig_node != NULL ) { 
			
			if ( orig_node->primary_orig_node->orig != orig_node->orig ) { 
				
				addr_to_string( orig_node->primary_orig_node->orig, prev_pip_str, sizeof(prev_pip_str) );
				
				debug_output( 0, "WARNING: neighbor %s changed primary interface from %s to %s !!!!!!!! \n", orig_str, prev_pip_str, orig_str );
				
				if ( orig_node->primary_orig_node->id4him != 0 )
					free_pifnb_node( orig_node->primary_orig_node );
				
				orig_node->primary_orig_node = orig_node;
			
			}
		
		} else {
			
			orig_node->primary_orig_node = orig_node;
		
		}
		
	}
		
	orig_node->primary_orig_node->last_aware = batman_time;

	
}

void set_lq_bits( struct link_node *ln, SQ_TYPE in_seqno, struct batman_if *this_if, uint8_t direct_undupl_neigh_ogm ) {
//	uint8_t is_new_lq_seqno = 0;
	SQ_TYPE new_lq_seqno;
	int i;
	
	if ( ln != NULL ) {
		
		for( i=0; i < found_ifs; i++ ) {
			
			new_lq_seqno = update_bits( (direct_undupl_neigh_ogm && this_if->if_num==i)?((0x01)<<(OGM_BITS_SIZE-1)):0, in_seqno,
						    &(ln->lndev[i].rq_sqr), ln->last_rq_sqn, 1, my_lws,
						    DBGL_ALL );
			
			if ( new_lq_seqno != in_seqno )
				debug_output(DBGL_SYSTEM, "ERROR - set_lq_bits() called with old in_seqno %d != new_lq_seano %d  !\n",
					    in_seqno, new_lq_seqno );

			
		}
		
		ln->last_rq_sqn = in_seqno;
		
	}
	
	return;
}



void update_link( struct orig_node *orig_node, SQ_TYPE in_seqno, struct batman_if *this_if, uint8_t direct_undupl_neigh_ogm, uint8_t link_flags ) {
	static char orig_str[ADDR_STR_LEN];
					
	if( direct_undupl_neigh_ogm ) {

		if ( orig_node->primary_orig_node->id4him == 0 )
			init_pifnb_node( orig_node->primary_orig_node );

		orig_node->primary_orig_node->last_link = batman_time;

		if (  orig_node->link_node == NULL )
			init_link_node( orig_node, in_seqno );
		
		if ( orig_node->link_node->link_flags != link_flags ) {
			
			addr_to_string( orig_node->orig, orig_str, sizeof(orig_str) );

			debug_output( 0, "INFO: neighbor %s changed link flags from %X to %X \n", orig_str, orig_node->link_node->link_flags, link_flags );
			
			
			if ( (link_flags & UNICAST_PROBES_CAP) &&  !(orig_node->link_node->link_flags & UNICAST_PROBES_CAP) ) {
				
				init_link_probes( orig_node->link_node );
				
			} else if (  !(link_flags & UNICAST_PROBES_CAP)  &&  (orig_node->link_node->link_flags & UNICAST_PROBES_CAP)  ) {
				
				stop_link_probes( orig_node->link_node );
				
			}
			

		}
	
	}
	
	set_lq_bits( orig_node->link_node, in_seqno, this_if, direct_undupl_neigh_ogm );
	
}


int tq_rate( struct orig_node *orig_neigh_node, struct batman_if *if_incoming, int range ) {
	
	int rtq, rq, tq;
	
	if ( orig_neigh_node->link_node == NULL )
		return 0;
	
	rtq = orig_neigh_node->link_node->lndev[ if_incoming->if_num ].rtq_sqr.vcnt;
	
	rq = orig_neigh_node->link_node->lndev[ if_incoming->if_num ].rq_sqr.vcnt;
	
	if ( rtq <= 0 || rq <= 0 ) return 0;
	
	tq = ( (range * rtq ) / rq );
	
	return ( (tq >= ( range )) ? ( range ) : tq );
	
}


int tq_power( int tq_rate_value, int range ) {
	
	int tq_power_value = range;
	int exp_counter;
	for ( exp_counter = 0; exp_counter < asymmetric_exp; exp_counter++ )
		tq_power_value = ((tq_power_value * tq_rate_value) / range);

	return tq_power_value;

}
			




int alreadyConsidered( struct orig_node *orig_node, SQ_TYPE seqno, uint32_t neigh, struct batman_if *if_incoming ) {

	struct list_head *neigh_pos;
	struct neigh_node *neigh_node;

	list_for_each( neigh_pos, &orig_node->neigh_list ) {

		neigh_node = list_entry( neigh_pos, struct neigh_node, list );

		
		if ( neigh == neigh_node->addr && if_incoming == neigh_node->if_incoming ) {
			
			neigh_node->last_aware = batman_time;

			if ( seqno == neigh_node->last_considered_seqno ) { 
				
				return YES;
				
			} else if ( ( seqno - neigh_node->last_considered_seqno ) > ( FULL_SEQ_RANGE - orig_node->pws ) ) {

				debug_output( 0, "alreadyConsidered(): This should not happen, we only acceppt current packets anyway !!!!!!!\n");
				return YES;	
				
			} else {
		
				neigh_node->last_considered_seqno = seqno;
				return NO;
			}
						
		}
		
	}

	neigh_node = init_neigh_node( orig_node, neigh, if_incoming, seqno, batman_time );

	return NO;
}

struct neigh_node *get_neigh_node( struct orig_node *orig_node, uint32_t neigh, struct batman_if *if_incoming ) {

	struct list_head *neigh_pos;
	struct neigh_node *nn;

	list_for_each( neigh_pos, &orig_node->neigh_list ) {

		nn = list_entry( neigh_pos, struct neigh_node, list );
		
		if ( neigh == nn->addr  &&  if_incoming == nn->if_incoming )
			return nn;
		
	}

	return NULL;
}



void debug_orig( int dbgl, int sock ) {

	struct hash_it_t *hashit = NULL;
	struct list_head *orig_pos, *neigh_pos;
	struct orig_node *orig_node;
	struct neigh_node *neigh_node;
	struct batman_if *neigh_node_if;
	struct gw_node *gw_node;
	uint16_t batman_count = 0;
	uint32_t uptime_sec;
	int download_speed, upload_speed;
	static char str[ADDR_STR_LEN], str2[ADDR_STR_LEN], orig_str[ADDR_STR_LEN];
	int dbg_ogm_out = 0, dbg_ogm_out2 = 0, rq, tq, rtq;
	static char dbg_ogm_str[MAX_DBG_STR_SIZE + 1], dbg_ogm_str2[MAX_DBG_STR_SIZE + 1]; // TBD: must be checked for overflow when using with sprintf
	uint8_t /*debug_neighbor = NO,*/ blocked;
	uint16_t hna_count = 0, srv_count = 0;
	struct hna_key key;
	struct hna_hash_node *hash_node;

	struct link_node *ln;
	struct list_head *link_pos;

	if ( dbgl == DBGL_ALL ) {

		dprintf( sock, "------------------ DEBUG ------------------ \n" );
		
		debug_send_list( sock );
		
		dprintf( sock, "\n" );

	}
	

	addr_to_string( ((struct batman_if *)if_list.next)->addr.sin_addr.s_addr, orig_str, sizeof(orig_str) );
	uptime_sec = get_time_sec();

	if ( dbgl == DBGL_ROUTES )
		dprintf( sock, "  %-11s brc %15s [%10s]: %20s ... [BatMan-eXp %s%s, MainIF/IP: %s/%s, UT: %id%2ih%2im] ATTENTION: detailed output with -d %d\n", "Originator", "Nexthop", "outgoingIF", "Potential nexthops", SOURCE_VERSION, ( strncmp( REVISION_VERSION, "0", 1 ) != 0 ? REVISION_VERSION : "" ), ((struct batman_if *)if_list.next)->dev, orig_str, uptime_sec/86400, ((uptime_sec%86400)/3600), ((uptime_sec)%3600)/60 , DBGL_DETAILS);
	
	
	if ( dbgl == DBGL_DETAILS  || dbgl == DBGL_NEIGHBORS ||  dbgl == DBGL_ALL ) {
		
		dprintf( sock, "BatMan-eXp %s%s, IF %s %s, LinkWindowSize %i, PathWindSize %i, OGI %ims, currSeqno %d, UT %i:%i%i:%i%i:%i%i, CPU %d/1000 \n",
		SOURCE_VERSION, ( strncmp( REVISION_VERSION, "0", 1 ) != 0 ? REVISION_VERSION : "" ), 
		((struct batman_if *)if_list.next)->dev, orig_str, my_lws, my_pws, my_ogi, 
		(list_entry( (&if_list)->next, struct batman_if, list ))->out.seqno,
					((uptime_sec)/86400), 
				(((uptime_sec)%86400)/36000)%10,
				(((uptime_sec)%86400)/3600)%10,
				(((uptime_sec)%3600)/600)%10,
				(((uptime_sec)%3600)/60)%10,
				(((uptime_sec)%60)/10)%10,
				(((uptime_sec)%60))%10,
				s_curr_avg_cpu_load
			);
	}
	
	if ( dbgl == DBGL_DETAILS  ||  dbgl == DBGL_ALL ) {
		
		dprintf( sock,   "Neighbor        outgoingIF     bestNextHop brc (~rcvd  knownSince  lseq lvld rid nid ) [     viaIF RTQ  RQ  TQ]..\n");
	
		list_for_each( link_pos, &link_list ) {

			ln = list_entry(link_pos, struct link_node, list);
		
			orig_node = ln->orig_node;
		
			if ( orig_node->router == NULL )
				continue;

			struct orig_node *onn = get_orig_node( orig_node->router->addr );
			int estimated_rcvd = ((( 10000 * orig_node->router->accepted_sqr.vcnt ) / orig_node->pws )+99) / 
					(((tq_power(tq_rate( onn, onn->router->if_incoming, my_lws ), my_lws)*100)/my_lws)+1);
			
			addr_to_string( orig_node->orig, str, sizeof (str) );
			addr_to_string( orig_node->router->addr, str2, sizeof (str2) );
			dbg_ogm_out = snprintf( dbg_ogm_str, MAX_DBG_STR_SIZE, "%-15s %-10s %15s %3i (  %3i %2i:%i%i:%i%i:%i%i %5i %4i %3d %3d )",
					str, orig_node->router->if_incoming->dev, str2,
					(100 * orig_node->router->accepted_sqr.vcnt) / orig_node->pws, /* accpted and rebroadcasted */
				//	(100 * orig_node->router->vld_sqr.vcnt ) / orig_node->pws, /* all rcvd*/
					estimated_rcvd > 100 ? 100 : estimated_rcvd,
					((uptime_sec-(orig_node->first_valid_sec))/86400), 
					(((uptime_sec-(orig_node->first_valid_sec))%86400)/36000)%10,
					(((uptime_sec-(orig_node->first_valid_sec))%86400)/3600)%10,
					(((uptime_sec-(orig_node->first_valid_sec))%3600)/600)%10,
					(((uptime_sec-(orig_node->first_valid_sec))%3600)/60)%10,
					(((uptime_sec-(orig_node->first_valid_sec))%60)/10)%10,
					(((uptime_sec-(orig_node->first_valid_sec))%60))%10,
					orig_node->last_accepted_sqn,
					( batman_time - orig_node->last_valid)/1000,
					( orig_node->primary_orig_node != NULL ? orig_node->primary_orig_node->id4me : -1 ),
					( orig_node->primary_orig_node != NULL ? orig_node->primary_orig_node->id4him : -1 )
					); 
					
			list_for_each( neigh_pos, &orig_node->neigh_list ) {
				
				neigh_node = list_entry( neigh_pos, struct neigh_node, list );

				if( neigh_node->addr == orig_node->orig ) {
					
					neigh_node_if = neigh_node->if_incoming;
				
					rq = ln->lndev[ neigh_node_if->if_num ].rq_sqr.vcnt;
					tq = tq_rate( orig_node, neigh_node_if, my_lws );
					rtq = ln->lndev[neigh_node_if->if_num].rtq_sqr.vcnt;

					dbg_ogm_out = dbg_ogm_out + snprintf( (dbg_ogm_str + dbg_ogm_out), (MAX_DBG_STR_SIZE - dbg_ogm_out), 
							" [%10s %3i %3i %3i] ",	neigh_node->if_incoming->dev, 
							((100*rtq)/my_lws), ((100*rq)/my_lws), ((100*tq)/my_lws) );

				}
			
			}
		
			if ( dbgl == DBGL_DETAILS )
				dprintf( sock,   "%s \n", dbg_ogm_str );
			
			
		}
		
		dprintf( sock,   "\n");
		
	}
			
		
	if ( dbgl == DBGL_NEIGHBORS  ||  dbgl == DBGL_ALL ) {
		
		dprintf( sock,   "Neighbor        ( knownSince   lseq lvld ) [     viaIF RTQ  RQ  TQ]  lastProbe weightAvg conservAvg windowAvg        lvld \n");
	
		list_for_each( link_pos, &link_list ) {

			ln = list_entry(link_pos, struct link_node, list);
		
			orig_node = ln->orig_node;
		
			if ( orig_node->router == NULL )
				continue;

			
			addr_to_string( orig_node->orig, str, sizeof (str) );
			addr_to_string( orig_node->router->addr, str2, sizeof (str2) );
			dbg_ogm_out = snprintf( dbg_ogm_str, MAX_DBG_STR_SIZE, "%-15s ( %2i:%i%i:%i%i:%i%i %5i %4i )",
					str,
					((uptime_sec-(orig_node->first_valid_sec))/86400), 
					(((uptime_sec-(orig_node->first_valid_sec))%86400)/36000)%10,
					(((uptime_sec-(orig_node->first_valid_sec))%86400)/3600)%10,
					(((uptime_sec-(orig_node->first_valid_sec))%3600)/600)%10,
					(((uptime_sec-(orig_node->first_valid_sec))%3600)/60)%10,
					(((uptime_sec-(orig_node->first_valid_sec))%60)/10)%10,
					(((uptime_sec-(orig_node->first_valid_sec))%60))%10,
					orig_node->last_accepted_sqn,
					( batman_time - orig_node->last_valid)/1000
					); 
					
			list_for_each( neigh_pos, &orig_node->neigh_list ) {
				neigh_node = list_entry( neigh_pos, struct neigh_node, list );

				if( neigh_node->addr == orig_node->orig ) {
					
					neigh_node_if = neigh_node->if_incoming;
				
					rq = ln->lndev[ neigh_node_if->if_num ].rq_sqr.vcnt;
					tq = tq_rate( orig_node, neigh_node_if, my_lws );
					rtq = ln->lndev[neigh_node_if->if_num].rtq_sqr.vcnt;

					dbg_ogm_out = dbg_ogm_out + snprintf( (dbg_ogm_str + dbg_ogm_out), (MAX_DBG_STR_SIZE - dbg_ogm_out), 
							" [%10s %3i %3i %3i] ",	neigh_node->if_incoming->dev, 
							((100*rtq)/my_lws), ((100*rq)/my_lws), ((100*tq)/my_lws) );

				}
			
			}
				
			dprintf( sock, "%s \n", dbg_ogm_str );
			
			dbg_ogm_out = 0;
			
			if ( ln->link_flags & UNICAST_PROBES_CAP ) {
		
				list_for_each( neigh_pos, &orig_node->neigh_list ) {
				
					neigh_node = list_entry( neigh_pos, struct neigh_node, list );

					if( neigh_node->addr == orig_node->orig ) {
						
						neigh_node_if = neigh_node->if_incoming;
					
	
						struct link_node_dev *lndev = &(ln->lndev[ neigh_node_if->if_num ]);

						
						dbg_ogm_out = dbg_ogm_out + snprintf( (dbg_ogm_str + dbg_ogm_out), (MAX_DBG_STR_SIZE - dbg_ogm_out), 
								" %10s                 %7.3f   %7.3f    %7.3f   %7.3f Mbps  %5d",
							neigh_node->if_incoming->dev, 
							(float)lndev->last_probe_tp/1000,
							(float)lndev->sum_probe_tp/PROBE_HISTORY/1000,
							(float)lndev->conservative_probe_tp/PROBE_HISTORY/1000,
							((float)(global_mt->t[ lndev->up_sqr.vcnt * (MAX_BITS_RANGE / unicast_probes_ws) ]))/1000/1000,
							( batman_time - lndev->last_complete_probe_stamp)/1000
							);
	
						dprintf( sock, "                                           %s \n", dbg_ogm_str);
						dbg_ogm_out = 0;

						
					}
			
				}
				

			}
			
		}
		
		dprintf( sock,   "\n");
		
	}
	
	
	
	if ( dbgl == DBGL_DETAILS  ||  dbgl == DBGL_ALL ) {
		dprintf( sock, "Originator      outgoingIF     bestNextHop brc (~rcvd  knownSince  lseq lvld pws  ogi cpu hop change ) alternativeNextHops brc ...\n");
	}
	
	int nodes_count = 0, sum_packet_count = 0, sum_rcvd_all_bits = 0, sum_lvld = 0, sum_last_nbrf = 0, sum_esitmated_ten_ogis = 0, sum_reserved_something = 0, sum_route_changes = 0, sum_hops = 0;
	
	
	while ( orig_hash  &&  (hashit = hash_iterate( orig_hash, hashit )) ) {

		orig_node = hashit->bucket->data;

		if ( orig_node->router == NULL )
			continue;
		
		if ( orig_node->primary_orig_node != orig_node )
			continue;
		
		nodes_count++;
		batman_count++;

		addr_to_string( orig_node->orig, str, sizeof (str) );
		addr_to_string( orig_node->router->addr, str2, sizeof (str2) );
		
		if( dbgl == DBGL_DETAILS || dbgl == DBGL_ALL ) {
			
			struct orig_node *onn = get_orig_node( orig_node->router->addr );
			int estimated_rcvd = ((( 10000 * orig_node->router->accepted_sqr.vcnt ) / orig_node->pws )+99) / 
					(((tq_power(tq_rate( onn, onn->router->if_incoming, my_lws ), my_lws)*100)/my_lws)+1);
			
			dbg_ogm_out = snprintf( dbg_ogm_str, MAX_DBG_STR_SIZE, "%-15s %-10s %15s %3i (  %3i %2i:%i%i:%i%i:%i%i %5i %4i %3i %4i %3i %3i %6i )", 
				str, orig_node->router->if_incoming->dev, str2,
				(( 100 * orig_node->router->accepted_sqr.vcnt ) / orig_node->pws ) /*accpeted and rebroadcasted*/,
			//	(( 100 * orig_node->router->vld_sqr.vcnt) / orig_node->pws ) /* all rcvd*/,
				estimated_rcvd > 100 ? 100 : estimated_rcvd,
				((uptime_sec-(orig_node->first_valid_sec))/86400), 
				(((uptime_sec-(orig_node->first_valid_sec))%86400)/36000)%10,
				(((uptime_sec-(orig_node->first_valid_sec))%86400)/3600)%10,
				(((uptime_sec-(orig_node->first_valid_sec))%3600)/600)%10,
				(((uptime_sec-(orig_node->first_valid_sec))%3600)/60)%10,
				(((uptime_sec-(orig_node->first_valid_sec))%60)/10)%10,
				(((uptime_sec-(orig_node->first_valid_sec))%60))%10,
				orig_node->last_accepted_sqn,
				( batman_time - orig_node->last_valid)/1000,
				orig_node->pws,
				(orig_node->ca10ogis / 10),
					orig_node->last_reserved_someting,
				(DEFAULT_TTL+1 - orig_node->last_path_ttl),
				orig_node->rt_changes
						); 
				
			sum_packet_count+=  (100 * orig_node->router->accepted_sqr.vcnt) / orig_node->pws; /* accepted */
			//sum_rcvd_all_bits+= (100 * orig_node->router->vld_sqr.vcnt) / orig_node->pws; /* all rcvd*/ 
			sum_rcvd_all_bits+= estimated_rcvd > 100 ? 100 : estimated_rcvd; 
			sum_lvld+= (batman_time - orig_node->last_valid)/1000;
			sum_last_nbrf+= orig_node->pws;
			sum_esitmated_ten_ogis+= orig_node->ca10ogis;
			sum_reserved_something+= orig_node->last_reserved_someting;
			sum_route_changes+= orig_node->rt_changes;
			sum_hops+= (DEFAULT_TTL+1 - orig_node->last_path_ttl);

			list_for_each( neigh_pos, &orig_node->neigh_list ) {
				neigh_node = list_entry( neigh_pos, struct neigh_node, list );

				if( neigh_node->addr != orig_node->router->addr ) {
				
					addr_to_string( neigh_node->addr, str, sizeof (str) );

					dbg_ogm_out = dbg_ogm_out + snprintf( (dbg_ogm_str + dbg_ogm_out), (MAX_DBG_STR_SIZE - dbg_ogm_out), " %15s %3i", str, 
					/* neigh_node->packet_count */ 
					(100 * neigh_node->accepted_sqr.vcnt) / orig_node->pws  /* accpted and and not rebroadcasted */ );
			
				}
			}

			dprintf( sock, "%s \n", dbg_ogm_str );
		
		}
		
		if ( dbgl == DBGL_ROUTES ) {
			
			dbg_ogm_out2 = snprintf( dbg_ogm_str2, MAX_DBG_STR_SIZE, "%-15s (%3i) %15s [%10s]:", 
					str, ((100*orig_node->router->accepted_sqr.vcnt)/orig_node->pws), str2, orig_node->router->if_incoming->dev );
			
			list_for_each( neigh_pos, &orig_node->neigh_list ) {
				neigh_node = list_entry( neigh_pos, struct neigh_node, list );

				if( neigh_node->addr != orig_node->router->addr ) {
				
					addr_to_string( neigh_node->addr, str, sizeof (str) );

					dbg_ogm_out2 = dbg_ogm_out2 + snprintf( (dbg_ogm_str2 + dbg_ogm_out2), (MAX_DBG_STR_SIZE - dbg_ogm_out2), " %15s (%3i)", str, ((100*neigh_node->accepted_sqr.vcnt)/orig_node->pws) );
			
				}
			}

			dprintf( sock, "%s \n", dbg_ogm_str2 );
		}

	}
	
	if ( dbgl == DBGL_DETAILS  ||  dbgl == DBGL_ALL ) {
		
		dbg_ogm_out = snprintf( dbg_ogm_str, MAX_DBG_STR_SIZE, "%4d %-37s %3i (  %3i                   %4i %3i %4i %3i %3i %6d )", 
					nodes_count, "known Originator(s), averages: ", 
					(nodes_count > 0 ? ( sum_packet_count / nodes_count ) : -1 ), 
					(nodes_count > 0 ? ( sum_rcvd_all_bits / nodes_count ) : -1 ), 
					(nodes_count > 0 ? ( sum_lvld / nodes_count ) : -1),
					(nodes_count > 0 ? ( sum_last_nbrf / nodes_count ) : -1 ), 
					(nodes_count > 0 ? ((sum_esitmated_ten_ogis / 10) / nodes_count ) : -1), 
					(nodes_count > 0 ? ( sum_reserved_something / nodes_count ) : -1),
					(nodes_count > 0 ? ( sum_hops / nodes_count ) : -1),
					(nodes_count > 0 ? ( sum_route_changes / nodes_count ) : -1)      ); 
		
		dprintf( sock, "%s \n", dbg_ogm_str );
	}
	
	if ( dbgl == DBGL_ALL )
		dprintf( sock, "\n" );

	if ( dbgl == DBGL_HNAS  ||  dbgl == DBGL_ALL ) {
		
		dprintf( sock, "Originator      Announced networks HNAs:  network/netmask or interface/IF (B:blocked)...\n");
	
		while ( orig_hash  &&  (hashit = hash_iterate( orig_hash, hashit )) ) {

			orig_node = hashit->bucket->data;

			if ( orig_node->router == NULL || orig_node->hna_array_len == 0)
				continue;

			addr_to_string( orig_node->orig, str, sizeof (str) );
			dbg_ogm_out = snprintf( dbg_ogm_str, MAX_DBG_STR_SIZE, "%-15s", str ); 
				
			hna_count = 0;
			
			while ( hna_count < orig_node->hna_array_len ) {


				key.addr     = orig_node->hna_array[hna_count].EXT_HNA_FIELD_ADDR;
				key.KEY_FIELD_ANETMASK = orig_node->hna_array[hna_count].EXT_HNA_FIELD_NETMASK;
				key.KEY_FIELD_ATYPE    = orig_node->hna_array[hna_count].EXT_HNA_FIELD_TYPE;

				
				addr_to_string( key.addr, str, sizeof (str) );
						
				// check if HNA was blocked
				hash_node = get_hna_node( &key );
				
				if ( hash_node->status == HNA_HASH_NODE_OTHER && hash_node->orig == orig_node )
					blocked = NO;
				else
					blocked = YES;


				if ( key.KEY_FIELD_ATYPE == A_TYPE_NETWORK )
					dbg_ogm_out = dbg_ogm_out + snprintf( (dbg_ogm_str + dbg_ogm_out), (MAX_DBG_STR_SIZE - dbg_ogm_out), " %15s/%2d %c ", 
						str, key.KEY_FIELD_ANETMASK, (blocked?'B':' ') );
				else if ( key.KEY_FIELD_ATYPE == A_TYPE_INTERFACE )
					dbg_ogm_out = dbg_ogm_out + snprintf( (dbg_ogm_str + dbg_ogm_out), (MAX_DBG_STR_SIZE - dbg_ogm_out), " %15s/IF %c ", 
						str, (blocked?'B':' ') );

				hna_count++;

			}

			dprintf( sock, "%s \n", dbg_ogm_str );

		}			
	}
	
	if ( dbgl == DBGL_ALL )
		dprintf( sock, "\n" );
	
	if ( dbgl == DBGL_SERVICES  ||  dbgl == DBGL_ALL ) {
		
		dprintf( sock, "Originator      Announced services ip:port:seqno ...\n");
	
		while ( orig_hash  &&  (hashit = hash_iterate( orig_hash, hashit )) ) {

			orig_node = hashit->bucket->data;

			if ( orig_node->router == NULL || orig_node->srv_array_len == 0)
				continue;

			addr_to_string( orig_node->orig, str, sizeof (str) );
			dbg_ogm_out = snprintf( dbg_ogm_str, MAX_DBG_STR_SIZE, "%-15s", str ); 
				
			srv_count = 0;
			
			while ( srv_count < orig_node->srv_array_len ) {

				addr_to_string( orig_node->srv_array[srv_count].EXT_SRV_FIELD_ADDR, str, sizeof (str) );

				dbg_ogm_out = dbg_ogm_out + snprintf( (dbg_ogm_str + dbg_ogm_out), (MAX_DBG_STR_SIZE - dbg_ogm_out), " %15s:%d:%d", 
						str, ntohs( orig_node->srv_array[srv_count].EXT_SRV_FIELD_PORT ), orig_node->srv_array[srv_count].EXT_SRV_FIELD_SEQNO );

				srv_count++;

			}

			dprintf( sock, "%s \n", dbg_ogm_str );

		}			

	}		

	
	if ( batman_count == 0 )
		dprintf( sock, "No batman nodes in range ... \n" );
	
	
	if ( dbgl == DBGL_ALL )
		dprintf( sock, "\n" );

	
	if ( dbgl == DBGL_GATEWAYS  ||  dbgl == DBGL_ALL ) {

		if ( list_empty( &gw_list ) ) {

			dprintf( sock, "No gateways in range ... \n" );

		} else {

			dprintf( sock, "%12s     %15s   #  \n", "Originator", "bestNextHop" );  

			list_for_each( orig_pos, &gw_list ) {

				gw_node = list_entry( orig_pos, struct gw_node, list );

				if ( gw_node->deleted || gw_node->orig_node->gw_msg == NULL || gw_node->orig_node->router == NULL )
					continue;

				addr_to_string( gw_node->orig_node->orig, str, sizeof (str) );
				addr_to_string( gw_node->orig_node->router->addr, str2, sizeof (str2) );
				
				get_gw_speeds( gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWFLAGS, &download_speed, &upload_speed );
				
				dprintf( sock, "%s %-15s %15s %3i, gw_class %2i - %i%s/%i%s, reliability: %i, supported tunnel types %s, %s \n",
					curr_gateway == gw_node ? "=>" : "  ", str, str2,
					(100 * gw_node->orig_node->router->accepted_sqr.vcnt) / gw_node->orig_node->pws,
					gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWFLAGS,
					download_speed > 2048 ? download_speed / 1024 : download_speed,
					download_speed > 2048 ? "MBit" : "KBit",
					upload_speed > 2048 ? upload_speed / 1024 : upload_speed,
					upload_speed > 2048 ? "MBit" : "KBit",
					gw_node->unavail_factor,
					(gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWTYPES & TWO_WAY_TUNNEL_FLAG)?"2WT":"-",
					(gw_node->orig_node->gw_msg->EXT_GW_FIELD_GWTYPES & ONE_WAY_TUNNEL_FLAG)?"1WT":"-" );
				
				batman_count++;

			}

			if ( batman_count == 0 )
				debug_output( DBGL_GATEWAYS, "No gateways in range ... \n" );

		}

	}

	
	if ( dbgl == DBGL_ALL )
		dprintf( sock, "---------------------------------------------- END DEBUG \n" );

}


