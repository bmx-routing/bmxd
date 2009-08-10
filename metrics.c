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


#include <stdio.h>
#include <string.h>

#include "batman.h"
#include "os.h"
#include "originator.h"
#include "metrics.h"


void flush_sq_record( struct sq_record *sqr ) {
	
	sqr->wa_val = sqr->wa_unscaled = sqr->wa_clr_sqn = sqr->wa_clr_sqn = 0;
	
	memset( sqr->sqn_entry_queue, 0, SQN_LOUNGE_SIZE );
}


//returns seqno tip of exit queue
static void push_sqn_lounge_queue( uint8_t probe, uint8_t lounge_size, SQ_TYPE seqno, 
                            struct sq_record *sqr, uint8_t ws,
                            uint8_t *exit_queue, uint8_t *exit_queue_len, SQ_TYPE *exit_queue_tip, 
                            uint32_t orig, uint32_t neigh, struct batman_if *bif, char *who )
{

	uint8_t pos = seqno % (SQN_LOUNGE_SIZE);
	
	dbgf_ext( DBGT_INFO, "probe %d, SQN %d, exitQueueTip %d, lounge_size %d, wa_val_old %d ws %d",
	          probe, seqno, sqr->sqn_entry_queue_tip, lounge_size, sqr->wa_val, ws );
	
	if ( seqno == sqr->sqn_entry_queue_tip ) { 
		
#ifndef NOPARANOIA
		if ( probe  &&  sqr->sqn_entry_queue[pos] ) {
			dbgf( DBGL_SYS, DBGT_ERR,
			      "%s  OG %16s  NB %16s  IF %s probe[%d]=%d but entryQueue[pos:%d]=%d already marked!",
			      who, ipStr(orig), ipStr(neigh), bif->dev, 
			      seqno, probe, pos, sqr->sqn_entry_queue[pos] );
		}
#endif		
		if ( !sqr->sqn_entry_queue[pos] )
			sqr->sqn_entry_queue[pos] = probe;
		
		*exit_queue_len = 0;
		*exit_queue_tip = sqr->sqn_entry_queue_tip - lounge_size;
		
		dbgf_ext( DBGT_INFO, "MAINSTREAM (SQN equal to entry_queue_tip) wa_val_new %d, exitQueueLen %d, exitQueue[tip:%d] %d",
		         sqr->wa_val, *exit_queue_len, *exit_queue_tip, exit_queue[(*exit_queue_tip)%SQN_LOUNGE_SIZE]);
		
		
		
	} else if ( ((SQ_TYPE)( seqno - sqr->sqn_entry_queue_tip )) > MAX_SEQNO - lounge_size ) {  //impossible for lounge_size==0
		
#ifndef NOPARANOIA
		if ( probe  &&  sqr->sqn_entry_queue[pos] ) {
			dbgf( DBGL_SYS, DBGT_ERR,
			      "%s  OG %16s  NB %16s  IF %s probe[%d]=%d but entryQueue[pos:%d]=%d already marked! tip %d",
			      who, ipStr(orig), ipStr(neigh), bif->dev, 
			      seqno, probe, pos, sqr->sqn_entry_queue[pos], sqr->sqn_entry_queue_tip);
		}
#endif
		if ( !sqr->sqn_entry_queue[pos] )
			sqr->sqn_entry_queue[pos] = probe;
		
		*exit_queue_len = 0;
		
		*exit_queue_tip = sqr->sqn_entry_queue_tip - lounge_size;
		
		dbgf_ext( DBGT_INFO, "ACCEPTABLE (SQN within entry-queue-boundaries) wa_val_new %d, exitQueueLen %d, exitQueue[tip:%d] %d",
		         sqr->wa_val, *exit_queue_len, *exit_queue_tip, exit_queue[(*exit_queue_tip)%SQN_LOUNGE_SIZE]);
		
		
	} else if ( ((SQ_TYPE)( seqno - sqr->sqn_entry_queue_tip )) <= lounge_size ) {  //impossible for lounge_size==0
		// seqno == sqr->sqn_entry_queue_tip has already been catched above
		
		SQ_TYPE i;
		uint8_t len = 0;
		
		
		for( i = sqr->sqn_entry_queue_tip+1-lounge_size; i != ((SQ_TYPE)(seqno+1-lounge_size)); i++ ) {
			len++;
			exit_queue[i%SQN_LOUNGE_SIZE] = sqr->sqn_entry_queue[i%SQN_LOUNGE_SIZE];
		}
		
		for( i = sqr->sqn_entry_queue_tip+1 ; i != ((SQ_TYPE)(seqno+1)); i++ )
			sqr->sqn_entry_queue[i%SQN_LOUNGE_SIZE] = 0;
		
		sqr->sqn_entry_queue[pos] = probe;
		sqr->sqn_entry_queue_tip = seqno;
		
		*exit_queue_len = len;
		*exit_queue_tip = sqr->sqn_entry_queue_tip - lounge_size;
		
		dbgf_ext( DBGT_INFO, "AVANTGARDE (SQN redefining entry-queue-boundaries) wa_val_new %d, exitQueueLen %d, exitQueue[tip:%d] %d",
		         sqr->wa_val, *exit_queue_len, *exit_queue_tip, exit_queue[(*exit_queue_tip)%SQN_LOUNGE_SIZE]);
		
		
		
	} else if ( ((SQ_TYPE)( seqno - sqr->sqn_entry_queue_tip )) <= ws + lounge_size ) {
		// seqno - sqr->sqn_entry_queue_tip <= lounge_size has already been catched above
		
		SQ_TYPE i, old_entry_queue_tip = sqr->sqn_entry_queue_tip;
		
		for( i = sqr->sqn_entry_queue_tip+1-lounge_size ; i != ((SQ_TYPE)(sqr->sqn_entry_queue_tip+1)); i++ )
			exit_queue[i%SQN_LOUNGE_SIZE] = sqr->sqn_entry_queue[i%SQN_LOUNGE_SIZE];
		
		
		for( i = seqno+1 - lounge_size ; i != ((SQ_TYPE)(seqno+1)); i++ )
			sqr->sqn_entry_queue[i%SQN_LOUNGE_SIZE] = 0;
		
		sqr->sqn_entry_queue[pos] = probe;
		sqr->sqn_entry_queue_tip = seqno;
		
		*exit_queue_len = lounge_size;
		*exit_queue_tip = old_entry_queue_tip;
		
		dbgf_ext( DBGT_INFO, "CRITICAL NEW (partly purging entry-queue) wa_val_new %d, exitQueueLen %d, exitQueue[tip:%d] %d",
		         sqr->wa_val, *exit_queue_len, *exit_queue_tip, exit_queue[(*exit_queue_tip)%SQN_LOUNGE_SIZE]);
		
	} else {
		
		SQ_TYPE i;
		
		for( i = seqno+1 - lounge_size ; i != ((SQ_TYPE)(seqno+1)); i++ )
			sqr->sqn_entry_queue[i%SQN_LOUNGE_SIZE] = 0;
		
		sqr->sqn_entry_queue[pos] = probe;
		sqr->sqn_entry_queue_tip = seqno;
		
		*exit_queue_len = 0;
		*exit_queue_tip = sqr->sqn_entry_queue_tip - lounge_size;
		
		dbgf_ext( DBGT_INFO, "LOST NEW (completely purging entry-queue) wa_val_new %d, exitQueueLen %d, exitQueue[tip:%d] %d",
		         sqr->wa_val, *exit_queue_len, *exit_queue_tip, exit_queue[(*exit_queue_tip)%SQN_LOUNGE_SIZE]);

	}
}



static void update_metric( uint8_t probe, SQ_TYPE sq_upd, struct sq_record *sqr, uint8_t ws ) {

	uint32_t m_weight = ws/2;
	SQ_TYPE offset = sq_upd - sqr->wa_clr_sqn;
	uint32_t old_wa_val = sqr->wa_val;
	
	if ( offset >= ws ) {
		
		if ( old_wa_val ) {
			dbgf_all( DBGT_WARN, "(offset:%d=SQN:%d-clrSQN:%d) > ws:%d  probe %d, old_wa_val %d ",
			offset, sq_upd, sqr->wa_clr_sqn, ws, probe, sqr->wa_val );
		}
		
		sqr->wa_unscaled = 0;
	
	} else {
		
		SQ_TYPE i;
		for ( i=0; i < offset; i++ )
			sqr->wa_unscaled -= ( sqr->wa_unscaled / m_weight );
		
	}
	
	sqr->wa_clr_sqn = sq_upd;
	
	if ( probe  &&  sqr->wa_set_sqn != sq_upd ) {
		
		sqr->wa_unscaled += ( (probe * wa_scale_factor) / m_weight );

		sqr->wa_set_sqn = sq_upd;
	}
	
	sqr->wa_val = sqr->wa_unscaled/wa_scale_factor;
	
	
	dbgf_ext( DBGT_INFO, "probe %d, SQN %d, old_wa_val %d, new_wa_val %d", probe, sq_upd, old_wa_val, sqr->wa_val );
	
}



/*update_queued_metric() MUST deal with unordered SQNs !!!

SQNs of incoming OGM are collected (queued) in a waiting-room/lounge (entry-queue) 
before being further processed (considered for path/link quality calculation).
This way we can reorder lately rcvd OGM-SQNs and process them in the right order.
The maximum acceptable delay (in terms of SQNs) is defined by the lounge_size of each node.

push_sqn_lounge_queue() is responsible to manage the waiting room and return ready-to-process SQN in the exit-queue


*/
void update_queued_metric( uint8_t probe, uint8_t lounge_size, SQ_TYPE seqno, struct sq_record *sqr, uint8_t ws,
                           uint32_t orig, uint32_t neigh, struct batman_if *bif, char* who )
{
	dbgf_ext( DBGT_INFO, " " );
	
	uint8_t old_wa_val;
	old_wa_val = sqr->wa_val;
	
	if ( lounge_size == 0 ) {
		
		//IMPORTANT: update_metric needs ordered SQNs
		update_metric( probe, seqno, sqr, ws );
	
	} else {
	
		uint8_t exit_queue[SQN_LOUNGE_SIZE];
		uint8_t exit_queue_len;
		SQ_TYPE exit_queue_tip;
		
		push_sqn_lounge_queue( probe, lounge_size, seqno, sqr, ws, 
		                       exit_queue, &exit_queue_len, &exit_queue_tip,
		                       orig, neigh, bif, who );
		
		SQ_TYPE i;
		for( i = exit_queue_tip+1-exit_queue_len; i != ((SQ_TYPE)(exit_queue_tip+1)); i++ )
			update_metric( exit_queue[i%SQN_LOUNGE_SIZE], i, sqr, ws );
		
		if ( sqr->sqn_entry_queue_tip == seqno ) { 						// MAINSTREAM, AVANTGARDE, CRITICAL_NEW, or LOST_NEW
			
			if ( exit_queue_len == 0  ||							// MAINSTREAM, ACCEPTABLE, or LOST_NEW
			     ((SQ_TYPE)(sqr->sqn_entry_queue_tip - lounge_size)) != exit_queue_tip )	// CRITICAL_NEW
			{
				update_metric( 0, sqr->sqn_entry_queue_tip - lounge_size, sqr, ws );
			}
		
		}	
	}
	
	//dbgf( ((old_wa_val && !sqr->wa_val) ?  DBGL_CHANGES : DBGL_ALL), ((old_wa_val && !sqr->wa_val) ?  DBGT_WARN : DBGT_INFO),
	dbgf_ext( DBGT_INFO,
	/*if ( !strcmp( who, "process_ogm(own via NB)" ) || !strcmp( who, "schedule_own_ogm()") ) 
	 	dbg( DBGL_CHANGES, DBGT_INFO, */
	          "done! %26s  OG %-15s  via IF %-10s  NB %-10s  probe %3d  lounge_size %2d  SQN %-5d  wa_val old %3d  new %3d",
	          who, ipStr( orig ), bif->dev, ipStr( neigh ), probe, lounge_size, seqno, old_wa_val, sqr->wa_val );
	
	
}


uint32_t get_wavg( uint32_t wavg, uint8_t weight_exp ) {

	return wavg>>weight_exp;
}


uint32_t upd_wavg( uint32_t *wavg, uint32_t probe, uint8_t weight_exp ) {
	
#ifndef NOPARANOIA
	if ( weight_exp > 10 || (weight_exp && probe >= (uint32_t)(0x01<<(32-weight_exp))) )
		dbg( DBGL_SYS, DBGT_ERR, 
		     "probe or weight_exp value to large to calculate weighted average!"
		     "upd_wavg(wavg: %d, probe: %d, weight_exp: %d ) = %d:",
		     *wavg, probe, weight_exp, *wavg>>weight_exp );
#endif
	
	if ( *wavg )
		*wavg += probe - ((*wavg)>>weight_exp);
	else
		*wavg = probe<<weight_exp;
	
	
	return *wavg>>weight_exp;
}
