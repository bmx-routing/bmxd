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
#include <sys/time.h>

#include "batman.h"
#include "os.h"
#include "originator.h"
#include "control.h"
#include "metrics.h"




#ifdef METRICTABLE
struct metric_table *global_mt = NULL;

struct metric_table *init_metric_table( int size, int base_m, int min ) {
	
	struct metric_table *mt = debugMalloc( sizeof( struct metric_table ), 721 );
		
	mt->t_size =  size > MAX_BITS_RANGE ? MAX_BITS_RANGE+1 : size+1 ;
	mt->t_base_m = base_m;
	mt->t_min = min;
	mt->t = debugMalloc( (mt->t_size) * sizeof( uint32_t) , 722 );
	
	double base = ((double)base_m)/1000;
	double rate = mt->t_min;
	int i;
	uint32_t prev = 0;
	
	for ( i=0; i < mt->t_size; i++ ) {
		
		mt->t[i] = ( rate *= base );
		
		if ( prev >= rate ) {
			
			debug_output( DBGL_SYSTEM, "ERROR - init_metric_table(): invalid parameters: size %d, base_m %d, min %d \n", size, base_m, min );
			
			debugFree( mt->t, 1722 );
			debugFree( mt, 1721 );
			return NULL;
		}
		
		prev = rate;
			
			
#ifdef EXT_DBG
		debug_all( "init_metric_table(): %4d  %10u bps  %13.4f bps  %13.4f kbps  %13.4f Mbps\n", i, mt->t[i], rate, rate/1000, rate/1000000 );
#endif
	}
	
	return mt;
	
}

void cleanup_metric_table( struct metric_table *mt ) {
	
	if ( mt == NULL )
		return;
	
	debugFree( mt->t, 1722 );
	debugFree( mt, 1721 );
	mt = NULL;

}

void print_metric_table( int fd, struct metric_table *mt ) {

	if ( mt == NULL ) 
		return;
	
	int i;
	
	for ( i=0; i < mt->t_size; i++ ) {
		
		uint32_t y = mt->t[mt->t_size-1-i];
		//float max = mt->t[mt->t_size-1];
		
		dprintf( fd, " %4d      %10u -> %10u ns  %10.4f   \n",
			i, mt->t[i], y, 1000000000 / ((float)(y)) ) ; 
		
		//((float)mt->t[i])/1000000, y, (((float)(y))/(mt->t_min*max)) * 1000000, 1 / (((float)(y))/(mt->t_min*max)) / 1000000, 
	}
	
}

#endif


void flush_sq_record( struct sq_record *sqr, int num_words )
{
	
	sqr->rcnt = sqr->vcnt = sqr->ocnt = sqr->bcnt = 0;
	
	memset( sqr->bits, 0, num_words * sizeof(REC_BITS_TYPE) );
	
}


#ifdef EXT_DBG

static char dbg_bits_str[MAX_DBG_STR_SIZE + 1];

int debug_marker( int pos, int bit, int sq, int rws, char name, uint8_t dbgl ) {
	
	int i, dbg_bits_out;
	int bit_len = pos*REC_BITS_SIZE + bit;
	int err = 0;
	if ( bit_len != sq%rws ) {
		debug_output( DBGL_SYSTEM, "debug_marker(): ERROR - calculated positions (%d:%d) do not match given sq %dmod%d=%d !! \n",
			    pos, bit, sq, rws, sq%rws );
		err = 1;
	}
	
	dbg_bits_out=0;
	for ( i=0; i<=bit_len; ) {
		dbg_bits_out += snprintf( (dbg_bits_str + dbg_bits_out), (MAX_DBG_STR_SIZE - dbg_bits_out), "%c", i==bit_len ? name:' ' );
		i++;
	}
	debug_output( err?DBGL_SYSTEM:dbgl, "%s \n", dbg_bits_str );

	return err;
}

int test_bits( REC_BITS_TYPE *word, uint16_t vws, uint16_t ows, SQ_TYPE sq, uint16_t rbits, uint16_t vbits, uint16_t obits, uint16_t bbits, uint8_t dbgl  ) {
	
	prof_start( PROF_test_bits );

	int i, dbg_bits_out, rcnt=0, vcnt=0, ocnt=0, bcnt=0, j, k=0, err = 0;
	
	uint16_t rws = ( (vws/REC_BITS_SIZE)  + ((vws%REC_BITS_SIZE)?1:0) ) * REC_BITS_SIZE ;

	debug_output( dbgl, "test_bits() vws %d  rws %d  sq %d  rbits %d  vcnt %d  obits %d  bbits %d \n", vws, rws,  sq, rbits, vbits, obits, bbits );
	
	dbg_bits_out=0;
	for ( j=0; j<=1; j++ ) {
		for ( i=0; i<rws; ) {
			do {
				int is_set = (word[i/REC_BITS_SIZE])&(0x01<<i%REC_BITS_SIZE);
				
				if( j == 0 )
					dbg_bits_out += snprintf( (dbg_bits_str + dbg_bits_out), (MAX_DBG_STR_SIZE - dbg_bits_out), "%c", is_set?'I':'_' );
				
				if ( j == 0  &&  is_set )
					rcnt++;
				
				if ( k > ((sq%rws)+rws-vws)  &&  k <= ((sq%rws)+rws)  &&  is_set )
					vcnt++;
				
				if ( k > ((sq%rws)+rws-ows)  &&  k <= ((sq%rws)+rws)  &&  is_set )
					ocnt++;

				if ( k > ((sq%rws)+rws-vws)  &&  k <= ((sq%rws)+rws-ows)  &&  is_set )
					bcnt++;
				
				i++;
				k++;
				
				
			} while( (i%REC_BITS_SIZE) != 0 && i < rws );
		}
	}
	
	if ( rbits != rcnt || vbits != vcnt || obits != ocnt || bbits != bcnt ) {
		debug_output( DBGL_SYSTEM, "ERROR - test_bits(%d): counted bits != given bits rc %d rg %d   vc %d vg %d   oc %d og %d   bc %d bg %d !! \n",
			      sq, rcnt, rbits, vcnt, vbits, ocnt, obits, bcnt, bbits );
		
		err = 1;
	}

	debug_output( err?DBGL_SYSTEM:dbgl, "%s \n", dbg_bits_str );

	/*
	dbg_bits_out=0;
	for ( i=0; i<rws; i+=10) {
		dbg_bits_out += snprintf( (dbg_bits_str + dbg_bits_out), (MAX_DBG_STR_SIZE - dbg_bits_out), "%-10d", i );
	}
	debug_output( err?DBGL_SYSTEM:dbgl, "%s \n", dbg_bits_str );

	
	dbg_bits_out=0;
	for ( i=0; i<rws; i++) {
		dbg_bits_out += snprintf( (dbg_bits_str + dbg_bits_out), (MAX_DBG_STR_SIZE - dbg_bits_out), "%1d", i%10 );
	}
	debug_output( err?DBGL_SYSTEM:dbgl, "%s \n", dbg_bits_str );
	*/

	prof_stop( PROF_test_bits );

	return err;
}

#endif


static inline void purge_bits(  OGM_BITS_TYPE bits_upd, REC_BITS_TYPE *bits_rec, 
				uint16_t rws, uint16_t vws, SQ_TYPE sq_upd, SQ_TYPE sq_rec, uint16_t blocked_sq_offset,
				uint16_t *rcnt_rec, uint16_t *vcnt_rec, uint16_t *ocnt_rec,
				int16_t rec_pos_ms, int16_t upd_pos_ms, int16_t rec_bit_ms, int16_t upd_bit_ms ) 
{
	int16_t i;
	
	SQ_TYPE upd_o = ((SQ_TYPE)(sq_upd - sq_rec)) > blocked_sq_offset ? sq_rec : sq_upd - blocked_sq_offset;
	
	int16_t upd_o_pos_ms = ( upd_o % rws) / REC_BITS_SIZE; 
	int16_t upd_o_bit_ms = ( upd_o % rws) % REC_BITS_SIZE;
	
	int16_t rec_o_pos_ms = ( ((SQ_TYPE)(sq_rec - blocked_sq_offset)) % rws) / REC_BITS_SIZE; 
	int16_t rec_o_bit_ms = ( ((SQ_TYPE)(sq_rec - blocked_sq_offset)) % rws) % REC_BITS_SIZE;
	
	
	i = rec_o_pos_ms;
	
	if ( i==upd_o_pos_ms  &&  rec_o_bit_ms <= upd_o_bit_ms ) {
		
		*ocnt_rec -= get_set_bits( bits_rec[i] &  ( ((((REC_BITS_TYPE)-1)<<(rec_o_bit_ms))<<1) & ~((((REC_BITS_TYPE)-1)<<(upd_o_bit_ms))<<1) ) );
		
	} else {
		
		*ocnt_rec -= get_set_bits( bits_rec[i] &  ((((REC_BITS_TYPE)-1)<<(rec_o_bit_ms))<<1) );
		
		for (;;) {
			
			i = ( i==((rws/REC_BITS_SIZE)-1) ? 0: i+1 );
				
			if ( i==upd_o_pos_ms ) {
				
				*ocnt_rec -= get_set_bits(bits_rec[i] & ~((((REC_BITS_TYPE)-1)<<(upd_o_bit_ms))<<1) );
				break;
			
			} else {
				*ocnt_rec -= get_set_bits(bits_rec[i]);
			}
		}
	}

	
	i = rec_pos_ms;
		
	if ( i==upd_pos_ms  &&  rec_bit_ms<=upd_bit_ms ) {
				
		*rcnt_rec -= get_set_bits( bits_rec[i] &  ( ((((REC_BITS_TYPE)-1)<<(rec_bit_ms))<<1) & ~((((REC_BITS_TYPE)-1)<<(upd_bit_ms))<<1) ) );
		bits_rec[i] =              bits_rec[i] & ~( ((((REC_BITS_TYPE)-1)<<(rec_bit_ms))<<1) & ~((((REC_BITS_TYPE)-1)<<(upd_bit_ms))<<1) );
				
	} else {
		
		*rcnt_rec -= get_set_bits(bits_rec[i] &  ((((REC_BITS_TYPE)-1)<<(rec_bit_ms))<<1) );
		bits_rec[i] =             bits_rec[i] & ~((((REC_BITS_TYPE)-1)<<(rec_bit_ms))<<1);
		
		for (;;) {
			
			i = ( i==((rws/REC_BITS_SIZE)-1) ? 0: i+1 );
				
			if ( i==upd_pos_ms ) {
					
				*rcnt_rec -= get_set_bits(bits_rec[i] & ~((((REC_BITS_TYPE)-1)<<(upd_bit_ms))<<1) );
				bits_rec[i] =             bits_rec[i] &  ((((REC_BITS_TYPE)-1)<<(upd_bit_ms))<<1);
				break;		
					
			} else {
				*rcnt_rec -= get_set_bits(bits_rec[i]);
				bits_rec[i] = 0;
			}
		}
	}
	
	// the number of bits in vws differ by those in rws only by those in the two REC_BITS_TYPEs around upd_pos_ms, so we just count them
	if ( rws != vws ) {
		
		// the position following the more-significant-REC_BITS_TYPE
		int upd_pos_pp = (upd_pos_ms + 1) >= (rws/REC_BITS_SIZE) ? 0 : (upd_pos_ms + 1);

		*vcnt_rec = *rcnt_rec - (
				get_set_bits( bits_rec[upd_pos_ms] &  ((( ((REC_BITS_TYPE)-1)>>(REC_BITS_SIZE+vws-rws) )<<upd_bit_ms)<<1) ) +
				get_set_bits( bits_rec[upd_pos_pp] &  ((( ((REC_BITS_TYPE)-1)>>(REC_BITS_SIZE+vws-rws) )>>(REC_BITS_SIZE-(upd_bit_ms+1)))) ) );
			
	} else { 
		*vcnt_rec = *rcnt_rec;
	}

}

static inline void record_bits( OGM_BITS_TYPE bits_upd, REC_BITS_TYPE *bits_rec, SQ_TYPE sq_upd, int16_t upd_pos_ls, int16_t upd_pos_ms,
				    uint16_t *rcnt_rec, uint16_t *vcnt_rec, uint16_t *ocnt_rec, uint8_t dbgl )
{

	uint16_t shift_ls_left = ((uint16_t)(sq_upd)) % REC_BITS_SIZE;
	uint16_t shift_ms_right = (REC_BITS_SIZE-1)-shift_ls_left;
	
	REC_BITS_TYPE ls_word = ( ((REC_BITS_TYPE)bits_upd) << ((REC_BITS_SIZE-OGM_BITS_SIZE) + 1) ) << shift_ls_left;
	
	REC_BITS_TYPE ms_word = ( ((REC_BITS_TYPE)bits_upd) << (REC_BITS_SIZE-OGM_BITS_SIZE) ) >> shift_ms_right;

	// count only the new bits 
	uint16_t new_bits = get_set_bits( (~(bits_rec[upd_pos_ls])) & ls_word ) + get_set_bits( (~(bits_rec[upd_pos_ms])) & ms_word );

	*rcnt_rec += new_bits;
	*vcnt_rec += new_bits; 
	*ocnt_rec += new_bits; 

	
	bits_rec[upd_pos_ls] |= ls_word;
	bits_rec[upd_pos_ms] |= ms_word;
	
#ifdef EXT_DBG
	debug_output( dbgl, "record_bits(): ls:rec[%2d]= %X -> %d bits, ms:rec[%2d]= %X -> %d bits \n",
		      upd_pos_ls, ls_word, get_set_bits( ls_word ), upd_pos_ms, ms_word, get_set_bits( ms_word ) );
#endif
}

/* update sequence number array (by bits_rec and seqno_rec) accroding to bits_upd and sq_upd
 * bits_upd must be in host-byte-order
 * works best if msb of bits_upd is true. msb MUST represent seqno_upd
 * if bits_upd == 0 :  just purge upto seqno_upd
 * else :  or-update assuming that position of highest given bit in bits_upd represents seqno_upd
 * all recorded bits in bits_rec older than send_seqno_rec will only be purged (ie will not be or-updated)
 * Finally sq_rec MUST BE UPDATED before this record is called again !!!
 * Precondition: rws % (8*sizeof(REC_BITS_TYPE)) MBZ   AND   rws - (8*sizeof(REC_BITS_TYPE)) < vws <= rws
 */

SQ_TYPE update_bits(  OGM_BITS_TYPE bits_upd, SQ_TYPE sq_upd, 
		      struct sq_record *sqr, SQ_TYPE sq_rec, uint16_t blocked_sq_offset, uint16_t vws, 
		      uint8_t dbgl )
{
	
	prof_start( PROF_update_bits );

	uint16_t rws = ( (vws/REC_BITS_SIZE)  + ((vws%REC_BITS_SIZE)?1:0) ) * REC_BITS_SIZE ;

	SQ_TYPE new_sq;
	
	// the byte position of the more-significant-REC_BITS_TYPE position to update
	int16_t upd_pos_ms = (sq_upd % rws) / REC_BITS_SIZE; 
	// the bit position of the more-significant-REC_BITS_TYPE position to update
	int16_t upd_bit_ms = (sq_upd % rws) % REC_BITS_SIZE;
	
	// the byte position of the less-significant-REC_BITS_TYPE position to update
	int16_t upd_pos_ls = (upd_pos_ms - 1) < 0 ? ((rws/REC_BITS_SIZE)-1) : (upd_pos_ms - 1);
	
	int16_t rec_pos_ms = (sq_rec % rws) / REC_BITS_SIZE;
	int16_t rec_bit_ms = (sq_rec % rws) % REC_BITS_SIZE;
	
#ifdef EXT_DBG
	debug_output( dbgl, "\n");
	debug_output( dbgl, "update_bits(): bits %2X  sq_upd %5d  blocked_sq_offs %5d   sq_rec %5d  rcnt %5d vcnt %5d ocnt %5d bcnt %5d rws %5d vws %5d \n"
				"				(upd_pos_ms %d  upd_bit_ms %d  upd_pos_ls %d  rec_pos_ms %d  rec_bit_ms %d)\n",
				bits_upd, sq_upd, blocked_sq_offset, sq_rec, sqr->rcnt, sqr->vcnt, sqr->ocnt, sqr->bcnt, rws, vws,
				upd_pos_ms, upd_bit_ms, upd_pos_ls, rec_pos_ms, rec_bit_ms  );
#endif	
	
	// if not already done, shift to-be-updated bits to the most significant position
	while ( bits_upd && !(bits_upd & (0x01<<(OGM_BITS_SIZE-1)) ) )
		bits_upd = bits_upd<<1;
	
	// if vws < OGM_BITS_SIZE truncate bits_upd to vws
	if ( vws < OGM_BITS_SIZE )
		bits_upd &= ((OGM_BITS_TYPE)-1)<<(OGM_BITS_SIZE-vws);

	
#ifdef EXT_DBG
	test_bits( sqr->bits,  vws, blocked_sq_offset, sq_rec, sqr->rcnt, sqr->vcnt, sqr->ocnt, sqr->bcnt, dbgl );
	debug_marker( rec_pos_ms, rec_bit_ms, sq_rec, rws, 'O', dbgl );
	debug_marker( upd_pos_ms, upd_bit_ms, sq_upd, rws, 'N', dbgl );
#endif	
	
	
	if ( ((SQ_TYPE)(sq_rec - sq_upd)) < vws ) {
		
#ifdef EXT_DBG
		debug_output(dbgl, "update_bits(): bits_upd completely within known range -> nothing to purge, maybe update unblocked bits: \n");
#endif		
		new_sq = sq_rec;
		
		if ( ((SQ_TYPE)(sq_rec -  sq_upd)) >= blocked_sq_offset ) {

#ifdef EXT_DBG
			debug_output(dbgl, "update_bits(): bits_upd completely within blocked range -> block all bits \n");
#endif
			
			bits_upd = 0;
		
		} else if ( ((SQ_TYPE)( sq_rec - sq_upd )) > ((SQ_TYPE)( blocked_sq_offset - OGM_BITS_SIZE ))  ) {
			
#ifdef EXT_DBG
			debug_output(dbgl, "update_bits(): blocked boundary older than update: block some trailing bits: bits_upd %X & %X\n",
				     (OGM_BITS_TYPE)bits_upd, 
				      ((OGM_BITS_TYPE)(~(((OGM_BITS_TYPE)-1)>>(blocked_sq_offset - ((SQ_TYPE)(sq_rec - sq_upd))) ) ) ) );
#endif			
			
			bits_upd &= ~( ((OGM_BITS_TYPE)-1)>>(blocked_sq_offset - ((SQ_TYPE)(sq_rec - sq_upd))) );
			
			
		} // else leave bits_upd untouched
		
		record_bits( bits_upd, sqr->bits, sq_upd, upd_pos_ls, upd_pos_ms, &sqr->rcnt, &sqr->vcnt, &sqr->ocnt, dbgl );
		
		
	} else if ( ((uint16_t)(sq_upd - sq_rec) < vws) ) {

#ifdef EXT_DBG
		debug_output(dbgl, "update_bits(): partly newer than known range. Partly overlapping with known range -> something to purge \n");
#endif		
		new_sq = sq_upd;
		
		// IF blocked range overlapping with new bits (thus: offset range smaller than OGM_BITS_SIZE) THEN  only record bits in offset range:
		if ( blocked_sq_offset < OGM_BITS_SIZE )
			bits_upd &= ~( ((OGM_BITS_TYPE)-1)>>blocked_sq_offset );
		
		
		purge_bits(  bits_upd, sqr->bits,
			     rws, vws, sq_upd, sq_rec, blocked_sq_offset,
			     &sqr->rcnt, &sqr->vcnt, &sqr->ocnt,
			     rec_pos_ms, upd_pos_ms, rec_bit_ms, upd_bit_ms );
		
		record_bits( bits_upd, sqr->bits, sq_upd, upd_pos_ls, upd_pos_ms, &sqr->rcnt, &sqr->vcnt, &sqr->ocnt, dbgl );

		
	} else {
		
#ifdef EXT_DBG
		debug_output(dbgl, "update_bits():  out of known range! purge all: \n");
#endif		
		new_sq = sq_upd;
		
		// if offset range smaller than OGM_BITS_SIZE:  only record bits in offset range:
		if ( blocked_sq_offset < OGM_BITS_SIZE )
			bits_upd &= ~( ((OGM_BITS_TYPE)-1)>>blocked_sq_offset );

		memset( (char*)sqr->bits, 0, rws/(sizeof(char)*8)  );
		
		sqr->vcnt = sqr->ocnt = sqr->rcnt = 0;
		
		record_bits( bits_upd, sqr->bits, sq_upd, upd_pos_ls, upd_pos_ms, &sqr->rcnt, &sqr->vcnt, &sqr->ocnt, dbgl );
		
	}
	
	sqr->bcnt = sqr->vcnt - sqr->ocnt;
	
	
	
#ifdef EXT_DBG
	debug_marker( upd_pos_ms, upd_bit_ms, sq_upd, rws, 'N', dbgl );
	
	int err = 0;

	if ( sqr->sq_rec != 0  &&  sqr->sq_rec != sq_rec ) {
		err=1;
		debug_output( DBGL_SYSTEM, "ERROR - update_bits(): given sq_rec %d != recorded sq_rec %d \n", sq_rec, sqr->sq_rec );
		
	}
	
	sqr->sq_rec = new_sq;
	
	err = test_bits( sqr->bits, vws, blocked_sq_offset, new_sq, sqr->rcnt, sqr->vcnt, sqr->ocnt, sqr->bcnt, dbgl );
	
	if ( err )
		debug_output( DBGL_SYSTEM, "ERROR - update_bits(): bits %2X  sq_upd %5d  blocked_sq_offs %5d   sq_rec %5d  rcnt_rec %5d vcnt rec %5d  rws %5d vws %5d \n"
				"				(upd_pos_ms %d  upd_bit_ms %d  upd_pos_ls %d  rec_pos_ms %d  rec_bit_ms %d)\n",
				bits_upd, sq_upd, blocked_sq_offset, sq_rec, sqr->rcnt, sqr->vcnt, rws, vws,
				upd_pos_ms, upd_bit_ms, upd_pos_ls, rec_pos_ms, rec_bit_ms  );
#endif

	prof_stop( PROF_update_bits );

	return new_sq;
	
}

int link_probe_nodes = 0;

void init_link_probes( struct link_node *ln ) {
	
	ln->link_flags |= UNICAST_PROBES_CAP ;
	link_probe_nodes++;
	
	
}

void stop_link_probes( struct link_node *ln ) {
	
	ln->link_flags &= ~UNICAST_PROBES_CAP ;
	link_probe_nodes--;
	
}

uint32_t send_unicast_probes( void ) {

	struct link_node *ln;
	struct list_head *link_pos, *list_pos;
	
	struct orig_node *orig_node;
	struct sockaddr_in probe_addr;
	
	static char orig_str[ADDR_STR_LEN];
	static int probe_if = 0;
	
	int rtq;
	
	unsigned char probe_packet[MAX_UNI_PROBES_SIZE];
	memset( probe_packet, 123, MAX_UNI_PROBES_SIZE );
	
	struct bat_header *bh = (struct bat_header*)probe_packet;
	struct bat_packet_uprq *uprq = (struct bat_packet_uprq*)(probe_packet + sizeof(struct bat_header));
	
	memset( bh, 0, sizeof( struct bat_header ) );
	
	if (unicast_probes_num == 0) 
		return 1000;

	
	bh->version = COMPAT_VERSION;
		
	bh->link_flags |= UNICAST_PROBES_CAP;
				
	
	bh->size = ( sizeof(struct bat_header) + sizeof( struct bat_packet_uprq ) ) / 4;

	memset( uprq, 0, sizeof( struct bat_packet_uprq ) );

	uprq->bat_type = BAT_TYPE_UPRQ;
	uprq->ext_msg = NO;
	uprq->size = sizeof( struct bat_packet_uprq ) / 4;
	
	uprq->probe_max = htons( unicast_probes_num );
	
	list_for_each( link_pos, &link_list ) {

		ln = list_entry(link_pos, struct link_node, list);
		
		if (!( ln->link_flags & UNICAST_PROBES_CAP ))
			continue;
		
		orig_node = ln->orig_node;
		addr_to_string( orig_node->orig, orig_str, sizeof (orig_str) );

		probe_addr.sin_family = AF_INET;
		probe_addr.sin_port = htons( ogm_port );
		probe_addr.sin_addr.s_addr = orig_node->orig;


		list_for_each( list_pos, &if_list ) {

			struct batman_if *bif = list_entry( list_pos, struct batman_if, list );

			if ( bif->if_num == probe_if  &&  !bif->is_lo  &&  (rtq=ln->lndev[bif->if_num].rtq_sqr.vcnt) > 0 ) {
			
				uprq->probe_interval = htons( (ln->lndev[bif->if_num].curr_probe_interval)++ );

				
				debug_all( " send_unicast_probes(): probing NB %s on %s rtq %d, size %d\n", orig_str, bif->dev, rtq, bh->size );
				
				int probe_num;
				for ( probe_num = 0; probe_num <= unicast_probes_num ; probe_num++ ) {
				
					int udp_size =  sizeof(struct bat_header) + sizeof(struct bat_packet_uprq);
					
					if ( probe_num > 0 )
						udp_size = unicast_probes_size; 
					
					uprq->probe_num = htons( probe_num );
					
					send_udp_packet( probe_packet, udp_size, &probe_addr,  bif->udp_send_sock);
				
				}
			
			}
		}
		
	}
	
	if ( ++probe_if >= found_ifs )
		probe_if = 0 ;
	
	return rand_num( 2*unicast_probes_ival ) / found_ifs;
	
//	return ( unicast_probes_ival + rand_num( 2*MIN_UNI_PROBES_IVAL ) - MIN_UNI_PROBES_IVAL ) / found_ifs;
	
}


void process_unicast_probe( struct msg_buff *mb ) {
	
	mb->uprq->probe_interval = ntohs( mb->uprq->probe_interval );
	mb->uprq->probe_num      = ntohs( mb->uprq->probe_num );
	mb->uprq->probe_max      = ntohs( mb->uprq->probe_max );

	debug_all( "Received unicast link probe request: %s %s probe_ival %6d %2d/%2d, total bytes %4d, %s, time: %6d %6ld:%6ld, \n", 
		      mb->neigh_str, mb->iif->dev, mb->uprq->probe_interval, mb->uprq->probe_num, mb->uprq->probe_max, mb->total_length, 
			mb->unicast?"UNICAST":"BRCAST" , batman_time, mb->tv_stamp.tv_sec, mb->tv_stamp.tv_usec );

	
	struct orig_node *orig_neigh_node = get_orig_node( mb->neigh );

	struct link_node *ln;
	
	if ( ( ln = orig_neigh_node->link_node ) == NULL ) {
		debug_output( DBGL_SYSTEM, "ERROR - DROP UNICAST PROBE from NB %15s  IF %10s  - NO LINK NODE !!!!!\n", mb->neigh_str, mb->iif->dev );
		return;
	}
	
	
//	int idx =  mb->uprq->probe_interval % PROBE_RECORD_ARRAY_SIZE;
	
	struct link_node_dev *lndev = &(ln->lndev[ mb->iif->if_num ]);
	
	if ( lndev->pr.interval != mb->uprq->probe_interval  ||
		    lndev->pr.last_num >= mb->uprq->probe_num  ) {
		
		if ( ((SQ_TYPE)(mb->uprq->probe_interval - lndev->last_complete_probe_interval)) > PROBE_HISTORY ) {
			
			lndev->last_probe_tp = lndev->sum_probe_tp = lndev->conservative_probe_tp = 0;
			
			debug_output( DBGL_CHANGES, "WARNING, process_unicast_probe(): missed %d probes from %15s %10s \n",
				      ((SQ_TYPE)(mb->uprq->probe_interval -1 - lndev->last_complete_probe_interval)), mb->neigh_str, mb->iif->dev );
			
		} else if ( ((SQ_TYPE)(mb->uprq->probe_interval - lndev->last_complete_probe_interval)) > 1 ){
			
			
			SQ_TYPE i;
			
			for (i=0; LESS_SQ( lndev->last_complete_probe_interval+1+i, mb->uprq->probe_interval ); i++ ){
				
				lndev->sum_probe_tp -= lndev->sum_probe_tp / PROBE_HISTORY;
			
				lndev->conservative_probe_tp += ((lndev->conservative_probe_tp / 2) / PROBE_HISTORY) - lndev->conservative_probe_tp / PROBE_HISTORY;
				
			}
			
			debug_output( DBGL_CHANGES, "WARNING, process_unicast_probe(): missed %d/%d probes from %15s %10s \n",
				      i, ((SQ_TYPE)(mb->uprq->probe_interval -1 - lndev->last_complete_probe_interval)), mb->neigh_str, mb->iif->dev );
			
		}
		
		lndev->pr.interval = mb->uprq->probe_interval;
		lndev->pr.data_bits = 0;
		lndev->pr.rcvd_nums = 0;
		lndev->pr.last_num     = mb->uprq->probe_num;
		lndev->pr.init_num     = mb->uprq->probe_num;
		lndev->pr.init_stamp.tv_sec  = mb->tv_stamp.tv_sec;
		lndev->pr.init_stamp.tv_usec = mb->tv_stamp.tv_usec;
		lndev->pr.latency = 0;
		lndev->pr.throughput = 0;
		
	} else {
		struct timeval ipt;

		lndev->pr.data_bits += (8*(mb->total_length + UDP_OVERHEAD));
		lndev->pr.rcvd_nums++;
		lndev->pr.last_num = mb->uprq->probe_num;
		lndev->pr.last_stamp.tv_sec  = mb->tv_stamp.tv_sec;
		lndev->pr.last_stamp.tv_usec = mb->tv_stamp.tv_usec;
		
		if ( mb->uprq->probe_max == mb->uprq->probe_num ) {
		
			timersub( &(lndev->pr.last_stamp), &(lndev->pr.init_stamp), &ipt );
			
			if ( ipt.tv_sec < 100  &&  (ipt.tv_sec > 0 || ipt.tv_usec > 0) ) {
				
				lndev->last_complete_probe_interval = lndev->pr.interval;
				lndev->last_complete_probe_stamp = batman_time;
			
				lndev->pr.latency = ipt.tv_sec * 1000000 + ipt.tv_usec;
				
				lndev->last_probe_tp = lndev->pr.throughput = (
						(1000 * (lndev->pr.data_bits)) /
						(lndev->pr.latency) );
				
				lndev->sum_probe_tp += lndev->pr.throughput - lndev->sum_probe_tp/PROBE_HISTORY;
				
				
				if ( lndev->conservative_probe_tp < PROBE_HISTORY )
					lndev->conservative_probe_tp = PROBE_HISTORY;
				
				uint32_t conservative_tp;
				
				if ( lndev->pr.throughput > (lndev->conservative_probe_tp * 2) / PROBE_HISTORY )
					conservative_tp = (lndev->conservative_probe_tp * 2) / PROBE_HISTORY;
				else if ( lndev->pr.throughput < (lndev->conservative_probe_tp / 2) / PROBE_HISTORY )
					conservative_tp = (lndev->conservative_probe_tp / 2) / PROBE_HISTORY;
				else
					conservative_tp = lndev->pr.throughput;
				
				
				lndev->conservative_probe_tp += conservative_tp - lndev->conservative_probe_tp/PROBE_HISTORY;
				
			} else {
				
				lndev->last_probe_tp = lndev->pr.throughput = 0;
				
			}
			
#ifdef METRICTABLE

			SQ_TYPE up_sqn = OGM_BITS_SIZE * (mb->uprq->probe_interval);
			
			uint16_t prev_vcnt;
			prev_vcnt = lndev->up_sqr.vcnt;
			
			lndev->last_up_sqn = update_bits( 0, up_sqn,  &lndev->up_sqr, lndev->last_up_sqn, OGM_BITS_SIZE, unicast_probes_ws,  DBGL_ALL );
			
								
			// find upper boundary of average setBits per OGM to represent measured throughut
			uint16_t b, f = MAX_BITS_RANGE / unicast_probes_ws;
			OGM_BITS_TYPE bits;
			
			for ( b=0; b < OGM_BITS_SIZE && global_mt->t[ f*b*(unicast_probes_ws/OGM_BITS_SIZE) ] < lndev->pr.throughput*1000; b++ );
			
			if ( b )
				bits = ((OGM_BITS_TYPE)-1) << (OGM_BITS_SIZE-b);
			else 
				bits = 0;
			
			
			if (  global_mt->t[ f*(lndev->up_sqr.vcnt+b) ] <= lndev->pr.throughput*1000 ) {
				
				update_bits( bits, up_sqn,  &lndev->up_sqr, lndev->last_up_sqn, OGM_BITS_SIZE, unicast_probes_ws,  DBGL_CHANGES );
				
			} else {
				
				bits = bits <<1;
				update_bits( bits, up_sqn,  &lndev->up_sqr, lndev->last_up_sqn, OGM_BITS_SIZE, unicast_probes_ws,  DBGL_CHANGES );
			
			}
		
			debug_all( "U_PROBE  %s %s #%5d %2d/%2d,"
					" %4d bits in %4d us -> %5d Kbps avg %5d, mt[%4d-%2d+%2d=%4d (%3d)] = %5d ([%d*%2d->%4d]=%6d [%2d]=%5d  )\n", 
					mb->neigh_str, mb->iif->dev, mb->uprq->probe_interval,
					lndev->pr.rcvd_nums, mb->uprq->probe_max,
					lndev->pr.data_bits,
					lndev->pr.latency,
					lndev->pr.throughput,
					lndev->sum_probe_tp / PROBE_HISTORY,
					prev_vcnt, prev_vcnt-lndev->up_sqr.vcnt, get_set_bits( bits ), 
					lndev->up_sqr.vcnt, (int)get_set_bits( bits ) - (int)(prev_vcnt-lndev->up_sqr.vcnt),
					global_mt->t[ f*lndev->up_sqr.vcnt ]/1000,
					f, b, f*b*(unicast_probes_ws/OGM_BITS_SIZE), global_mt->t[ f*b*(unicast_probes_ws/OGM_BITS_SIZE) ]/1000,
					b-1, global_mt->t[ f*(b-1)*(unicast_probes_ws/OGM_BITS_SIZE) ]/1000
				    );
			
#endif
			
		}
	
	}
	
}



