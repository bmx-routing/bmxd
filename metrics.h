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
 
#ifndef _BATMAN_METRICS_H
#define _BATMAN_METRICS_H


#define MAX_BITS_RANGE 1024
#define MAX_UNICAST_PROBING_WORDS (( MAX_BITS_RANGE / REC_BITS_SIZE ) + ( ( MAX_BITS_RANGE % REC_BITS_SIZE > 0)? 1 : 0 )) 



struct metric_table {
	
	int t_size;
	int t_base_m;
	int t_min;
	uint32_t *t;
	
};


extern struct metric_table *global_mt;

struct metric_table *init_metric_table( int size, int base_m, int min );

void print_metric_table( int fd, struct metric_table *mt );
		

void flush_sq_record( struct sq_record *sqr, int num_words );

SQ_TYPE update_bits(  OGM_BITS_TYPE bits_upd, SQ_TYPE sq_upd, 
		      struct sq_record *sqr, SQ_TYPE sq_rec, uint16_t blocked_sq_offset, uint16_t vws, 
		      uint8_t dbgl );

void cleanup_metric_table( struct metric_table *mt );

void init_link_probes( struct link_node *ln );
void stop_link_probes( struct link_node *ln );
uint32_t send_unicast_probes( void );
void process_unicast_probe( struct msg_buff *mb );

#endif
