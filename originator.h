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



//int compare_orig( void *data1, void *data2 );
//int choose_orig( void *data, int32_t size );
struct orig_node *get_orig_node( uint32_t addr );
int update_lq_bits_INVALID( struct orig_node *orig_node, uint8_t update, uint16_t in_seqno, struct batman_if *this_if, uint8_t direct_undupl_neigh_ogm, uint16_t read_range );
void set_dbg_rcvd_all_bits( struct orig_node *orig_node, uint16_t in_seqno, struct batman_if *this_if, uint8_t bidirect_ogm );

void set_lq_bits( struct orig_node *orig_node, uint16_t in_seqno, struct batman_if *this_if, uint8_t direct_undupl_neigh_ogm );
int get_lq_bits( struct orig_node *orig_node, struct batman_if *this_if, uint16_t read_range );


int update_bi_link_bits ( struct orig_node *orig_neigh_node, struct batman_if * this_if, uint8_t write, uint16_t read_range );
int nlq_rate( struct orig_node *orig_neigh_node, struct batman_if *if_incoming );
int nlq_power( int nlq_rate_value );
int acceptance_rate( int nlq_assumption, uint16_t lq_assumtion );
void update_orig( struct orig_node *orig_node, struct bat_packet *in, uint32_t neigh, struct batman_if *if_incoming, struct ext_packet *gw_array, int16_t gw_array_len, struct ext_packet *hna_array, int16_t hna_array_len, uint32_t rcvd_time );
void purge_orig( uint32_t curr_time );
void debug_orig();

