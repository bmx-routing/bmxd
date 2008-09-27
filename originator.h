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

extern struct list_head_first link_list;

struct orig_node *get_orig_node( uint32_t addr );

void init_originator( void );
struct neigh_node *init_neigh_node( struct orig_node *orig_node, uint32_t neigh, struct batman_if *iif, SQ_TYPE seqno, uint32_t last_aware );
void free_link_node( struct orig_node *orig_node );
void flush_link_node_seqnos( void );
void update_primary_orig( struct orig_node *orig_node, struct msg_buff *mb );
void update_link( struct orig_node *orig_node, SQ_TYPE in_seqno, struct batman_if *this_if, uint8_t direct_undupl_neigh_ogm, uint8_t link_flags );
void set_lq_bits( struct link_node *link_node, SQ_TYPE in_seqno, struct batman_if *this_if, uint8_t direct_undupl_neigh_ogm );

int get_lq_bits( struct link_node *link_node, struct batman_if *this_if, uint16_t read_range );

int tq_rate( struct orig_node *orig_neigh_node, struct batman_if *if_incoming, int range );
int tq_power( int tq_rate_value, int range );

int alreadyConsidered( struct orig_node *orig_node, SQ_TYPE seqno, uint32_t neigh, struct batman_if *if_incoming );

struct neigh_node *get_neigh_node( struct orig_node *orig_node, uint32_t neigh, struct batman_if *if_incoming );

void update_orig( struct orig_node *orig_node, struct orig_node *orig_neigh_node, uint8_t acceppted, struct msg_buff *mb );
void purge_orig( uint32_t curr_time );
void debug_orig( int dbgl, int sock );

