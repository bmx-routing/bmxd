/* Copyright (C) 2006 B.A.T.M.A.N. contributors:
 * Axel Neumann
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


struct send_node                 /* structure for send_list maintaining packets to be (re-)broadcasted */
{
	struct list_head list;
	uint32_t send_time;
	int16_t  send_bucket;
	uint8_t  iteration;
	uint8_t  send;
	uint8_t  done;
	uint8_t  own;
	unsigned char *ogm_buff;
	int32_t  ogm_buff_len;
	struct batman_if *if_outgoing;
};

void init_dispatch( void );
void cleanup_dispatch( void );
void wait4Event( uint32_t timeout );
void schedule_own_ogm( struct batman_if *batman_if, uint32_t current_time );
void schedule_rcvd_ogm( uint8_t unidirectional, uint8_t directlink, uint8_t cloned, uint16_t neigh_id, struct msg_buff *mb );
void debug_send_list( int sock );
void send_outstanding_ogms();

