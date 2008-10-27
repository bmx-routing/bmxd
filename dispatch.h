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
	uint8_t  own;
	unsigned char *ogm_buff;
	int32_t  ogm_buff_len;
	struct batman_if *if_outgoing;
};



struct todo_node 
{ 
	struct list_head list; 
	uint32_t expire;
	void (* task) (void *fpara); // pointer to the function to be executed
	void *data; //NULL or pointer to data to be given to function. Data will be freed after functio is called.
};


void init_dispatch( void );
void cleanup_dispatch( void );
void register_task( uint32_t timeout, void (* task) (void *), void *data );
uint32_t whats_next( void /*(** task) (void *),  void **data*/ );
void wait4Event( uint32_t timeout );
void schedule_own_ogm( struct batman_if *batman_if, uint32_t current_time );
void debug_send_list( int sock );
void send_outstanding_ogms( void *data );

