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

#include "batman.h"

extern int unix_sock;

extern struct list_head_first cmsg_list;

extern struct list_head_first unix_clients;


struct client_node
{
	struct list_head list;
	int fd;
};

extern struct list_head_first dbgl_clients[DBGL_MAX+1];


struct cntl_msg {
	uint8_t version;
	uint8_t type;
	uint16_t len;
	int32_t val;
	uint32_t ip;
	uint32_t val1;
	uint32_t val2;
	char aux[]; // this may the beginning of an auxilarry string or the end of a common cntl_msg
} __attribute__((packed));

struct cmsg_node {
	struct list_head list;
	struct cntl_msg cmsg;
};

void init_control( void );
void cleanup_control( void );
void activate_debug_system( void );
void accept_unix_client( void );
void handle_unix_dbgl_msg( struct list_head* list_pos, struct list_head * prev_list_head, int dbgl );
void handle_unix_control_msg( struct list_head* list_pos, struct list_head * prev_list_head );
void debug_log( char *last, ... );
void debug_output( int8_t dbgl, char *last, ... );

