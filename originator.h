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


#define MIN_SEQNO 0
#define DEF_SEQNO 0 /* causes seqno to be randomized */
#define MAX_SEQNO ((uint16_t)-1)


extern int32_t my_pws; // my path window size used to quantify the end to end path quality between me and other nodes
#define MAX_PWS 250      /* TBD: should not be larger until ogm->ws and neigh_node.packet_count (and related variables) is only 8 bit */
#define MIN_PWS 1
#define DEF_PWS 100  /* NBRF: NeighBor Ranking sequence Frame) sliding packet range of received orginator messages in squence numbers (should be a multiple of our word size) */

extern int32_t my_lws; // my link window size used to quantify the link qualities to direct neighbors
#define DEF_LWS 100
#define MAX_LWS 250
#define MIN_LWS 1

#define ARG_OGI_INTERVAL "ogm_interval"
extern int32_t my_ogi; // my originator interval
#define DEF_OGI 1000
#define MIN_OGI 200
#define MAX_OGI 10000 

extern int32_t my_link_lounge;
extern int32_t Default_lounge;

#define MIN_LOUNGE_SIZE 0
#define MAX_LOUNGE_SIZE (SQN_LOUNGE_SIZE-1)


//#define PURGE_SAFETY_PERIOD 25000 //25000
//#define PURGE_TIMEOUT ((MAX_OGI*MAX_PWS) + PURGE_SAFETY_PERIOD) /* 10 minutes + safety_period */ 
//extern int32_t purge_to
#define DEF_PURGE_TO  100000
#define MIN_PURGE_TO  10
#define MAX_PURGE_TO  864000 /*10 days*/

//extern int32_t dad_to;
#define DEF_DAD_TO 100
#define MIN_DAD_TO 1
#define MAX_DAD_TO 3600
//#define DEF_DAD_TO 100
//#define MIN_DAD_TO 10 /* if this is changed, be careful with PURGE_TIMEOUT */
//#define MAX_DAD_TO (PURGE_TIMEOUT/2)

extern int32_t Ttl;
#define DEF_TTL 50                /* Time To Live of OGM broadcast messages */
#define MAX_TTL 63
#define MIN_TTL 1

#define ARG_WL_CLONES   "ogm_broadcasts"
extern int32_t wl_clones;
#define DEF_WL_CLONES 200
#define MIN_WL_CLONES 0
#define MAX_WL_CLONES 400

#define DEF_LAN_CLONES 100


#define DEF_ASYM_WEIGHT	100
#define MIN_ASYM_WEIGHT	0
#define MAX_ASYM_WEIGHT	100
#define ARG_ASYM_WEIGHT	"asymmetric_weight"

#define DEF_ASYM_EXP	1
#define MIN_ASYM_EXP	0
#define MAX_ASYM_EXP	3
#define ARG_ASYM_EXP	"asymmetric_exp"

extern struct batman_if *primary_if;
extern uint32_t primary_addr;


extern struct hashtable_t *orig_hash;
extern struct list_head_first if_list;

extern struct list_head_first link_list;

struct orig_node *get_orig_node( uint32_t addr, uint8_t create );

int tq_rate( struct orig_node *orig_node_neigh, struct batman_if *iif, int range );

void purge_orig( uint32_t curr_time, struct batman_if *bif );

struct link_node_dev *get_lndev( struct link_node *ln, struct batman_if *bif, uint8_t create );

void process_ogm( struct msg_buff *mb );
void init_originator( void );
