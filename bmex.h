/*
 * Copyright (C) 2006 B.A.T.M.A.N. contributors:
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

/* 
 * No configuration files or fancy command line switches yet
 * To experiment with B.A.T.M.A.N. settings change them here
 * and recompile the code
 * Here is the stuff you may want to play with: */ 
 

#ifndef _BMEX_BMEX_H
#define _BMEX_BMEX_H


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <linux/if.h>
#include "list.h"

/* #include "os.h" */

#define BM_DEBUG


#ifdef BM_DEBUG
#define dbg(...) output(__VA_ARGS__)
#else
#define dbg(...) 
#endif /* BM_DEBUG */

#define MAX_OF_LONG   2147483647
#define MIN_OF_LONG   -2147483647
#define MAX_OF_ULONG  4294967295
#define MAX_OF_CHAR   127
#define MAX_OF_UCHAR  255

#define minOf(a, b) (((a)<=(b))?(a):(b))
#define maxOf(a, b) (((a)>=(b))?(a):(b))

#define diffOf(a, b) ( maxOf((a),(b)) - minOf((a),(b))  )

// the following timer-macros are taken from the GNU C Library.
# define timerisset(tvp)	((tvp)->tv_sec || (tvp)->tv_usec)
# define timerclear(tvp)	((tvp)->tv_sec = (tvp)->tv_usec = 0)
# define timercmp(a, b, CMP) 						      \
  (((a)->tv_sec == (b)->tv_sec) ? 					      \
   ((a)->tv_usec CMP (b)->tv_usec) : 					      \
   ((a)->tv_sec CMP (b)->tv_sec))
# define timeradd(a, b, result)						      \
  do {									      \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;			      \
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;			      \
    if ((result)->tv_usec >= 1000000)					      \
      {									      \
	++(result)->tv_sec;						      \
	(result)->tv_usec -= 1000000;					      \
      }									      \
  } while (0)
# define timersub(a, b, result)						      \
  do {									      \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;			      \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;			      \
    if ((result)->tv_usec < 0) {					      \
      --(result)->tv_sec;						      \
      (result)->tv_usec += 1000000;					      \
    }									      \
  } while (0)





static struct timeval tv_null = {0,0};
static struct timeval start_time_tv, now_tv, then_tv;
//static struct sockaddr_in rcv_broad;
//static int rcv_sock;
static int stop;

int forward_old;





#define VERSION "0.08"
#define RCV_PORT 1967

#define ADDR_STR_LEN 16

#define YES 0x01
#define NO 0x00


// originator treatment flags:
#define ORIG_RCVD_UNI_FLAG 0x01    // originator message received with unidirectional flag
#define ORIG_BDNB_FLAG     0x02    // originator message received via currently bidirectional NB
#define ORIG_OS_FLAG  	   0x04    // NOT unidirectionalFlag && originator message with orig-addr && seqno already seen 
#define ORIG_OSN_FLAG 	   0x08    // ORIG_OS_FLAG && viaNeighb-addr already seen
#define ORIG_OSD_FLAG 	   0x10    // ORIG_OS_FLAG && viaDevice already seen 
#define ORIG_OSND_FLAG 	   0x20    // ORIG_OS_FLAG && viaNeighb-addr already seen && viaDevice already seen 
#define ORIG_CONSIDER_FLAG 0x40    // maintain and consider for further route selection 
#define ORIG_BROADCASTED_FLAG 0x80 // originator-seq-touple message hase already been (sheduled) for re-broadcast via all devs
 
#define UNIDIRECTIONAL_FLAG 0x01
#define INGW_UL_CAP_FLAGS	0x30
#define INGW_DL_CAP_FLAGS	0xC0

#define MIN_INGW_UL_CAP 0x00
#define MAX_INGW_UL_CAP 0x03
int arg_ingw_ul_capacity = 0; /* 0: no internet GW, 1: > 0bit/s, 2: > 64kbit/s, 3: > 6Mbit/s */

#define MIN_INGW_DL_CAP 0x00
#define MAX_INGW_DL_CAP 0x03
int arg_ingw_dl_capacity = 0;

#define TRIP_TIME_PLUS_CONST_RESET_THRESHOLD 10000

#define MIN_DEBUG 0
#define MAX_DEBUG 5
int arg_debug = 1;
  
#define MIN_ORIG_INTERVAL 100
#define MAX_ORIG_INTERVAL 100000
int arg_orig_interval_ms = 1000; /* originator packet emission period */


#define MIN_BIDIRECT_TO 100
#define MAX_BIDIRECT_TO 100000
int arg_bidirect_to_ms = 3000;   /* timeout until neighbour must be confirmed bidirectional */

#define MIN_ORIG_JITTER 0
#define MAX_ORIG_JITTER 1000
int arg_orig_jitter_ms = 50;    /*900 originator packet emission jitter */

#define MIN_FW_JITTER 0
#define MAX_FW_JITTER 1000
int arg_fw_jitter_ms = 50;

#define MIN_KEEP_FORW_ORDER 0
#define MAX_KEEP_FORW_ORDER 1
int arg_keep_forw_order = 1;

#define MIN_FORW_AGAIN 0
#define MAX_FORW_AGAIN 1
int arg_forward_again = 0;       /* forward orig_messages again if same seqno received multiple times due to longer hold-back time */ 

#define MIN_TTL 1
#define MAX_TTL 254
int arg_ttl = 100;				/* start ttl to be defined before the -dev argument */
#define TTL_MULTIPLE_DEVICES 1

#define MIN_PURGE_INTERVAL 100
#define MAX_PURGE_INTERVAL 10000
int arg_purge_interval_ms = 1000; /* purge routes, orig_list, pack_list period */


// TBD: this should depend on ( originators:orig_interval * receivers:arg_received_seq_range + safety-mark)
#define MIN_PURGE_TO  1000
#define MAX_PURGE_TO  100000
int arg_purge_to_ms = 20000; /* timeout for pack_nodes and orig_nodes for being removed */
 
#define MIN_RECEIVED_SEQ_RANGE 1
#define MAX_RECEIVED_SEQ_RANGE 100
int arg_received_seq_range = 10; /* range of latest seqno considered for bestNeighbour selection */

//int arg_additional_orig_to_ms = 1000; /* additional timeout (to arg_received_pack_to_ms)  for maintaining received originators */


 
#define MAX_ORIG_BUNDLE 20
#define MIN_ORIG_BUNDLE 1
int arg_max_orig_bundle = 1;     /* maximum number of originator messages to bundle */

/*int arg_forw_scheduler = 1*/      /* 0: no orig packet bundling, */
                                    /* 1: bundling during fw_jitter */
				  					/* 2: bundling during tx_intercal */
#define MIN_ROUTING_METRIC 1
#define ROUTING_METRIC_ORIGS 1
#define ROUTING_METRIC_AVG_TTL 2
#define MAX_ROUTING_METRIC 2
int arg_routing_metric = ROUTING_METRIC_ORIGS;

/*
#define MIN_ASB_POLICY 0x01
#define ASB_POLICY_HBT 0x01     alreadySeenBetter() considering hold_back_time 
#define ASB_POLICY_TTL 0x02     alreadySeenBetter() considering ttl 
#define ASB_POLICY_FIRST 0x04   alreadySeenBetter() considering simply the first occurance of a seqno 
#define MAX_ASB_POLICY 0x04
int arg_asb_policy = 0;
*/

#define MIN_CONSIDER_POLICY			0x01
#define CONSIDER_POLICY_INVALID 		0x00
#define CONSIDER_POLICY_STRICTLY_FIRST_SEEN     0x01
#define CONSIDER_POLICY_MAX_TTL         	0x02
#define CONSIDER_POLICY_MAX_TTL_MINUS_ONE	0x03
#define MAX_CONSIDER_POLICY			0x03
int arg_consider_policy = CONSIDER_POLICY_MAX_TTL_MINUS_ONE;

#define MIN_FORWARD_POLICY		    0x01
#define FORWARD_POLICY_INVALID 		    0x00
#define FORWARD_POLICY_STRICTLY_FIRST_SEEN  0x01
#define FORWARD_POLICY_BEST_NB              0x02
#define MAX_FORWARD_POLICY		    0x02
int arg_forward_policy = FORWARD_POLICY_BEST_NB;



/********************************************************************
 * Data Structures for maintaining known origs, OGMs, BNTOGs, and PNTOGs
 */
 
unsigned int my_rcv_addr = 0;   /* this node's ip adress */

struct packet_orig
{
  unsigned long  orig;
  unsigned char  flags;    /* 0xF0: UNIDIRECTIONAL link, ... */
/* ttl of received packet - 1, orig node sends packet with with device specific arg_ttl */
  unsigned char  ttl;     
  unsigned long seqno;    
  unsigned short hold_back_time; /* time in ms this packet has been hold by forwarding nodes, TBD: check value for overflows */
  long originated_oview_tstmp; /* timestamp in ms since start of programm (from originator point of view) when packet was originated */

} __attribute__((packed));

struct pack_node
{
  struct list_head list;
  struct timeval forwarded;
  struct timeval received;
  long  originated_oview_tstmp;
  unsigned short hold_back_time; 
/*   struct timeval ooptim_originated_rview_tstmp; */
  /* received - hold_back_time ( - unknown_aggregated_MAC_and_PHY_delay=0 ) */
  /* but comparing this value for identical originator-seqnumber touples, received via different routes,
     the route with the smaller ooptim_originated_rview_tstmp indicates a smaller
     unknown_aggregated_MAC_and_PHY_delay, thus a faster one-way trip time */
  unsigned char treatmentFlags;
  char already_scheduled_for_rebroadcast_via_all_devs;
  unsigned long seqno;    
  struct orig_node *orig_node;
  struct orig_node *via_orig_node;
  struct device_node *via_device_node; // set in setOrigPack_node()
  
  unsigned char  flags; 
  unsigned char  ttl;
};

#define MAX_DEVICE_LIST_SIZE 3
int device_list_size = 0;

struct hmvd
{
  short rcvdOrigs;	
  short rcvd1Origs;	
  short sumTtl; // divide it by rcvdOrigs and you get avgTtl
  unsigned char minTtl;
  unsigned char maxTtl;
  unsigned long minSeqno;
  unsigned long maxSeqno;
  long minTtpc;
  long maxTtpc;
  long sumTtpc;
  long latestTtpc;
  //  	struct device_node *via_device_node; // set in setOrigPack_node()
};

struct summary_node {
  struct list_head list; 

  struct orig_node *orig_node; // points to next neighbor ( towards destination destination orig )
  short rcvdOrigs; 
  short rcvd1Origs;	
  short sumTtl; // divide it by rcvdOrigs and you get avgTtl
  unsigned char minTtl;
  unsigned char maxTtl;
  unsigned long minSeqno;
  unsigned long maxSeqno;
  long minTtpc;
  long maxTtpc;
  long sumTtpc;
  long latestTtpc;
  
  struct hmvd hmvda[ MAX_DEVICE_LIST_SIZE ];
};

struct best_route
{
  struct orig_node *best_router;
  int best_router_device_index;
  //  unsigned short best_device_nodes[MAX_DEVICE_LIST_SIZE];
};

int best_device_index ( unsigned short *best_device_nodes );

struct device_node {
  struct list_head list; 

  struct orig_node *orig_node;
  int device_node_index;     // set at init_device(), can be used to derive corresponding position in device_node_array

  unsigned long seqno;     // TBD: this number must be checked for wrap arounds 
  unsigned char flags;     // orig-flags to be broadcasted for this interface (orig-addess)
  unsigned char ttl;       // TTL to be broadcasted for this interface (orig-address)
  
  int int_flags;   // flags from interface while initialization
  int int_mtu;     // mtu of interface while initialization

  char arg_device[IFNAMSIZ];  // assigned name via parameter list
  char phy_device[IFNAMSIZ];  // physical name of interface (if virtual interfaces used)

  int snd_sock; //used for receiving as well
  struct sockaddr_in snd_broad;
  struct sockaddr_in mc_addr;
  //  struct ifreq snd_int_req;
  struct sockaddr_in snd_addr, snd_null;

  struct list_head forw_list; /* stores originator packets from other originators to be broadcasted via this device */
  int forw_list_size;
};

struct device_node device_node_array[MAX_DEVICE_LIST_SIZE];

/* 
 * an orig_node can be a 
 * a) far-away node: if ( (now - lastConfAsNb > arg_bidirectional_to_ms) && this_device_node == NULL )
 * b) neighbor node: if ( (now - lastConfAsNb < arg_bidirectional_to_ms) && this_device_node == NULL 
 * 																		&& via_device_node != NULL )
 * 					a neighbor node can be a router towards other nodes
 * c) one of this machines interfaces: if ( router==NULL && this_device_node != NULL 
 * 														&& via_device_node == NULL  )
 * 
 * */
struct orig_node 
{ 
  struct list_head list; 
  unsigned long addr; 
  struct timeval lastSeenAsNb[MAX_DEVICE_LIST_SIZE]; 
  struct timeval lastConfAsNb[MAX_DEVICE_LIST_SIZE];

  struct list_head pack_list;
  unsigned long maxSeqno;
  long min_originated_oview_tstmp; /* timestamp in ms since start of programm (from originator point of view) when first seen packet was originated */
  long min_originated_rview_tstmp; /* timestamp in ms since start of programm (from receiver point of view) when first seen packet was received */
  long minTtpc;


  /* received originator specific *************************/
  struct orig_node *configured_router; /* pointing to currently configured router (or NULL) for this node */
  //  struct helper_metric helper_metric;

  /* neighbor-node specific: ******************************/
  /* set while update_neigbor() TBD: this may fluctuate if receiving bidirectional neighbor indications from same neighbor via different interfaces (devices) */
  //  struct device_node *via_device_node;

  // set while findBestNeigh() and only valid for the moment
  // unsigned short last_best_device_nodes[MAX_DEVICE_LIST_SIZE];
  
  /* set while add_del_route(), to remember the device used for a certain route */
  struct device_node *configured_device_node;
  // unsigned short configured_device_nodes[MAX_DEVICE_LIST_SIZE];

  /* device specific:...***********************************/
  /* set once at program strartup and only for own orig_nodes*/
  struct device_node *this_device_node;
};

struct forw_node 
{ 
  struct list_head list; 
  struct timeval order;
  struct pack_node *pack_node;
};

static LIST_HEAD(orig_list);

static LIST_HEAD(to_list);

static LIST_HEAD(summary_list);




/********************************************************************
 * Helper functions and stuff
 */

             char   aGreaterB_us_wraparounds( unsigned short a_us, unsigned short b_us);

            float   avgTtl( struct summary_node *summary_node );

            float   avgTtl_dev( struct summary_node *summary_node, int dev_index );

            float   avgTtpc_dev( struct summary_node *summary_node, int dev_index );

             void   output(int importance, char *format, ...);

      static void   handler(int sig);

//      static void   finish(void);

      static void   usage(void);

              int   is_aborted();

             void  *alloc_memory(int len);

             void   free_memory(void *mem);

             void   addr_to_string(unsigned int addr, char *str, int len);

              int   rand_num(int limit);

             long   tv2time( struct timeval *tv );

             void   time2tv( struct timeval *tv, long time_ms );

             void   addTime2tv( struct timeval *tv, long time_ms );

             void   abs2relTv(  struct timeval *tv_abs,  struct timeval *tv_rel );

      static void   get_time_internal(struct timeval *tv);

static unsigned long   get_time( struct timeval *tv );

             void   set_forwarding(int state);

              int   get_forwarding(void);

             char   addrIsMine(  unsigned int neigh );

              int   jitter( int jitter );

              int   init_device( char *arg_device );

             void   apply_init_args( int argc, char** argv);

              int   process_arg( char *argp, char** argv, int argc);

             void   help();

             void   add_del_route( struct orig_node *dest_node, 
				   struct orig_node *router_node, 
				   int del,
				   struct device_node *via_device_node );

             void   output_route( char *orig_str, char* hop_str, struct orig_node *orig_node, int hmvdaPos, struct summary_node *summary_node);

             void   showRoutes( struct list_head *debug_orig_list );

             void   updateRoutes( struct orig_node *orig_node, struct best_route *best_route );

             void   delAllRoutes( void );

             void   closeAllSockets( void );

              int   batman(void);

              int   main(int ac, char **av);


/********************************************************************
 * Structures and Functions for orig-data processing and maintainance
 */

    unsigned char   origTreatmentFunc(struct orig_node *orig_node, 
				     struct packet_orig *in, 
				     struct orig_node *neigh_node, 
				     int rcvd_via_device_node_index );

 struct orig_node  *get_orig_node( unsigned int addr );

 struct orig_node  *update_neighbour(struct packet_orig *in, 
				     unsigned int neigh, 
				     int via_device_node_index,
				     struct timeval *received );

             void   purgePackNodes( struct orig_node *orig_node );

struct summary_node *getMetricNode( struct orig_node *orig_node );


             long   get_tripTimePlusConst ( struct pack_node *pack_node );

              int   updateHelperMetricsForOrig( struct orig_node *orig_node );

             void   findBestNeigh( struct orig_node *orig_node, struct best_route *best_route );

             void   updateOrigAPacketAForwARouteList( unsigned int neigh, 
						      struct packet_orig *in, 
						      short rcvd_via_device_node_item );
             void   purgePacketsAOrigsARoutes();


/********************************************************************
 * Functions for packet reception and sending
 */

             void   addToForwList( struct pack_node *pack_node, int delay, short via_device_node_item );

             void   addToAllForwLists( struct pack_node *pack_node, int delay );

              int   wait_for_packet(unsigned char *buff, 
				    int len, unsigned int *neigh,
				    int *rcvd_via_device_node_item,
				    struct timeval *tv_to_abs,
				    int *more_data );

             void   broadcastFwList( struct device_node *device_node );

              int   send_packet( unsigned char *buff, int len, struct device_node *device_node);

/*
returns remaining lifetime in ms (which is 0 in case of less than 1 ms)
of bidirectional link to given neigh_node and device_index
or -1 if exceeded or timed out
*/
              long  currentlyBidirectionalNeighFunc( struct orig_node *neigh_node,
						      int via_device_node_index );

 struct pack_node  *createOtherPackNode( unsigned char treatmentFlags,
					 struct orig_node *orig_node, 
					 struct orig_node *neigh_node,
					 struct device_node *via_device_node,
					 struct packet_orig *in, 
/* 					 struct timeval *ooptim_originated_rview_tstmp,  */
					 struct timeval *received );

 struct pack_node  *generateOwnPackNode( struct device_node * device_node );


/********************************************************************
 * Functions related to the state machine and its events
 */


#define EVENT_NO             0x00
#define EVENT_ORIG_INTERVAL  0x01
#define EVENT_TX_INTERVAL    0x02
#define EVENT_PURGE_INTERVAL 0x03
#define EVENT_FW_JITTER      0x04

char * debug_event( int event ) {
	if( event == EVENT_NO ) return "EVENT_NO";
	else if( event == EVENT_ORIG_INTERVAL ) return "EVENT_ORIG_INTERVAL";
	else if( event == EVENT_TX_INTERVAL ) return "EVENT_TX_INTERVAL";
	else if( event == EVENT_PURGE_INTERVAL ) return "EVENT_PURGE_INTERVAL";
	else if( event == EVENT_FW_JITTER ) return "EVENT_FW_JITTER";

 return "INVALID EVENT";
}

struct to_node 
{ 
  struct list_head list; 
  struct timeval to;
  short event;
  struct device_node *datap;
};

             void   debug_event_list( void );

             void   add_event_to( int event, 
				  struct device_node *datap, /*data not to be removed after event*/ 
				  unsigned long to_ms );   /* register event timeout in to_list */

              int   get_pend_event( struct device_node **datap ); /* gets pending and removes event from to_list */

             void   get_next_to( struct timeval *tv );     /* get next scheduled to in ms from to_list */

#endif
