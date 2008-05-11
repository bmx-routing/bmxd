/*
 * Copyright (C) 2006 BATMAN contributors:
 * Thomas Lopatic, Marek Lindner, Axel Neumann
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



#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
//#include <sys/times.h>
#include <sys/time.h>
#include <sys/ioctl.h>


#include "../os.h"
#include "../batman.h"



#define BAT_LOGO_PRINT(x,y,z) printf( "\x1B[%i;%iH%c", y + 1, x, z )                      /* write char 'z' into column 'x', row 'y' */
#define BAT_LOGO_END(x,y) printf("\x1B[8;0H");fflush(NULL);bat_wait( x, y );              /* end of current picture */
#define IOCREMDEV 2

# define timercpy(d, a) (d)->tv_sec = (a)->tv_sec; (d)->tv_usec = (a)->tv_usec; 


extern struct vis_if vis_if;

//static clock_t start_time;
static struct timeval start_time_tv;
static float system_tick;
static struct timeval ret_tv, new_tv, diff_tv, acceptable_m_tv, acceptable_p_tv, max_tv = {0,(2000*MAX_SELECT_TIMEOUT_MS)};
static uint32_t my_ms_tick;

uint8_t forward_old, if_rp_filter_all_old, if_rp_filter_default_old, if_send_redirects_all_old, if_send_redirects_default_old;



char* get_init_string( int begin ){
	
#define INIT_STRING_SIZE 500
	
	char *dbg_init_str = debugMalloc( INIT_STRING_SIZE, 127 );
	int i, dbg_init_out = 0;
	
	for (i=0; i < g_argc; i++) {
		
		if ( i >= begin && INIT_STRING_SIZE > dbg_init_out) {
			dbg_init_out = dbg_init_out + snprintf( (dbg_init_str + dbg_init_out), (INIT_STRING_SIZE - dbg_init_out), "%s ", g_argv[i] );
		}
		
	}
	
	return dbg_init_str;

}



void fake_start_time( int32_t fake ) {
	start_time_tv.tv_sec-= fake;
}


uint32_t get_time( uint8_t msec ) {
	//struct tms tp;
	
	timeradd( &max_tv, &new_tv, &acceptable_p_tv );
	timercpy( &acceptable_m_tv, &new_tv );
	gettimeofday( &new_tv, NULL );
	
	if ( timercmp( &new_tv, &acceptable_p_tv, > ) ) {
		
		timersub( &new_tv, &acceptable_p_tv, &diff_tv );
		timeradd( &start_time_tv, &diff_tv, &start_time_tv );
		
		debug_log( "WARNING: Critical system time drift detected: ++ca %ld s, %ld us! Correcting reference! \n", diff_tv.tv_sec, diff_tv.tv_usec );
		
	} else 	if ( timercmp( &new_tv, &acceptable_m_tv, < ) ) {
		
		timersub( &acceptable_m_tv, &new_tv, &diff_tv );
		timersub( &start_time_tv, &diff_tv, &start_time_tv );
		
		debug_log( "WARNING: Critical system time drift detected: --ca %ld s, %ld us! Correcting reference! \n", diff_tv.tv_sec, diff_tv.tv_usec );

	}
	
	timersub( &new_tv, &start_time_tv, &ret_tv );	
	
	if (  msec )
		return ( (ret_tv.tv_sec * 1000) + (ret_tv.tv_usec / 1000) );
	else
		return ret_tv.tv_sec;

}


/* batman animation */
void sym_print( char x, char y, char *z ) {

	char i = 0, Z;

	do{

		BAT_LOGO_PRINT( 25 + (int)x + (int)i, (int)y, z[(int)i] );

		switch ( z[(int)i] ) {

			case 92:
				Z = 47;   // "\" --> "/"
				break;

			case 47:
				Z = 92;   // "/" --> "\"
				break;

			case 41:
				Z = 40;   // ")" --> "("
				break;

			default:
				Z = z[(int)i];
				break;

		}

		BAT_LOGO_PRINT( 24 - (int)x - (int)i, (int)y, Z );
		i++;

	} while( z[(int)i - 1] );

	return;

}



void bat_wait( int32_t T, int32_t t ) {

	struct timeval time;

	time.tv_sec = T;
	time.tv_usec = ( t * 10000 );

	select( 0, NULL, NULL, NULL, &time );

	return;

}



void print_animation( void ) {

	system( "clear" );
	BAT_LOGO_END( 0, 50 );

	sym_print( 0, 3, "." );
	BAT_LOGO_END( 1, 0 );

	sym_print( 0, 4, "v" );
	BAT_LOGO_END( 0, 20 );

	sym_print( 1, 3, "^" );
	BAT_LOGO_END( 0, 20 );

	sym_print( 1, 4, "/" );
	sym_print( 0, 5, "/" );
	BAT_LOGO_END( 0, 10 );

	sym_print( 2, 3, "\\" );
	sym_print( 2, 5, "/" );
	sym_print( 0, 6, ")/" );
	BAT_LOGO_END( 0, 10 );

	sym_print( 2, 3, "_\\" );
	sym_print( 4, 4, ")" );
	sym_print( 2, 5, " /" );
	sym_print( 0, 6, " )/" );
	BAT_LOGO_END( 0, 10 );

	sym_print( 4, 2, "'\\" );
	sym_print( 2, 3, "__/ \\" );
	sym_print( 4, 4, "   )" );
	sym_print( 1, 5, "   " );
	sym_print( 2, 6, "   /" );
	sym_print( 3, 7, "\\" );
	BAT_LOGO_END( 0, 15 );

	sym_print( 6, 3, " \\" );
	sym_print( 3, 4, "_ \\   \\" );
	sym_print( 10, 5, "\\" );
	sym_print( 1, 6, "          \\" );
	sym_print( 3, 7, " " );
	BAT_LOGO_END( 0, 20 );

	sym_print( 7, 1, "____________" );
	sym_print( 7, 3, " _   \\" );
	sym_print( 3, 4, "_      " );
	sym_print( 10, 5, " " );
	sym_print( 11, 6, " " );
	BAT_LOGO_END( 0, 25 );

	sym_print( 3, 1, "____________    " );
	sym_print( 1, 2, "'|\\   \\" );
	sym_print( 2, 3, " /         " );
	sym_print( 3, 4, " " );
	BAT_LOGO_END( 0, 25 );

	sym_print( 3, 1, "    ____________" );
	sym_print( 1, 2, "    '\\   " );
	sym_print( 2, 3, "__/  _   \\" );
	sym_print( 3, 4, "_" );
	BAT_LOGO_END( 0, 35 );

	sym_print( 7, 1, "            " );
	sym_print( 7, 3, " \\   " );
	sym_print( 5, 4, "\\    \\" );
	sym_print( 11, 5, "\\" );
	sym_print( 12, 6, "\\" );
	BAT_LOGO_END( 0 ,35 );

}



void addr_to_string( uint32_t addr, char *str, int32_t len ) {

	inet_ntop( AF_INET, &addr, str, len );

}



int32_t rand_num( uint32_t limit ) {

	return ( limit == 0 ? 0 : rand() % limit );

}



int8_t is_aborted() {

	return stop != 0;

}



void handler( int32_t sig ) {

	stop = 1;

}

void del_default_route() {

	curr_gateway = NULL;

	if ( curr_gateway_thread_id != 0 ) {
		if ( pthread_join( curr_gateway_thread_id, NULL ) != 0 )
			debug_output( 0, "Error - couldn't completely join thread, %s! \n", strerror(errno));
		
		curr_gateway_thread_id = 0;
	}
}



int8_t add_default_route( struct gw_node *new_curr_gw ) {

	struct curr_gw_data *curr_gw_data;

	del_default_route();
	
	curr_gateway = new_curr_gw;
	
	curr_gw_data = debugMalloc( sizeof(struct curr_gw_data), 207 );
	curr_gw_data->gw_node = new_curr_gw;
	curr_gw_data->orig = new_curr_gw->orig_node->orig;
	curr_gw_data->batman_if = list_entry( (&if_list)->next , struct batman_if, list );

	if ( pthread_create( &curr_gateway_thread_id, NULL, &client_to_gw_tun, curr_gw_data ) != 0 ) {

		debug_output( 0, "Error - couldn't spawn thread: %s\n", strerror(errno) );
		debugFree( curr_gw_data, 1207 );
		curr_gateway = NULL;
		curr_gateway_thread_id=0;
	}

	return 1;

}

int8_t receive_packet( uint32_t timeout ) {
	
	prof_start( PROF_receive_packet );

	static unsigned char packet_in[2001];
	static unsigned char *pos = NULL, *check_pos;
	static int32_t len = 0, check_len, check_done;
	static uint32_t rcvd_neighbor = 0, rcvd_time = 0, last_get_time_result = 0;

	
	static char str[ADDR_STR_LEN];
	static char str2[ADDR_STR_LEN];
	
	struct sockaddr_in addr;
	uint32_t addr_len;
	uint32_t return_time = *received_batman_time + timeout;
	struct timeval tv;
	struct list_head *if_pos;
	static struct batman_if *batman_if = NULL;
	int8_t res;
	int16_t left_pos, ext_type, done_pos, ext_pos;
	struct ext_packet *ext_array;
	fd_set tmp_wait_set;
	
	
	
	debug_output(4, "receive_packet() remaining len %d, timeout %d \n", len, timeout );
	
	if( len != 0 && len < sizeof( struct bat_packet_common ) ) {
		
		addr_to_string( rcvd_neighbor, str, sizeof(str) );
		debug_output(0, "Drop packet: processing strange packet buffer size. %i from: %s !!!!!!!!!!!!!!\n", len, str );
		len = 0;
		
		prof_stop( PROF_receive_packet );
		return -1;
	}


	while ( len < sizeof( struct bat_packet_common ) ) {
		
		pos = packet_in;

		addr_len = sizeof(struct sockaddr_in);
		memcpy( &tmp_wait_set, &receive_wait_set, sizeof(fd_set) );
		
		tv.tv_sec  =   (return_time - *received_batman_time) / 1000;
		tv.tv_usec = ( (return_time - *received_batman_time) % 1000 ) * 1000;
		
		res = select( receive_max_sock + 1, &tmp_wait_set, NULL, NULL, &tv );
		
		s_returned_select++;

		*received_batman_time = rcvd_time = get_time_msec();
		
		
		
		if ( *received_batman_time < last_get_time_result ) {
			
			len = 0;
			last_get_time_result = *received_batman_time;
			debug_output( 0, "WARNING - Detected Timeoverlap...\n" );
			prof_stop( PROF_receive_packet );
			return 0;
			
		}
		
		last_get_time_result = *received_batman_time;
		
		
				
		if ( res < 0 && errno != EINTR ) {
		
			debug_output( 0, "Error - can't select: %s\n", strerror(errno) );
			prof_stop( PROF_receive_packet );
			return -1;
		}
			
		if ( res <= 0 ) {
			
			/*Often select returns just a few milliseconds before being scheduled */
			if ( return_time < *received_batman_time + 10 ) {
				
				//cheating time :-)
				*received_batman_time = rcvd_time = return_time;
				
				prof_stop( PROF_receive_packet );
				return 0;
				
			} else {
				
				debug_output( 3, "Select returned %d without reason!! return_time %d, curr_time %d\n", res, return_time, *received_batman_time );
				continue;
			}
		}
		
		
		if ( FD_ISSET( ifevent_sk, &tmp_wait_set ) ) {
			
			debug_output( 3, "Select indicated changed interface status! going to check interfaces! \n" );
			recv_ifevent_netlink_sk( );
			check_interfaces();
			
		}
		
		
		
		list_for_each( if_pos, &if_list ) {
		
			batman_if = list_entry( if_pos, struct batman_if, list );
		
			if ( FD_ISSET( batman_if->udp_recv_sock, &tmp_wait_set ) ) {
		
				len = recvfrom( batman_if->udp_recv_sock, pos, sizeof(packet_in) - 1, 0, (struct sockaddr *)&addr, &addr_len );

				if ( len < 0 ) {
		
					debug_output( 0, "Error - can't receive packet: %s\n", strerror(errno) );
					
					prof_stop( PROF_receive_packet );
					return -1;
				}
				
				(*received_if_incoming) = batman_if;
				
				rcvd_neighbor = addr.sin_addr.s_addr;
		
				break;
			}
		}
		
		if ( len > 0 && rcvd_neighbor == batman_if->addr.sin_addr.s_addr ) {
			
			addr_to_string( rcvd_neighbor, str, sizeof(str) );
			debug_output( 4, "Drop packet: received my own broadcast (sender: %s) \n", str );

			len = 0;
			
			if ( return_time > *received_batman_time ) {
				continue;
			} else {
				prof_stop( PROF_receive_packet );
				return 0;
			}
				
		}
		
		if ( len < sizeof(struct bat_header) + sizeof(struct bat_packet_common) ) {
			
			len = 0;
			
			if ( return_time > *received_batman_time ) {
				continue;
			} else {
				prof_stop( PROF_receive_packet );
				return 0;
			}
		
		}
	
		// we acceppt longer packets than specified by pos->size to allow padding for equal packet sizes
		if ( 	len < (sizeof(struct bat_header) + sizeof(struct bat_packet_common))  ||
			(((struct bat_header *)pos)->version) != COMPAT_VERSION  ||
			((((struct bat_header *)pos)->size)<<2) > len )   {
		
			addr_to_string( rcvd_neighbor, str, sizeof(str) );
		
			if ( len >= (sizeof(struct bat_header) + sizeof(struct bat_packet_common)) )
				debug_output( 0, "WARNING - Drop packet: rcvd incompatible batman version or size %i, flags? %X, size? %i, via NB %s. My version is %d \n", ((struct bat_header *)pos)->version, ((struct bat_packet_common *)(pos+sizeof(struct bat_header)))->reserved1, len, str, COMPAT_VERSION );
				
			else
				debug_output( 0, "Error - Rcvd to small packet size %i, via NB %s.\n", len, str );
			
			len = 0;
			
			if ( return_time > *received_batman_time ) {
				
				continue;
				
			} else {
			
				prof_stop( PROF_receive_packet );
				return 0;
			}
		
		}
	
		s_received_aggregations++;
		
		
		check_len = len = ((((struct bat_header *)pos)->size)<<2) - sizeof( struct bat_header );
		check_pos = pos = pos + sizeof(struct bat_header);
		
		
		/* fast plausibility check */
		check_done = 0;
		
		while ( check_done < check_len ) {
			
			if ( check_len < sizeof( struct bat_packet_common ) ) {
		
				debug_output(0, "Error - Recvfrom returned with absolutely to small packet length %d !!!! \n", check_len );
				prof_stop( PROF_receive_packet );
				return -1;
			}
			
			if ( 	(((struct bat_packet_common *)check_pos)->ext_msg) != 0 ||
				(((struct bat_packet_common *)check_pos)->size)    == 0 ||
				((((struct bat_packet_common *)check_pos)->size)<<2) > check_len  ) {

				addr_to_string( rcvd_neighbor, str, sizeof(str) );
		
				if (	(((struct bat_packet_common *)check_pos)->ext_msg) == 0 &&
					((((struct bat_packet_common *)check_pos)->size)<<2) >= sizeof( struct bat_packet ) &&
					check_len >= sizeof( struct bat_packet )  )
					addr_to_string( ((struct bat_packet *)check_pos)->orig, str2, sizeof(str2) );
			
				else
					addr_to_string( 0, str2, sizeof(str2) );
		
				debug_output(0, "Error - Drop jumbo packet: rcvd incorrect size or order: ext_msg %d, reserved %X, OGM size field %d aggregated OGM size %i, via IF: %s, NB %s, Originator? %s. \n",  ((struct bat_packet_common *)check_pos)->ext_msg, ((struct bat_packet_common *)check_pos)->reserved1, ((((struct bat_packet_common *)check_pos)->size)), check_len, batman_if->dev, str, str2);
		
				len = 0;
		
				prof_stop( PROF_receive_packet );
				return 0;
			}
			
			check_done = check_done + ((((struct bat_packet_common *)check_pos)->size)<<2) ;
			check_pos  = check_pos  + ((((struct bat_packet_common *)check_pos)->size)<<2) ;
			
		}
		
		if ( check_len != check_done ) {
			
			debug_output(0, "Error - Drop jumbo packet: End of packet does not match indicated size \n");
			
			len = 0;
		
			prof_stop( PROF_receive_packet );
			return 0;
			
		}
		
		break;
		
	}
	
				
	*received_batman_time = rcvd_time;
		
	
	
	if ( ((struct bat_packet_common *)pos)->bat_type == BAT_TYPE_OGM  ) {
		
		((struct bat_packet *)pos)->seqno = ntohs( ((struct bat_packet *)pos)->seqno ); /* network to host order for our 16bit seqno. */

		*received_neigh = rcvd_neighbor;

		*received_ogm = (struct bat_packet *)pos;
	
		*received_batman_time = rcvd_time;
	
	
		/* process optional gateway extension messages */
	
		left_pos  = (len - sizeof(struct bat_packet)) / sizeof(struct ext_packet);
		done_pos  = 0;
	
		*received_gw_array = NULL;
		*received_gw_pos   = 0;
	
		*received_hna_array = NULL;
		*received_hna_pos = 0;

		*received_srv_array = NULL;
		*received_srv_pos = 0;
	
		*received_vis_array = NULL;
		*received_vis_pos = 0;
	
		*received_pip_array = NULL;
		*received_pip_pos = 0;

		ext_type = 0;
	
		ext_array = (struct ext_packet *) (pos + sizeof(struct bat_packet) + (done_pos * sizeof(struct ext_packet)) );
		ext_pos = 0;
	
		while ( done_pos < left_pos && 
			(done_pos * sizeof(struct ext_packet))  <  ((((struct bat_packet_common *)pos)->size)<<2) &&
			((ext_array)[0]).EXT_FIELD_MSG == YES && 
			ext_type <= EXT_TYPE_MAX ) {
		
			while( (ext_pos + done_pos) < left_pos && ((ext_array)[ext_pos]).EXT_FIELD_MSG == YES ) {
			
				if ( ((ext_array)[ext_pos]).EXT_FIELD_TYPE == ext_type  ) {
				
					(ext_pos)++;
				
				} else if ( ((ext_array)[ext_pos]).EXT_FIELD_TYPE > ext_type  ) {
				
					break;
				
				} else {
				
					debug_output( 0, "Drop packet: rcvd incompatible extension message order: size? %i, ext_type %d, via NB %s, originator? %s. \n",  
							len, ((ext_array)[ext_pos]).EXT_FIELD_TYPE, str, str2 );
					len = 0;
					
					prof_stop( PROF_receive_packet );
					return 0;
				}
				
			}

			done_pos = done_pos + ext_pos;
		
			if ( ext_pos != 0 ) {
			
				if ( ext_type == EXT_TYPE_GW ) {
				
					*received_gw_array = ext_array;
					*received_gw_pos = ext_pos;
				
				} else if ( ext_type == EXT_TYPE_HNA ) {
				
					*received_hna_array = ext_array;
					*received_hna_pos = ext_pos;
				
				} else if ( ext_type == EXT_TYPE_SRV ) {
				
					*received_srv_array = ext_array;
					*received_srv_pos = ext_pos;
				
				} else if ( ext_type == EXT_TYPE_VIS ) {
				
					*received_vis_array = ext_array;
					*received_vis_pos = ext_pos;
				
				} else if ( ext_type == EXT_TYPE_PIP ) {
				
					*received_pip_array = ext_array;
					*received_pip_pos = ext_pos;
				
				}
			
			}
	
			ext_array = (struct ext_packet *) (pos + sizeof(struct bat_packet) + (done_pos * sizeof(struct ext_packet)) );
			ext_pos = 0;
			ext_type++;
	
		}
		
		s_received_ogms++;
		
		
		if ( (sizeof(struct bat_packet) + (done_pos * sizeof(struct ext_packet)))  !=  ((((struct bat_packet_common *)pos)->size)<<2) ) {
			
			len = len - ((((struct bat_packet_common *)pos)->size)<<2);
			pos = pos + ((((struct bat_packet_common *)pos)->size)<<2);
		
			debug_output( 0, "WARNING - Drop packet! Received corrupted packet size: processed bytes: %d , indicated bytes %d, batman flags. %X,  gw_pos %d, hna_pos: %d, srv_pos %d, pip_pos %d, remaining bytes %d \n", (sizeof(struct bat_packet) + (done_pos * sizeof(struct ext_packet))), ((((struct bat_packet_common *)pos)->size)<<2), ((struct bat_packet *)pos)->flags, *received_gw_pos, *received_hna_pos, *received_srv_pos, *received_pip_pos, len );
			
			prof_stop( PROF_receive_packet );
			return 0;
			
		}

	
		/* prepare for next ogm and attached extension messages */
	
		len = len - ((((struct bat_packet_common *)pos)->size)<<2);
		pos = pos + ((((struct bat_packet_common *)pos)->size)<<2);
		
		debug_output( 4, "Received packet batman flags. %X,  gw_pos %d, hna_pos: %d, srv_pos %d, pip_pos %d, remaining bytes %d \n", ((struct bat_packet *)pos)->flags, *received_gw_pos, *received_hna_pos, *received_srv_pos, *received_pip_pos, len );
		
		prof_stop( PROF_receive_packet );
		return 1;
		
	} else {
		
		
		addr_to_string( rcvd_neighbor, str, sizeof(str) );
		addr_to_string( ((struct bat_packet *)pos)->orig, str2, sizeof(str2) );
		
		debug_output( 0, "WARNING - Drop single unkown bat_type bat_type %X, size? %i, via NB %s, originator? %s. \n",  ((struct bat_packet_common *)pos)->bat_type, len, str, str2 );
		
		len = len - ((((struct bat_packet_common *)pos)->size)<<2) ;
		pos = pos + ((((struct bat_packet_common *)pos)->size)<<2) ;
	
		prof_stop( PROF_receive_packet );
		return 0;
	}

	len = 0;
	
	prof_stop( PROF_receive_packet );
	return 0;	

}



int8_t send_udp_packet( unsigned char *packet_buff, int32_t packet_buff_len, struct sockaddr_in *broad, int32_t send_sock, struct batman_if *batman_if ) {
	
	if ((batman_if != NULL) && (!batman_if->if_active))
		return 0;

	if ( sendto( send_sock, packet_buff, packet_buff_len, 0, (struct sockaddr *)broad, sizeof(struct sockaddr_in) ) < 0 ) {

		
		if ( errno == 1 ) {

			debug_output(0, "Error - can't send udp packet: %s.\nDoes your firewall allow outgoing packets on port %i ?\n", strerror(errno), ntohs(broad->sin_port));

		} else {

			debug_output(0, "Error - can't send udp packet: %s\n", strerror(errno));

		}
		
		return -1;
		
	}

	return 0;

}



void restore_defaults() {

	struct list_head *if_pos, *if_pos_tmp;

	stop = 1;

	add_del_interface_rules( 1, (routing_class > 0 ? YES : NO), YES );
	
	stop_gw_service();

	del_default_route();
	
	list_for_each_safe( if_pos, if_pos_tmp, &if_list ) {
		
		struct batman_if *batman_if = list_entry( if_pos, struct batman_if, list );
		
		deactivate_interface( batman_if );

		list_del( (struct list_head *)&if_list, if_pos, &if_list );
		debugFree( if_pos, 1214 );

	}
	
	/* delete rule for hosts and announced interfaces */
	if( !more_rules  &&  !no_prio_rules ) {
	
		add_del_rule( 0, 0, BATMAN_RT_TABLE_INTERFACES, BATMAN_RT_PRIO_INTERFACES, 0, 1, 1 );
		add_del_rule( 0, 0, BATMAN_RT_TABLE_HOSTS, BATMAN_RT_PRIO_HOSTS, 0, 1, 1 );
		
	}

	
	/* delete rule for hna networks */
	if( !no_prio_rules )
		add_del_rule( 0, 0, BATMAN_RT_TABLE_NETWORKS,   BATMAN_RT_PRIO_NETWORKS,   0, 1, 1 );

	/* delete unreachable routing table entry */
	if ( !no_unreachable_rule )
		add_del_route( 0, 0, 0, 0, 0, "unknown", BATMAN_RT_TABLE_UNREACH, 2, 1 );

	
	if ( vis_if.sock )
		close( vis_if.sock );

	if ( unix_if.unix_sock )
		close( unix_if.unix_sock );

	if ( unix_if.listen_thread_id != 0 ) {
		pthread_join( unix_if.listen_thread_id, NULL );
		unix_if.listen_thread_id = 0;
	}
	
	if ( debug_level == 0 )
		closelog();
	
	set_forwarding( forward_old );

	set_rp_filter( if_rp_filter_all_old, "all" );
	set_rp_filter( if_rp_filter_default_old, "default" );

	set_send_redirects( if_send_redirects_all_old, "all" );
	set_send_redirects( if_send_redirects_default_old, "default" );


}



void restore_and_exit( uint8_t is_sigsegv ) {

	struct orig_node *orig_node;
	struct hash_it_t *hashit = NULL;

	if ( !conn_client ) {

		/* remove tun interface first */
		stop = 1;

		restore_defaults();

		/* all rules and routes were purged in segmentation_fault() */
		if ( !is_sigsegv ) {

			while ( NULL != ( hashit = hash_iterate( orig_hash, hashit ) ) ) {

				orig_node = hashit->bucket->data;

				update_routes( orig_node, NULL, NULL, 0 );

			}

		}

		//restore_defaults();

	}

	if ( !is_sigsegv )
		exit(EXIT_FAILURE);

}



void segmentation_fault( int32_t sig ) {

	signal( SIGSEGV, SIG_DFL );

	debug_output( 0, "Error - SIGSEGV received, trying to clean up ... \n" );

	flush_routes_rules(0 /* flush route */ );
	
	if ( !no_prio_rules )
		flush_routes_rules(1 /* flush rule */);

	restore_and_exit(1);

	raise( SIGSEGV );

}



void cleanup() {

	int8_t i;
	struct debug_level_info *debug_level_info;
	struct list_head *debug_pos, *debug_pos_tmp;
	
	debugFree( todo_mutex, 1229 );


	for ( i = 0; i < debug_level_max; i++ ) {

		if ( debug_clients.clients_num[i] > 0 ) {

			list_for_each_safe( debug_pos, debug_pos_tmp, (struct list_head *)debug_clients.fd_list[i] ) {

				debug_level_info = list_entry(debug_pos, struct debug_level_info, list);

				list_del( (struct list_head *)debug_clients.fd_list[i], debug_pos, (struct list_head_first *)debug_clients.fd_list[i] );
				debugFree( debug_pos, 1218 );

			}

		}

		debugFree( debug_clients.fd_list[i], 1219 );
		debugFree( debug_clients.mutex[i], 1220 );

	}

	debugFree( debug_clients.fd_list, 1221 );
	debugFree( debug_clients.mutex, 1222 );
	debugFree( debug_clients.clients_num, 1223 );

}



int main( int argc, char *argv[] ) {

	int8_t res;
	//struct tms tp;
	
	g_argc = argc;
	g_argv = argv;
	

	/* check if user is root */
	if ( ( getuid() ) || ( getgid() ) ) {

		fprintf( stderr, "Error - you must be root to run %s !\n", argv[0] );
		exit(EXIT_FAILURE);

	}


	INIT_LIST_HEAD_FIRST( forw_list );
	INIT_LIST_HEAD_FIRST( gw_list );
	INIT_LIST_HEAD_FIRST( notun_list );
	INIT_LIST_HEAD_FIRST( if_list );
	INIT_LIST_HEAD_FIRST( my_hna_list );
	INIT_LIST_HEAD_FIRST( my_srv_list );
	INIT_LIST_HEAD_FIRST( todo_list );
	INIT_LIST_HEAD_FIRST( link_list );
	INIT_LIST_HEAD_FIRST( pifnb_list );

	/* for profiling the functions */
	prof_init( PROF_all, "all" );
	prof_init( PROF_choose_gw, "choose_gw" );
	prof_init( PROF_update_routes, "update_routes" );
	prof_init( PROF_update_gw_list, "update_gw_list" );
	prof_init( PROF_is_duplicate, "isDuplicate" );
	prof_init( PROF_get_orig_node, "get_orig_node" );
	prof_init( PROF_update_originator, "update_orig" );
	prof_init( PROF_purge_originator, "purge_orig" );
	prof_init( PROF_schedule_forward_packet, "schedule_forward_packet" );
	prof_init( PROF_send_outstanding_packets, "send_outstanding_packets" );
	prof_init( PROF_receive_packet, "receive_packet" );
	prof_init( PROF_set_dbg_rcvd_all_bits, "set_dbg_rcvd_all_bits" );
	
	
	todo_mutex = debugMalloc( sizeof(pthread_mutex_t), 229 );
	pthread_mutex_init( (pthread_mutex_t *)todo_mutex, NULL );

	//start_time = times(&tp);
	gettimeofday( &start_time_tv, NULL );
	gettimeofday( &new_tv, NULL );

	system_tick = (float)sysconf(_SC_CLK_TCK);
	
	my_ms_tick = (1000/sysconf(_SC_CLK_TCK));
	
	if ( my_ms_tick == 0 ) {
		
		fprintf( stderr, "Error - System SC_CLK_TCK greater than 1000! Unexpected Systemvalue! Contact a developer to fix this for your system !\n" );
		exit(EXIT_FAILURE);

	}

	//printf(" some values: sizeof clock_t %d, system_tick %f %ld start_time %ld \n", sizeof(clock_t), system_tick, sysconf(_SC_CLK_TCK), start_time );
	
	srand( getpid() );
	
	if( open_netlink_socket() < 0 )
		exit(EXIT_FAILURE);
	
	if ( open_ifevent_netlink_sk() < 0 )
		exit(EXIT_FAILURE);
	
	apply_init_args( argc, argv );

	if_rp_filter_all_old = get_rp_filter( "all" );
	if_rp_filter_default_old = get_rp_filter( "default" );

	if_send_redirects_all_old = get_send_redirects( "all" );
	if_send_redirects_default_old = get_send_redirects( "default" );

	set_rp_filter( 0, "all" );
	set_rp_filter( 0, "default" );

	set_send_redirects( 0, "all" );
	set_send_redirects( 0, "default" );
		
	forward_old = get_forwarding();
	set_forwarding(1);

	
	char *init_string = get_init_string( 0 );
	
	debug_output(0, "Startup parameters: %s\n", init_string);
	
	debugFree( init_string, 1127 );


	
	res = batman();


	restore_defaults();
	
	close_ifevent_netlink_sk();	
	close_netlink_socket();
	
	cleanup();
	
	
	checkLeak();
	return res;

}


