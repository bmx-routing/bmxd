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
#include <sys/socket.h>
#include <sys/time.h>


#include "../batman.h"
#include "../os.h"
#include "../originator.h"
#include "../metrics.h"
#include "../control.h"
#include "../dispatch.h"




#define BAT_LOGO_PRINT(x,y,z) printf( "\x1B[%i;%iH%c", y + 1, x, z )                      /* write char 'z' into column 'x', row 'y' */
#define BAT_LOGO_END(x,y) printf("\x1B[8;0H");fflush(NULL);bat_wait( x, y );              /* end of current picture */
#define IOCREMDEV 2

# define timercpy(d, a) (d)->tv_sec = (a)->tv_sec; (d)->tv_usec = (a)->tv_usec; 



//static clock_t start_time;
static struct timeval start_time_tv;
static struct timeval ret_tv, new_tv, diff_tv, acceptable_m_tv, acceptable_p_tv, max_tv = {0,(2000*MAX_SELECT_TIMEOUT_MS)};




void fake_start_time( int32_t fake ) {
	start_time_tv.tv_sec-= fake;
}


uint32_t get_time( uint8_t msec, struct timeval *precise_tv ) {
	
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
	
	if ( precise_tv ) {
		precise_tv->tv_sec = ret_tv.tv_sec;
		precise_tv->tv_usec = ret_tv.tv_usec;
	}		
	
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


/* counting bits based on http://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetTable */

static unsigned char BitsSetTable256[256];

void init_set_bits_table256( void ) {
	BitsSetTable256[0] = 0;
	int i;
	for (i = 0; i < 256; i++)
	{
		BitsSetTable256[i] = (i & 1) + BitsSetTable256[i / 2];
	}
}

// count the number of true bits in v
uint8_t get_set_bits( uint32_t v ) {
	uint8_t c=0;

	for (; v; v = v>>8 )
		c += BitsSetTable256[v & 0xff];

	return c;
}





int8_t send_udp_packet( unsigned char *packet_buff, int32_t packet_buff_len, struct sockaddr_in *dst, int32_t send_sock ) {
	
	int status;
	
	if ( send_sock == 0 )
		return 0;
	
	/*	
	static struct iovec iov;
	iov.iov_base = packet_buff;
	iov.iov_len  = packet_buff_len;
	
	static struct msghdr m = { 0, sizeof( struct sockaddr_in ), &iov, 1, NULL, 0, 0 };
	m.msg_name = dst;
	
	status = sendmsg( send_sock, &m, 0 );
	*/
	
	status = sendto( send_sock, packet_buff, packet_buff_len, 0, (struct sockaddr *)dst, sizeof(struct sockaddr_in) );
		
	if ( status < 0 ) {
		
		if ( errno == 1 ) {

			debug_output(0, "Error - can't send udp packet: %s.\nDoes your firewall allow outgoing packets on port %i ?\n", strerror(errno), ntohs(dst->sin_port));

		} else {

			debug_output(0, "Error - can't send udp packet: %s\n", strerror(errno));

		}
		
		return -1;
		
	}

	return 0;

}



void segmentation_fault( int32_t sig ) {

	signal( SIGSEGV, SIG_DFL );

	debug_output( 0, "Error - SIGSEGV received, trying to clean up ... \n" );

	cleanup_all( CLEANUP_CONTINUE );

	raise( SIGSEGV );

}

static int cleaning_up = NO;

void cleanup_all( int status ) {
	
	if ( !cleaning_up ) {
	
		cleaning_up = YES;
	
		// first, restore defaults...

		stop = 1;
		
		stop_gw_service();
		gateway_class = 0;
	
		del_default_route();
		routing_class = 0;
		

		flush_tracked_rules_and_routes();
	
		purge_orig( 0 );
		
		restore_kernel_config( NULL );

		// if ever started succesfully in daemon mode...
		if ( !client_mode && batman_time > 0 ) {
			
			// flush orphan rules (and do warning in case)
			if ( !no_prio_rules )
				flush_routes_rules(1 /* flush rule */);
			
			// flush orphan routes (and do warning in case)
			flush_routes_rules(0 /* flush route */ );
		
		}

		// second, cleanup stuff which would be eliminated anyway...
		
		/* cleanup: gw_list,  my_hna_list,  my_srv_list 
		
		init_originator();
		init_profile();
		*/
		
		cleanup_dispatch();
	
		if ( vis_if )
			cleanup_vis();
	
#ifdef METRICTABLE
		cleanup_metric_table( global_mt );
#endif
		
		struct list_head *list_pos, *list_tmp;
		
		list_for_each_safe( list_pos, list_tmp, &notun_list ) {
	
			list_del( (struct list_head *)&notun_list, list_pos, &notun_list );
	
			debugFree( list_pos, 1224 );
	
		}
		
		list_for_each_safe( list_pos, list_tmp, &if_list ) {
			
			struct batman_if *batman_if = list_entry( list_pos, struct batman_if, list );
			
			if ( batman_if->if_active )
				deactivate_interface( batman_if );
	
			list_del( (struct list_head *)&if_list, list_pos, &if_list );
			debugFree( list_pos, 1214 );
	
		}
	
		add_del_own_hna( YES /*purge*/ );
		
		add_del_own_srv( YES /*purge*/ );

		purge_empty_hna_nodes( );
	
		cleanup_route();

		hash_destroy( hna_hash );

		hash_destroy( orig_hash );

		
		// last, close debugging system and check for forgotten resources...
		
		cleanup_control();
	
		checkLeak();
	
	}
		

	if ( status == CLEANUP_SUCCESS ) {
		
		exit( EXIT_SUCCESS );

	} else if ( status == CLEANUP_FAILURE ) {
		
		exit ( EXIT_FAILURE );
	
	} else if ( status == CLEANUP_CONTINUE ) {
		return;
	
	}

	exit ( EXIT_FAILURE );
	
}


int main( int argc, char *argv[] ) {

	/* check if user is root */
	if ( ( getuid() ) || ( getgid() ) ) {

		fprintf( stderr, "Error - you must be root to run %s !\n", argv[0] );
		exit(EXIT_FAILURE);

	}
	
	gettimeofday( &start_time_tv, NULL );
	gettimeofday( &new_tv, NULL );

	srand( getpid() );

	init_set_bits_table256();
	
#ifdef METRICTABLE
	global_mt = init_metric_table( MAX_BITS_RANGE, 1010, 1000 );
#endif
	
	init_originator();
	init_control();
	init_dispatch();
	init_profile();
	init_route();
	
	
	apply_init_args( argc, argv );

	check_kernel_config( NULL, YES/*init*/ );
	
	batman();

	cleanup_all( CLEANUP_SUCCESS );
	
	//should never reach here !!
	return -1;
}


