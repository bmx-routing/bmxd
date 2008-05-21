/*
 * Copyright (C) 2006 BATMAN contributors:
 * Marek Lindner
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



#include <unistd.h>       /* close() */
#include <fcntl.h>        /* open(), O_RDWR */
#include <errno.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>   /* iph */
#include <linux/if_tun.h> /* TUNSETPERSIST, ... */
#include <linux/if.h>     /* ifr_if, ifr_tun */
#include <sys/socket.h>
#include <stdio.h>

#include "../os.h"
#include "../batman.h"

static int32_t batman_tun_index = 0;


/* Probe for tun interface availability */
int8_t probe_tun(uint8_t print_to_stderr) {

	int32_t fd;

	if ( ( fd = open( "/dev/net/tun", O_RDWR ) ) < 0 ) {

		if (print_to_stderr)
			fprintf( stderr, "Error - could not open '/dev/net/tun' ! Is the tun kernel module loaded ?\n" );
		else
			debug_output( 0, "Error - could not open '/dev/net/tun' ! Is the tun kernel module loaded ?\n" );
		
		return 0;

	}

	close( fd );

	return 1;

}



int8_t del_dev_tun( int32_t fd ) {

	if ( no_tun_persist == NO ) {
		
		if ( ioctl( fd, TUNSETPERSIST, 0 ) < 0 ) {
	
			debug_output( 0, "Error - can't delete tun device: %s\n", strerror(errno) );
			return -1;
	
		}
		
	}

	close( fd );

//	batman_tun_index--;
	
	return 1;

}



int8_t add_dev_tun(  uint32_t tun_addr, char *tun_dev, size_t tun_dev_size, int32_t *fd, int32_t *ifi ) {

	int32_t tmp_fd, sock_opts;
	struct ifreq ifr_tun, ifr_if;
	struct sockaddr_in addr;

	/* set up tunnel device */
	memset( &ifr_if, 0, sizeof(ifr_if) );

	
	if ( ( *fd = open( "/dev/net/tun", O_RDWR ) ) < 0 ) {

		debug_output( 0, "Error - can't open tun device (/dev/net/tun): %s\n", strerror(errno) );
		return -1;

	}

	batman_tun_index = 0;
	uint8_t name_tun_success = NO;
	
	while ( batman_tun_index < MAX_BATMAN_TUN_INDEX && !name_tun_success ) {
		
		memset( &ifr_tun, 0, sizeof(ifr_tun) );
		ifr_tun.ifr_flags = IFF_TUN | IFF_NO_PI;
		sprintf( ifr_tun.ifr_name, "%s%d", BATMAN_TUN_PREFIX, batman_tun_index++ );
		
		debug_output( 0, "Trying to name tunnel to %s ... \n", ifr_tun.ifr_name );
		
		if ( ( ioctl( *fd, TUNSETIFF, (void *) &ifr_tun ) ) < 0 ) {
	
			debug_output( 0, "busy!\n" );
	
		} else {
			
			name_tun_success = YES;
			debug_output( 0, "success!\n" );
		}
		
	}
	
	if ( !name_tun_success ) {
		
		debug_output( 0, "Error - can't create tun device (TUNSETIFF): %s\n", strerror(errno) );
		
		debug_output( 0, "Error - Giving up !\n" );
		close(*fd);
		return -1;
		
	}
	
	if( no_tun_persist == NO ) {
		
		if ( ioctl( *fd, TUNSETPERSIST, 1 ) < 0 ) {
	
			debug_output( 0, "Error - can't create tun device (TUNSETPERSIST): %s\n", strerror(errno) );
			close(*fd);
			return -1;
	
		}
	
	}

	tmp_fd = socket( AF_INET, SOCK_DGRAM, 0 );

	if ( tmp_fd < 0 ) {
		debug_output( 0, "Error - can't create tun device (udp socket): %s\n", strerror(errno) );
		del_dev_tun( *fd );
		return -1;
	}


	/* set ip of this end point of tunnel */
	memset( &addr, 0, sizeof(addr) );
	addr.sin_addr.s_addr = tun_addr;
	addr.sin_family = AF_INET;
	memcpy( &ifr_tun.ifr_addr, &addr, sizeof(struct sockaddr) );


	if ( ioctl( tmp_fd, SIOCSIFADDR, &ifr_tun) < 0 ) {

		debug_output( 0, "Error - can't create tun device (SIOCSIFADDR): %s\n", strerror(errno) );
		del_dev_tun( *fd );
		close( tmp_fd );
		return -1;

	}


	if ( ioctl( tmp_fd, SIOCGIFINDEX, &ifr_tun ) < 0 ) {

		debug_output( 0, "Error - can't create tun device (SIOCGIFINDEX): %s\n", strerror(errno) );
		del_dev_tun( *fd );
		close( tmp_fd );
		return -1;

	}

	*ifi = ifr_tun.ifr_ifindex;

	if ( ioctl( tmp_fd, SIOCGIFFLAGS, &ifr_tun) < 0 ) {

		debug_output( 0, "Error - can't create tun device (SIOCGIFFLAGS): %s\n", strerror(errno) );
		del_dev_tun( *fd );
		close( tmp_fd );
		return -1;

	}

	ifr_tun.ifr_flags |= IFF_UP;
	ifr_tun.ifr_flags |= IFF_RUNNING;

	if ( ioctl( tmp_fd, SIOCSIFFLAGS, &ifr_tun) < 0 ) {

		debug_output( 0, "Error - can't create tun device (SIOCSIFFLAGS): %s\n", strerror(errno) );
		del_dev_tun( *fd );
		close( tmp_fd );
		return -1;

	}

	/* find smallest MTU from real interfaces */
	struct list_head *if_pos;
	int mtu_min = 1500;
	list_for_each(if_pos, &if_list) {
			
		struct batman_if *batman_if = list_entry(if_pos, struct batman_if, list);
		
		if ( batman_if->if_active ) {
			
			strncpy( ifr_if.ifr_name, batman_if->dev, IFNAMSIZ - 1 );
		
			if ( ioctl( tmp_fd, SIOCGIFMTU, &ifr_if ) < 0 ) {
		
				debug_output( 0, "Error - can't get SIOCGIFMTU from device %s: %s\n",
						batman_if->dev, strerror(errno) );
				del_dev_tun( *fd );
				close( tmp_fd );
				return -1;
		
			}
			
			if( mtu_min > ifr_if.ifr_mtu ) 
				mtu_min = ifr_if.ifr_mtu;
		debug_output( 3, "searching min. MTU, so fare: %d, current dev %s, mtu: %d \n", mtu_min, batman_if->dev, ifr_if.ifr_mtu);
		
		}				
	}


	/* set MTU of tun interface: real MTU - 29 */
	if ( mtu_min < 100 ) {

		debug_output( 0, "Warning - MTU min smaller than 100 -> can't reduce MTU anymore\n" );
		del_dev_tun( *fd );
		close( tmp_fd );
		return -1;

	} else {

		ifr_tun.ifr_mtu = mtu_min - 29;

		if ( ioctl( tmp_fd, SIOCSIFMTU, &ifr_tun ) < 0 ) {

			debug_output( 0, "Error - can't set SIOCSIFMTU for device %s: %s\n", 
				      ifr_tun.ifr_name, strerror(errno) );
			del_dev_tun( *fd );
			close( tmp_fd );
			return -1;

		}

	}


	/* make tun socket non blocking */
	sock_opts = fcntl( *fd, F_GETFL, 0 );
	fcntl( *fd, F_SETFL, sock_opts | O_NONBLOCK );


	strncpy( tun_dev, ifr_tun.ifr_name, tun_dev_size - 1 );
	close( tmp_fd );

	return 1;

}


int8_t set_tun_addr( int32_t fd, uint32_t tun_addr, char *tun_dev ) {

	struct sockaddr_in addr;
	struct ifreq ifr_tun;


	memset( &ifr_tun, 0, sizeof(ifr_tun) );
	memset( &addr, 0, sizeof(addr) );

	addr.sin_addr.s_addr = tun_addr;
	addr.sin_family = AF_INET;
	memcpy( &ifr_tun.ifr_addr, &addr, sizeof(struct sockaddr) );

	strncpy( ifr_tun.ifr_name, tun_dev, IFNAMSIZ - 1 );

	if ( ioctl( fd, SIOCSIFADDR, &ifr_tun) < 0 ) {

		debug_output( 0, "Error - can't set tun address (SIOCSIFADDR): %s\n", strerror(errno) );
		return -1;

	}

	return 1;

}

