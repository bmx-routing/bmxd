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


#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <paths.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
//#include <net/if.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "../os.h"
#include "../originator.h"
#include "../metrics.h"
#include "../control.h"

#include "../batman.h"

#define IOCSETDEV 1


//from  linux/wireless.h
#define SIOCGIWNAME    0x8B01          /* get name == wireless protocol */


int8_t stop;

int32_t loop_mode = NO, info_output = 0;


static struct option long_options[] = {
 {ADVANCED_SWITCH,            0, 0, 0},
 {PURGE_SWITCH,               0, 0, 0},
 {GENIII_DEFAULTS_SWITCH,     0, 0, 0},
 {BMX_DEFAULTS_SWITCH,        0, 0, 0},
 {GRAZ07_DEFAULTS_SWITCH,     0, 0, 0},
 {ADD_SRV_SWITCH,             1, 0, 0},
 {DEL_SRV_SWITCH,             1, 0, 0},
 {AGGREGATIONS_PER_OGI_SWITCH,1, 0, 0},
 {BIDIRECT_TIMEOUT_SWITCH,    1, 0, 0},
 {NBRFSIZE_SWITCH,            1, 0, 0},
 {INITIAL_SEQNO_SWITCH,       1, 0, 0},
 {FAKE_UPTIME_SWITCH,         1, 0, 0},
 {DAD_TIMEOUT_SWITCH,         1, 0, 0},
 {GW_CHANGE_HYSTERESIS_SWITCH,1, 0, 0},
 {GW_TUNNEL_NETW_SWITCH,      1, 0, 0},
 {TUNNEL_IP_LEASE_TIME_SWITCH,1, 0, 0},
 {TWO_WAY_TUNNEL_SWITCH,      1, 0, 0},
 {ONE_WAY_TUNNEL_SWITCH,      1, 0, 0},
 {TTL_SWITCH,                 1, 0, 0},
 {NONPRIMARY_HNA_SWITCH,      1, 0, 0},
 {ASOCIAL_SWITCH,             0, 0, 0},
 {NO_TUNPERSIST_SWITCH,       0, 0, 0},
 {MAGIC_SWITCH,               1, 0, 0},
 {RT_PRIO_OFFSET_SWITCH,      1, 0, 0},
 {MORE_RULES_SWITCH,          0, 0, 0},
 {NO_PRIO_RULES_SWITCH,       0, 0, 0},
 {NO_LO_RULE_SWITCH,          0, 0, 0},
 {NO_TUNNEL_RULE_SWITCH,      1, 0, 0},
 {SRC_ADDR_SWITCH,	      1, 0, 0},
 {NO_THROW_RULES_SWITCH,      0, 0, 0},
 {NO_UNREACHABLE_RULE_SWITCH, 0, 0, 0},
 {NO_UNRESP_CHECK_SWITCH,     0, 0, 0},
 {RT_TABLE_OFFSET_SWITCH,     1, 0, 0},
 {BASE_PORT_SWITCH,           1, 0, 0},
 {DUP_TTL_LIMIT_SWITCH,       1, 0, 0},
 {DUP_RATE_SWITCH,	      1, 0, 0},
 {TTL_DEGRADE_SWITCH,	      1, 0, 0},
 {WL_CLONES_SWITCH,           1, 0, 0},
 {ASYMMETRIC_WEIGHT_SWITCH,   1, 0, 0},
 {ASYMMETRIC_EXP_SWITCH,      1, 0, 0},
 {UNI_PROBES_N_SWITCH,        1, 0, 0},
 {UNI_PROBES_IVAL_SWITCH,     1, 0, 0},
 {UNI_PROBES_SIZE_SWITCH,     1, 0, 0},
 {UNI_PROBES_WS_SWITCH,       1, 0, 0},
 {PARALLEL_BAT_NETA_SWITCH,   0, 0, 0},
 {PARALLEL_BAT_NETB_SWITCH,   0, 0, 0},
 {PARALLEL_BAT_NETC_SWITCH,   0, 0, 0},
 {PARALLEL_BAT_24C3_SWITCH,   0, 0, 0},
 {0, 0, 0, 0}
};

int my_daemon() {

	int fd;

	switch( fork() ) {

		case -1:
			return -1;

		case 0:
			break;

		default:
			exit(EXIT_SUCCESS);

	}

	if ( setsid() == -1 )
		return(-1);

	/* Make certain we are not a session leader, or else we might reacquire a controlling terminal */
	if ( fork() )
		exit(EXIT_SUCCESS);

	chdir( "/" );

	if ( ( fd = open(_PATH_DEVNULL, O_RDWR, 0) ) != -1 ) {

		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);

		if ( fd > 2 )
			close(fd);

	}

	return 0;

}

	
void set_init_addr( char* switch_name, char* switch_arg, uint32_t *ip, uint32_t *netmask, int creq ) {
	struct in_addr tmp_ip_holder;
	char *slashptr = NULL;
	
	if ( netmask ) {
	
		if ( ( slashptr = strchr( switch_arg, '/' ) ) == NULL ) {

			debug_output( DBGL_SYSTEM, "Invalid %s argument (netmask is missing): %s\n", switch_name, switch_arg );
			exit(EXIT_FAILURE);
	
		}

		*slashptr = '\0';

		errno = 0;
		
		*netmask = strtol( slashptr + 1, NULL, 10 );
	
		if ( ( errno == ERANGE ) || *netmask > 32 ) {
	
			debug_output( DBGL_SYSTEM, "Invalid %s argument (netmask is invalid): %s %s \n", switch_name, switch_arg, strerror( errno ) );
			exit(EXIT_FAILURE);
	
		}
		
	}
	
	errno = 0;
	
	if ( inet_pton( AF_INET, switch_arg, &tmp_ip_holder ) < 1 ) {

		debug_output( DBGL_SYSTEM, "Invalid (-)-%s value specified %s: %s\n", switch_name, switch_arg, strerror(errno) );
		exit(EXIT_FAILURE);

	}
	
	*ip = tmp_ip_holder.s_addr;
			
	if ( slashptr )
		*slashptr = '/';

	if ( client_mode && creq ) {
		
		struct cmsg_node *cn=debugMalloc( sizeof( struct cmsg_node ), 701 );
		memset( cn, 0, sizeof( struct cmsg_node ) );
		INIT_LIST_HEAD( &cn->list );
		
		cn->cmsg.version = COMPAT_VERSION;
		cn->cmsg.len = sizeof( struct cntl_msg );
		
		cn->cmsg.type = creq;
		cn->cmsg.ip = tmp_ip_holder.s_addr;
		cn->cmsg.val = netmask?*netmask:0;
		
		list_add_tail( &cn->list, &cmsg_list );

	}
	
	return;
}


void set_init_val( char* switch_name, int32_t switch_val, int32_t min, int32_t max, int32_t *target_value, int creq ) {
	
	if ( switch_val < min || switch_val > max ) {

		debug_output( DBGL_SYSTEM, "Invalid (-)-%s value specified: %i ! Value must be %i <= <value> <= %i !\n", switch_name, switch_val, min, max );

		// if invalid values are applied during startup we exit immediately
		if ( batman_time == 0 )
			exit(EXIT_FAILURE);
		
		return;
	}
	
	if ( target_value )
		*target_value = switch_val;
	
	if ( client_mode && creq ) {
		
		struct cmsg_node *cn=debugMalloc( sizeof( struct cmsg_node ), 702 );
		memset( cn, 0, sizeof( struct cmsg_node ) );
		INIT_LIST_HEAD( &cn->list );
		
		cn->cmsg.version = COMPAT_VERSION;
		cn->cmsg.len = sizeof( struct cntl_msg );
		
		cn->cmsg.type = creq;
		cn->cmsg.val = switch_val;
		
		list_add_tail( &cn->list, &cmsg_list );

	}
	
	return;
}


void set_init_arg( char* switch_name, char* switch_arg, int32_t min, int32_t max, int32_t *target_value, int creq ) {
	
	
	int32_t switch_val = switch_arg ? strtol(switch_arg, NULL , 10) : 0;
	
	set_init_val( switch_name, switch_val, min, max, target_value, creq );
	
}



void set_gw_network ( char *optarg_p ) {
	
	struct in_addr tmp_ip_holder;
	uint16_t netmask;
	char *slash_ptr;
	//static char netmask_str[ADDR_STR_LEN];
		
	char optarg_str[22];
	
	memcpy( optarg_str, optarg_p, sizeof(optarg_str) < strlen( optarg_p)+1 ? sizeof(optarg_str) : strlen(optarg_p)+1 );
	
	if ( ( slash_ptr = strchr( optarg_str, '/' ) ) == NULL ) {

		printf( "Invalid GW network (netmask is missing): %s\n", optarg_str );
		exit(EXIT_FAILURE);

	}

	*slash_ptr = '\0';

	if ( inet_pton( AF_INET, optarg_str, &tmp_ip_holder ) < 1 ) {

		*slash_ptr = '/';
		printf( "Invalid GW network (IP is invalid): %s\n", optarg_str );
		exit(EXIT_FAILURE);

	}

	errno = 0;

	netmask = strtol( slash_ptr + 1, NULL, 10 );

	if ( ( errno == ERANGE ) || ( errno != 0 && netmask == 0 ) ) {

		perror("strtol");
		exit(EXIT_FAILURE);

	}

	if ( netmask < MIN_GW_TUNNEL_NETMASK || netmask > MAX_GW_TUNNEL_NETMASK ) {

		*slash_ptr = '/';
		printf( "Invalid GW network (netmask %d is invalid): %s !\n", netmask, optarg_str );
		exit(EXIT_FAILURE);

	}

	gw_tunnel_prefix  = tmp_ip_holder.s_addr;
	gw_tunnel_prefix  = gw_tunnel_prefix & htonl( 0xFFFFFFFF<<(32-netmask) );
	gw_tunnel_netmask = netmask;
	
	
	*slash_ptr = '/';
	
}


void prepare_add_del_own_hna ( char *optarg_str, uint32_t addr, uint16_t netmask, int8_t del, uint8_t atype, int creq ) {
	
	struct hna_node *hna_node;
	struct in_addr tmp_ip_holder;
	char *slash_ptr;
	struct list_head *hna_list_pos;
	char str[16];
	uint8_t found = NO;
	
	// check if number of HNAs fit into max packet size
	if ( !del  &&  sizeof(struct bat_header) + sizeof(struct bat_packet_ogm) + 
		     ( ( 2 /*placeholder for the new hna-ext and one gw-ext packet*/ +  
		     my_srv_ext_array_len + my_hna_list_enabled) * sizeof(struct ext_packet)) > MAX_PACKET_OUT_SIZE ) {
		
		debug_output( DBGL_SYSTEM, "HNAs do not fit into max packet size \n");
		
		if ( batman_time == 0 )
			exit(EXIT_FAILURE);
		
		return;

	}

	if ( optarg_str ) {
	
		if ( (slash_ptr = strchr( optarg_str, '/' )) == NULL ) {
	
			printf( "Invalid announced network (netmask is missing): %s\n", optarg_str );
			
			if ( batman_time == 0 )
				exit(EXIT_FAILURE);
		
			return;
	
		}
	
		*slash_ptr = '\0';
	
		if ( inet_pton( AF_INET, optarg_str, &tmp_ip_holder ) < 1 ) {
	
			*slash_ptr = '/';
			printf( "Invalid announced network (IP is invalid): %s\n", optarg_str );
			
			if ( batman_time == 0 )
				exit(EXIT_FAILURE);
		
			return;

		}
		
		addr = tmp_ip_holder.s_addr;
		
		*slash_ptr = '/';
	
		errno = 0;
	
		netmask = strtol( slash_ptr + 1, NULL, 10 );
	
		if ( ( errno == ERANGE ) || ( errno != 0 && netmask == 0 ) ) {
	
			perror("strtol");
	
			if ( batman_time == 0 )
				exit(EXIT_FAILURE);
		
			return;

		}
	}
	
	if ( netmask < 1 || netmask > 32 ) {

		printf( "Invalid announced network (netmask is invalid): %s\n", optarg_str );

		if ( batman_time == 0 )
			exit(EXIT_FAILURE);
		
		return;

	}
	
	
	//tmp_ip_holder.s_addr = ( addr & htonl(0xFFFFFFFF<<(32-netmask)) );
	addr = ( addr & htonl(0xFFFFFFFF<<(32-netmask)) );
		
	
	list_for_each( hna_list_pos, &my_hna_list ) {

		hna_node = list_entry( hna_list_pos, struct hna_node, list );

		if ( hna_node->key.addr == addr && 
				   hna_node->key.KEY_FIELD_ANETMASK == netmask && 
				   hna_node->key.KEY_FIELD_ATYPE == atype ) {
				
			found = YES;
			
			if ( del && hna_node->enabled ) {
				
				hna_node->enabled = NO;
				my_hna_list_enabled--;
		
			} else if ( !del && ! hna_node->enabled ) {
			
				hna_node->enabled = YES;
				my_hna_list_enabled++;
			}
			
			
			break;
			
		}

	}

	
	if ( ! found ) {
		
		hna_node = debugMalloc( sizeof(struct hna_node), 203 );
		memset( hna_node, 0, sizeof(struct hna_node) );
		INIT_LIST_HEAD( &hna_node->list );
	
		hna_node->key.addr = addr;
		hna_node->key.KEY_FIELD_ANETMASK = netmask;
		hna_node->key.KEY_FIELD_ATYPE = atype;
		hna_node->enabled = ( del ? NO : YES );
		
		
		addr_to_string( hna_node->key.addr, str, sizeof (str) );
	
		list_add_tail( &hna_node->list, &my_hna_list );
		
		if ( hna_node->enabled )
			my_hna_list_enabled++;

	}
	
	if ( client_mode && creq == REQ_HNA) {
		
		struct cmsg_node *cn=debugMalloc( sizeof( struct cmsg_node ), 703 );
		memset( cn, 0, sizeof( struct cmsg_node ) );
		INIT_LIST_HEAD( &cn->list );
		
		cn->cmsg.version = COMPAT_VERSION;
		cn->cmsg.len = sizeof( struct cntl_msg );
		
		cn->cmsg.type = creq;
		cn->cmsg.val = netmask;
		cn->cmsg.ip = addr;
		cn->cmsg.val1 = del;
		cn->cmsg.val2 = atype;
		
		list_add_tail( &cn->list, &cmsg_list );

	}

	return;
	
}

void prepare_add_no_tunnel (  char *optarg_str ) {
	struct notun_node *notun_node;
	struct in_addr tmp_ip_holder;
	char *delimiter1_ptr;
	uint32_t netmask;
	
	if ( ( delimiter1_ptr = strchr( optarg_str, '/' ) ) == NULL ) {

		printf( "Invalid %s argument (netmask is missing): %s\n", NO_TUNNEL_RULE_SWITCH, optarg_str );
		exit(EXIT_FAILURE);

	}

	*delimiter1_ptr = '\0';

	if ( inet_pton( AF_INET, optarg_str, &tmp_ip_holder ) < 1 ) {

		*delimiter1_ptr = '/';
		printf( "Invalid %s argument (IP is invalid): %s\n", NO_TUNNEL_RULE_SWITCH, optarg_str );
		exit(EXIT_FAILURE);

	}

	*delimiter1_ptr = '/';
	
	errno = 0;
	netmask = strtol( delimiter1_ptr + 1, NULL, 10 );
	
	if ( ( errno == ERANGE ) || netmask > 32 ) {
	
		printf( "Invalid %s argument (netmask is invalid): %s\n", NO_TUNNEL_RULE_SWITCH, optarg_str );
		perror("strtol");
		exit(EXIT_FAILURE);
	
	}


	notun_node = debugMalloc( sizeof(struct notun_node), 224 );
	memset( notun_node, 0, sizeof(struct notun_node) );
	INIT_LIST_HEAD( &notun_node->list );

	notun_node->addr = tmp_ip_holder.s_addr;
	notun_node->netmask = netmask;

	list_add_tail( &notun_node->list, &notun_list );
	
}

	
	
void prepare_add_del_own_srv ( char *optarg_str, uint32_t addr, uint16_t port, uint8_t seqno, int8_t del ) {
	
	struct srv_node *srv_node;
	struct in_addr tmp_ip_holder;
	char *delimiter1_ptr, *delimiter2_ptr;
	struct list_head *srv_list_pos;
	char str[16];
	uint8_t found = NO;
	
	if ( optarg_str ) {
	
		int opt_len = strlen( optarg_str );
		seqno = 0;
		
		// check if number of SRVs fit into max packet size
		if ( !del  &&  sizeof(struct bat_header) + sizeof(struct bat_packet_ogm) + 
			( ( 2 /*placeholder for the new hna-ext and one gw-ext packet*/ +  
			my_srv_list_enabled + my_hna_list_enabled) * sizeof(struct ext_packet)) > MAX_PACKET_OUT_SIZE ) {
			
			debug_output(3, "SRV announcements do not fit into max packet size \n");
			
			if ( batman_time == 0 )
				exit(EXIT_FAILURE);
			
			return;
			
		}
	
	
		if ( ( delimiter1_ptr = strchr( optarg_str, ':' ) ) == NULL ) {
	
			printf( "Invalid SRV announcement (first : is missing): %s\n", optarg_str );
	
			if ( batman_time == 0 )
				exit(EXIT_FAILURE);
			
			return;

		}
	
		*delimiter1_ptr = '\0';
	
		if ( inet_pton( AF_INET, optarg_str, &tmp_ip_holder ) < 1 ) {
	
			*delimiter1_ptr = ':';
			printf( "Invalid SRV announcement (IP is invalid): %s\n", optarg_str );
	
			if ( batman_time == 0 )
				exit(EXIT_FAILURE);
			
			return;

		}
		
		addr = tmp_ip_holder.s_addr;
		
		*delimiter1_ptr = ':';
	
		
		errno = 0;
		port = strtol( delimiter1_ptr + 1, NULL, 10 );
		
		if ( ( errno == ERANGE ) ) {
		
			printf( "Invalid SRV announcement (port is invalid): %s\n", optarg_str );
			perror("strtol");
			
			if ( batman_time == 0 )
				exit(EXIT_FAILURE);
			
			return;
		
		}
		
		if( !del ) {
		
			if ( ( ((delimiter1_ptr + 2) - optarg_str) > opt_len ) || ( delimiter2_ptr = strchr( (delimiter1_ptr + 1), ':' ) ) == NULL ) {
		
				printf( "Invalid SRV announcement (2. : is missing): %s\n", optarg_str );
		
				if ( batman_time == 0 )
					exit(EXIT_FAILURE);
			
				return;

			}
			
			
			
			if (  ((delimiter2_ptr + 2) - optarg_str) > opt_len  ) {
		
				printf( "Invalid SRV announcement (seqno is missing): %s\n", optarg_str );
		
				if ( batman_time == 0 )
					exit(EXIT_FAILURE);
			
				return;

			}
			
			errno = 0;
			seqno = strtol( delimiter2_ptr + 1, NULL, 10 );
		
			if ( ( errno == ERANGE ) ) {
		
				printf( "Invalid SRV announcement (seqno is invalid): %s\n", optarg_str );
				perror("strtol");
		
				if ( batman_time == 0 )
					exit(EXIT_FAILURE);
			
				return;

			}
		
		}	
	
	}
	
	list_for_each( srv_list_pos, &my_srv_list ) {

		srv_node = list_entry( srv_list_pos, struct srv_node, list );

		if ( srv_node->srv_addr == addr && srv_node->srv_port == port ) {
		
			found = YES;
	
			if ( del && srv_node->enabled ) {
				//printf( "removing HNA %s/%i, atype %d \n", str, netmask, atype );
				srv_node->enabled = NO;
				my_srv_list_enabled--;

			} else if ( !del && ! srv_node->enabled ) {
	
				srv_node->enabled = YES;
				srv_node->srv_seqno = seqno;
				my_srv_list_enabled++;
			
			} else if ( !del && srv_node->enabled ) {
	
				srv_node->srv_seqno = seqno;
			
			}
	
			break;
	
		}

	}


	if ( ! found ) {

		srv_node = debugMalloc( sizeof(struct srv_node), 223 );
		memset( srv_node, 0, sizeof(struct srv_node) );
		INIT_LIST_HEAD( &srv_node->list );

		srv_node->srv_addr = addr;
		srv_node->srv_port = port;
		srv_node->srv_seqno = ( !del ? seqno : 0 );
		srv_node->enabled = ( del ? NO : YES ) ;


		addr_to_string( srv_node->srv_addr, str, sizeof (str) );
		printf( "adding SRV %s:%d:%i \n", str, port, seqno );

		list_add_tail( &srv_node->list, &my_srv_list );

		if ( srv_node->enabled )
			my_srv_list_enabled++;

	}
	

	if ( client_mode ) {
		
		struct cmsg_node *cn=debugMalloc( sizeof( struct cmsg_node ), 704 );
		memset( cn, 0, sizeof( struct cmsg_node ) );
		INIT_LIST_HEAD( &cn->list );
		
		cn->cmsg.version = COMPAT_VERSION;
		cn->cmsg.len = sizeof( struct cntl_msg );
		
		cn->cmsg.type = REQ_SRV;
		cn->cmsg.ip = addr;
		cn->cmsg.val = port;
		cn->cmsg.val1 = seqno;
		cn->cmsg.val2 = del;
		
		list_add_tail( &cn->list, &cmsg_list );

	}

}


void set_gw_speeds( char *optarg ) {
	
	int32_t download_speed = 0, upload_speed = 0;
	char *slash_ptr;
	
	if ( ( slash_ptr = strchr( optarg, '/' ) ) != NULL )
		*slash_ptr = '\0';

	errno = 0;

	download_speed = strtol( optarg, NULL, 10 );

	if ( ( errno == ERANGE ) || ( errno != 0 && download_speed == 0 ) ) {

		perror("strtol");
		exit(EXIT_FAILURE);

	}

	if ( strlen( optarg ) > 4  && 
		( ( strncmp( optarg + strlen( optarg ) - 4, "MBit", 4 ) == 0 ) || 
		  ( strncmp( optarg + strlen( optarg ) - 4, "mbit", 4 ) == 0 ) || 
		  ( strncmp( optarg + strlen( optarg ) - 4, "Mbit", 4 ) == 0 ) ) ) {
		
		download_speed *= 1024;
		
		  }

	if ( slash_ptr != NULL ) {

		errno = 0;

		upload_speed = strtol( slash_ptr + 1, NULL, 10 );

		if ( ( errno == ERANGE ) || ( errno != 0 && upload_speed == 0 ) ) {
			perror("strtol");
			exit(EXIT_FAILURE);
		}

		if ( strlen( slash_ptr + 1 ) > 4  && 
			( ( strncmp( slash_ptr + 1 + strlen( slash_ptr + 1 ) - 4, "MBit", 4 ) == 0 ) || 
			  ( strncmp( slash_ptr + 1 + strlen( slash_ptr + 1 ) - 4, "mbit", 4 ) == 0 ) || 
			  ( strncmp( slash_ptr + 1 + strlen( slash_ptr + 1 ) - 4, "Mbit", 4 ) == 0 ) ) ) {
			
			upload_speed *= 1024;
			
			  }

		*slash_ptr = '/';

	}
	
	if ( ( download_speed > 0 ) && ( upload_speed == 0 ) )
		upload_speed = download_speed / 5;

	if ( download_speed > 0 ) {

		gateway_class = get_gw_class( download_speed, upload_speed );
		get_gw_speeds( gateway_class, &download_speed, &upload_speed );

	}

	debug_output( DBGL_SYSTEM, "gateway class: %i -> propagating: %i%s/%i%s\n", gateway_class, ( download_speed > 2048 ? download_speed / 1024 : download_speed ), ( download_speed > 2048 ? "MBit" : "KBit" ), ( upload_speed > 2048 ? upload_speed / 1024 : upload_speed ), ( upload_speed > 2048 ? "MBit" : "KBit" ) );

	if ( client_mode ) {
		
		struct cmsg_node *cn=debugMalloc( sizeof( struct cmsg_node ), 705 );
		memset( cn, 0, sizeof( struct cmsg_node ) );
		INIT_LIST_HEAD( &cn->list );
		
		cn->cmsg.version = COMPAT_VERSION;
		cn->cmsg.len = sizeof( struct cntl_msg );
		
		cn->cmsg.type = REQ_GW_CLASS;
		cn->cmsg.val = gateway_class;
		
		list_add_tail( &cn->list, &cmsg_list );

	}

		
}



void apply_long_opt( int32_t option_index ) {
	
	do {
		if( strcmp( ADVANCED_SWITCH, long_options[option_index].name ) == 0 ) {
	
			errno = 0;
					
			verbose_usage();
			print_advanced_opts( YES /*verbose*/ );
			exit(EXIT_SUCCESS);

		} else if( strcmp( PURGE_SWITCH, long_options[option_index].name ) == 0 ) {
			
			set_init_val( PURGE_SWITCH, 0, 0, 0, NULL, REQ_PURGE );
			break;
		
		} else if ( strcmp( BMX_DEFAULTS_SWITCH, long_options[option_index].name ) == 0 ) {

			break;

		} else if ( strcmp( GENIII_DEFAULTS_SWITCH, long_options[option_index].name ) == 0 ) {

	
			errno = 0;
	
			printf( "Error - Sorry, %s is not supported anymore... !\n", GENIII_DEFAULTS_SWITCH );
			exit(EXIT_FAILURE);

		} else if ( strcmp( GRAZ07_DEFAULTS_SWITCH, long_options[option_index].name ) == 0 ) {

			errno = 0;
	
			printf( "Error - Sorry, %s is not supported anymore... !\n", GENIII_DEFAULTS_SWITCH );
			exit(EXIT_FAILURE);
					

		} else if ( strcmp( BIDIRECT_TIMEOUT_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( BIDIRECT_TIMEOUT_SWITCH, optarg, MIN_BIDIRECT_TIMEOUT, MAX_BIDIRECT_TIMEOUT, &my_lws, REQ_LWS );
			break;

		} else if ( strcmp( NBRFSIZE_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( NBRFSIZE_SWITCH, optarg, MIN_SEQ_RANGE, MAX_SEQ_RANGE, &my_pws, REQ_PWS );
			break;

		} else if ( strcmp( DAD_TIMEOUT_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( DAD_TIMEOUT_SWITCH, optarg, MIN_DAD_TIMEOUT, MAX_DAD_TIMEOUT, &dad_timeout, REQ_NONE );
			break;

		} else if ( strcmp( INITIAL_SEQNO_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( INITIAL_SEQNO_SWITCH, optarg, MIN_INITIAL_SEQNO, MAX_INITIAL_SEQNO, &initial_seqno, REQ_NONE );
			break;
				
		} else if ( strcmp( FAKE_UPTIME_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( FAKE_UPTIME_SWITCH, optarg, MIN_FAKE_UPTIME, MAX_FAKE_UPTIME, &fake_uptime, REQ_FAKE_TIME );
			fake_start_time( fake_uptime );
			break;
				
		} else if ( strcmp( GW_CHANGE_HYSTERESIS_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( GW_CHANGE_HYSTERESIS_SWITCH, optarg, MIN_GW_CHANGE_HYSTERESIS, MAX_GW_CHANGE_HYSTERESIS, &gw_change_hysteresis, REQ_GW_CHANGE_HYSTERESIS );
			break;

		} else if ( strcmp( GW_TUNNEL_NETW_SWITCH, long_options[option_index].name ) == 0 ) {

			set_gw_network( optarg );
			break;
					
					
		} else if ( strcmp( TUNNEL_IP_LEASE_TIME_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( TUNNEL_IP_LEASE_TIME_SWITCH, optarg, MIN_TUNNEL_IP_LEASE_TIME, MAX_TUNNEL_IP_LEASE_TIME, &tunnel_ip_lease_time, REQ_NONE );
			break;
							
		} else if ( strcmp( TWO_WAY_TUNNEL_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( TWO_WAY_TUNNEL_SWITCH, optarg, MIN_TWO_WAY_TUNNEL, MAX_TWO_WAY_TUNNEL, &two_way_tunnel, REQ_2WT );
			break;
				
		} else if ( strcmp( ONE_WAY_TUNNEL_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( ONE_WAY_TUNNEL_SWITCH, optarg, MIN_ONE_WAY_TUNNEL, MAX_ONE_WAY_TUNNEL, &one_way_tunnel, REQ_1WT );
			break;
				
		} else if ( strcmp( TTL_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( TTL_SWITCH, optarg, MIN_TTL, MAX_TTL, &ttl, REQ_TTL );
			break;

		} else if ( strcmp( DUP_TTL_LIMIT_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( DUP_TTL_LIMIT_SWITCH, optarg, MIN_DUP_TTL_LIMIT, MAX_DUP_TTL_LIMIT, &dup_ttl_limit, REQ_NONE );
			break;
				
		} else if ( strcmp( DUP_RATE_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( DUP_RATE_SWITCH, optarg, MIN_DUP_RATE, MAX_DUP_RATE, &dup_rate, REQ_NONE );
			break;

		} else if ( strcmp( TTL_DEGRADE_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( TTL_DEGRADE_SWITCH, optarg, MIN_TTL_DEGRADE, MAX_TTL_DEGRADE, &ttl_degrade, REQ_TTL_DEGRADE );
			break;
				
		} else if ( strcmp( WL_CLONES_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( WL_CLONES_SWITCH, optarg, MIN_WL_CLONES, MAX_WL_CLONES, &wl_clones, REQ_NONE );
			break;

		} else if ( strcmp( ASYMMETRIC_WEIGHT_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( ASYMMETRIC_WEIGHT_SWITCH, optarg, MIN_ASYMMETRIC_WEIGHT, MAX_ASYMMETRIC_WEIGHT, &asymmetric_weight, REQ_NONE );
			break;

		} else if ( strcmp( ASYMMETRIC_EXP_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( ASYMMETRIC_EXP_SWITCH, optarg, MIN_ASYMMETRIC_EXP, MAX_ASYMMETRIC_EXP, &asymmetric_exp, REQ_NONE );
			break;
					
		} else if ( strcmp( UNI_PROBES_N_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( UNI_PROBES_N_SWITCH, optarg, MIN_UNI_PROBES_N, MAX_UNI_PROBES_N, &unicast_probes_num, REQ_UNI_PROBES_N );
			break;
				
		} else if ( strcmp( UNI_PROBES_IVAL_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( UNI_PROBES_IVAL_SWITCH, optarg, MIN_UNI_PROBES_IVAL, MAX_UNI_PROBES_IVAL, &unicast_probes_ival, REQ_UNI_PROBES_IVAL );
			break;
				
		} else if ( strcmp( UNI_PROBES_SIZE_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( UNI_PROBES_SIZE_SWITCH, optarg, MIN_UNI_PROBES_SIZE, MAX_UNI_PROBES_SIZE, &unicast_probes_size, REQ_UNI_PROBES_SIZE );
			break;
				
		} else if ( strcmp( UNI_PROBES_WS_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( UNI_PROBES_WS_SWITCH, optarg, MIN_UNI_PROBES_WS, MAX_UNI_PROBES_WS, &unicast_probes_ws, REQ_UNI_PROBES_WS );
			break;
				
		} else if ( strcmp( RT_PRIO_OFFSET_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( RT_PRIO_OFFSET_SWITCH, optarg, MIN_RT_PRIO_OFFSET, MAX_RT_PRIO_OFFSET, &rt_prio_offset, REQ_NONE );
			break;
					
		} else if ( strcmp( BASE_PORT_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( BASE_PORT_SWITCH, optarg, MIN_BASE_PORT, MAX_BASE_PORT, &ogm_port, REQ_NONE );
			break;
				
		} else if ( strcmp( RT_TABLE_OFFSET_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( RT_TABLE_OFFSET_SWITCH, optarg, MIN_RT_TABLE_OFFSET, MAX_RT_TABLE_OFFSET, &rt_table_offset, REQ_NONE );
			break;
					
		} else if ( strcmp( AGGREGATIONS_PER_OGI_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( AGGREGATIONS_PER_OGI_SWITCH, optarg, MIN_AGGREGATIONS_PER_OGI, MAX_AGGREGATIONS_PER_OGI, &aggregations_per_ogi, REQ_NONE );
			break;
				
		} else if ( strcmp( ADD_SRV_SWITCH, long_options[option_index].name ) == 0 ) {

			prepare_add_del_own_srv( optarg, 0,0,0, NO /* do not delete */ );
			break;
				
		} else if ( strcmp( DEL_SRV_SWITCH, long_options[option_index].name ) == 0 ) {

			prepare_add_del_own_srv( optarg, 0,0,0, YES /*delete*/ );
			break;
					
		} else if ( strcmp( NO_TUNNEL_RULE_SWITCH, long_options[option_index].name ) == 0 ) {

			prepare_add_no_tunnel( optarg );
			break;
				
		} else if ( strcmp( SRC_ADDR_SWITCH, long_options[option_index].name ) == 0 ) {
					
			if ( outgoing_src == 0  &&  !client_mode ) {
						
				errno = 0;
				if ( inet_pton( AF_INET, optarg, &outgoing_src ) < 1 ) {
	
					printf( "Error - Invalid announced network (IP is invalid): %s,  %s\n", optarg, strerror( errno ) );
			
					exit(EXIT_FAILURE);
		
				}
				prepare_add_del_own_hna( NULL, outgoing_src, 32, NO, A_TYPE_INTERFACE, REQ_NONE );
					
			} else {
				printf( "Error - %s can only be specified once and only at startup!\n", SRC_ADDR_SWITCH );
				exit(EXIT_FAILURE);

			}
			break;
					
		} else if ( strcmp( NONPRIMARY_HNA_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( NONPRIMARY_HNA_SWITCH, optarg, MIN_NONPRIMARY_HNA, MAX_NONPRIMARY_HNA, &nonprimary_hna, REQ_NONE );
			break;
		
		} else if ( strcmp( MAGIC_SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( MAGIC_SWITCH, optarg, MIN_MAGIC, MAX_MAGIC, &magic_switch, REQ_MAGIC );
			break;
					
					
				/*	this is just a template:
		} else if ( strcmp( _SWITCH, long_options[option_index].name ) == 0 ) {

			set_init_arg( _SWITCH, optarg, MIN_, MAX_, & );
			break;
				*/
						
		} else if ( strcmp( ASOCIAL_SWITCH, long_options[option_index].name ) == 0 ) {

			asocial_device = YES;
			break;

				
		} else if ( strcmp( NO_TUNPERSIST_SWITCH, long_options[option_index].name ) == 0 ) {

			no_tun_persist = YES;
			break;
				
		} else if ( strcmp( MORE_RULES_SWITCH, long_options[option_index].name ) == 0 ) {

			debug_output( DBGL_SYSTEM, "WARNING --%s is not supported anymore... !\n", MORE_RULES_SWITCH );
			break;

		} else if ( strcmp( NO_PRIO_RULES_SWITCH, long_options[option_index].name ) == 0 ) {

			no_prio_rules = YES;
			break;

		} else if ( strcmp( NO_LO_RULE_SWITCH, long_options[option_index].name ) == 0 ) {

			no_lo_rule = YES;
			break;

		} else if ( strcmp( NO_THROW_RULES_SWITCH, long_options[option_index].name ) == 0 ) {

			no_throw_rules = YES;
			break;
			
		} else if ( strcmp( NO_UNREACHABLE_RULE_SWITCH, long_options[option_index].name ) == 0 ) {

			debug_output( DBGL_SYSTEM, "WARNING --%s is now deprecated and unreachable rules are disabled by default !\n", NO_UNREACHABLE_RULE_SWITCH );
			break;
			
		} else if ( strcmp( NO_UNRESP_CHECK_SWITCH, long_options[option_index].name ) == 0 ) {

			no_unresponsive_check = YES;
			break;
					
		} else if ( strcmp( PARALLEL_BAT_NETA_SWITCH, long_options[option_index].name ) == 0 ) {

			errno = 0;
					
			set_init_arg( BASE_PORT_SWITCH,       "14305", MIN_BASE_PORT,       MAX_BASE_PORT,       &ogm_port,        REQ_NONE ); 
			set_init_arg( RT_TABLE_OFFSET_SWITCH, "144",   MIN_RT_TABLE_OFFSET, MAX_RT_TABLE_OFFSET, &rt_table_offset, REQ_NONE ); 
			set_init_arg( RT_PRIO_OFFSET_SWITCH,  "14500", MIN_RT_PRIO_OFFSET,  MAX_RT_PRIO_OFFSET,  &rt_prio_offset,  REQ_NONE ); 
			set_gw_network( "169.254.128.0/22" );
					
			break;
					
		} else if ( strcmp( PARALLEL_BAT_NETB_SWITCH, long_options[option_index].name ) == 0 ) {

			errno = 0;
					
			set_init_arg( BASE_PORT_SWITCH,       "16305", MIN_BASE_PORT,       MAX_BASE_PORT,       &ogm_port,        REQ_NONE ); 
			set_init_arg( RT_TABLE_OFFSET_SWITCH, "40",    MIN_RT_TABLE_OFFSET, MAX_RT_TABLE_OFFSET, &rt_table_offset, REQ_NONE ); 
			set_init_arg( RT_PRIO_OFFSET_SWITCH,  "4000",  MIN_RT_PRIO_OFFSET,  MAX_RT_PRIO_OFFSET,  &rt_prio_offset,  REQ_NONE ); 
			set_gw_network( "169.254.160.0/22" );
					
			break;
					
		} else if ( strcmp( PARALLEL_BAT_NETC_SWITCH, long_options[option_index].name ) == 0 ) {

			errno = 0;
					
			set_init_arg( BASE_PORT_SWITCH,       "18305", MIN_BASE_PORT,       MAX_BASE_PORT,       &ogm_port,        REQ_NONE ); 
			set_init_arg( RT_TABLE_OFFSET_SWITCH, "184",   MIN_RT_TABLE_OFFSET, MAX_RT_TABLE_OFFSET, &rt_table_offset, REQ_NONE ); 
			set_init_arg( RT_PRIO_OFFSET_SWITCH,  "18500", MIN_RT_PRIO_OFFSET,  MAX_RT_PRIO_OFFSET,  &rt_prio_offset,  REQ_NONE ); 
			set_gw_network( "169.254.192.0/22" );
					
			set_init_arg( NBRFSIZE_SWITCH, "10", MIN_SEQ_RANGE, MAX_SEQ_RANGE, &my_pws, REQ_NONE );

			break;
					
		} else if ( strcmp( PARALLEL_BAT_24C3_SWITCH, long_options[option_index].name ) == 0 ) {

			errno = 0;
					
			set_init_arg( BASE_PORT_SWITCH,       "4308", MIN_BASE_PORT,       MAX_BASE_PORT,       &ogm_port,        REQ_NONE ); 
			set_init_arg( RT_TABLE_OFFSET_SWITCH, "76",   MIN_RT_TABLE_OFFSET, MAX_RT_TABLE_OFFSET, &rt_table_offset, REQ_NONE ); 
			set_init_arg( RT_PRIO_OFFSET_SWITCH,  "7600", MIN_RT_PRIO_OFFSET,  MAX_RT_PRIO_OFFSET,  &rt_prio_offset,  REQ_NONE ); 
			set_gw_network( "0.0.0.0/30" );
					
			set_init_arg( TWO_WAY_TUNNEL_SWITCH, "0", MIN_TWO_WAY_TUNNEL, MAX_TWO_WAY_TUNNEL, &two_way_tunnel, REQ_NONE );
			set_init_arg( ONE_WAY_TUNNEL_SWITCH, "3", MIN_TWO_WAY_TUNNEL, MAX_TWO_WAY_TUNNEL, &two_way_tunnel, REQ_NONE );

			set_init_arg( NBRFSIZE_SWITCH, "100", MIN_SEQ_RANGE, MAX_SEQ_RANGE, &my_pws, REQ_NONE );
			set_init_arg( BIDIRECT_TIMEOUT_SWITCH, "30", MIN_BIDIRECT_TIMEOUT, MAX_BIDIRECT_TIMEOUT, &my_lws, REQ_NONE );
			no_lo_rule = YES;

			break;
				
				/* this is just a template:
		} else if ( strcmp( _SWITCH, long_options[option_index].name ) == 0 ) {

			errno = 0;
			= YES;
			break;
				*/	
				

		}

		usage();
		exit(EXIT_FAILURE);

	} while ( 0 );
		
}

void apply_short_opt( int32_t optchar ) {
	
	struct in_addr tmp_ip_holder;
	memset( &tmp_ip_holder, 0, sizeof (struct in_addr) );

	switch ( optchar ) {
		
		case 'a':

			prepare_add_del_own_hna( optarg,0,0, NO /*no del*/, A_TYPE_NETWORK, REQ_HNA );
			break;

		case 'A':

			prepare_add_del_own_hna( optarg,0,0, YES /*del */, A_TYPE_NETWORK, REQ_HNA );
			break;
	
		case 'b':
			loop_mode = NO;
			break;

		case 'l':
			loop_mode = YES;
			break;
	
		case 'c':
			client_mode = YES;
			break;

		case 'd':

			set_init_arg( "d", optarg, DBGL_MIN, DBGL_MAX, &debug_level, REQ_DBGL ); 
			break;

		case 'g':

			set_gw_speeds( optarg );
			break;

		case 'H':
			verbose_usage();
			exit(EXIT_SUCCESS);
		
		case 'i':
			set_init_arg( "i", "1", 1, 1, &info_output, REQ_INFO ); 
			break;

		case 'n':
			no_policy_routing = 1;
			break;

		case 'o':

			set_init_arg( "o", optarg, MIN_ORIGINATOR_INTERVAL, MAX_ORIGINATOR_INTERVAL, &my_ogi, REQ_OGI );
			break;

		case 'p':

			set_init_addr( "p", optarg, &pref_gateway, NULL, REQ_PREF_GW );
			break;

		case 'r':

		
			set_init_arg( "r", optarg, MIN_RT_CLASS, MAX_RT_CLASS, &routing_class, REQ_RT_CLASS );
			break;

		case 's':

			errno = 0;
			if ( inet_pton( AF_INET, optarg, &tmp_ip_holder ) < 1 ) {

				printf( "Invalid preferred visualsation server IP specified: %s\n", optarg );
				exit(EXIT_FAILURE);

			}

			init_vis( tmp_ip_holder.s_addr );
			break;
	
		case 'v':

			printf( "BatMan-eXp %s%s (compatibility version %i)\n", SOURCE_VERSION, ( strncmp( REVISION_VERSION, "0", 1 ) != 0 ? REVISION_VERSION : "" ), COMPAT_VERSION );
			exit(EXIT_SUCCESS);

		case 'V':

			print_animation();

			printf( "\x1B[0;0HBatMan-eXp %s%s (compatibility version %i)\n", SOURCE_VERSION, ( strncmp( REVISION_VERSION, "0", 1 ) != 0 ? REVISION_VERSION : "" ), COMPAT_VERSION );
			printf( "\x1B[9;0H \t May the bat guide your path ...\n\n\n" );

			exit(EXIT_SUCCESS);

		case 'h':
			usage();
			exit(EXIT_SUCCESS);

		default:
			usage();
			exit(EXIT_FAILURE);

	}
	
}
	
char* get_init_string( int g_argc, char **g_argv ){
	
#define INIT_STRING_SIZE 500
	
	char *dbg_init_str = debugMalloc( INIT_STRING_SIZE, 127 );
	int i, dbg_init_out = 0;
	
	for (i=0; i < g_argc; i++) {
		
		if ( i >= 0 && INIT_STRING_SIZE > dbg_init_out) {
			dbg_init_out = dbg_init_out + snprintf( (dbg_init_str + dbg_init_out), (INIT_STRING_SIZE - dbg_init_out), "%s ", g_argv[i] );
		}
		
	}
	
	return dbg_init_str;

}


	
	
void apply_init_args( int argc, char *argv[] ) {

	struct batman_if *batman_if;
	char  ifaddr_str[ADDR_STR_LEN];

	int32_t optchar, recv_buff_len, found_args;
	struct ext_type_hna hna_type_request;

	memset( &hna_type_request, 0, sizeof( hna_type_request ) );
	
	stop = 0;
	prog_name = argv[0];
	
	inet_pton( AF_INET, DEF_GW_TUNNEL_PREFIX_STR, &gw_tunnel_prefix );

	
	printf( "BatMan-eXp %s%s (compatibility version %d) !\n", SOURCE_VERSION, ( strncmp( REVISION_VERSION, "0", 1 ) != 0 ? REVISION_VERSION : "" ), COMPAT_VERSION );

	while ( 1 ) {

		int32_t option_index = 0;

		
		if ( ( optchar = getopt_long ( argc, argv, "a:A:bclhHid:o:q:g:p:r:s:vV", long_options, &option_index ) ) == -1 ) {
			break;
		}
		
		if ( optchar == 0) {
			
			apply_long_opt( option_index );
			
		} else {
			
			apply_short_opt( optchar );

		}

	}
	
	found_args = optind;

	if ( !client_mode  &&  info_output ) {

		debug_config(1);
		
		print_metric_table( 1, global_mt );

		cleanup_all( CLEANUP_SUCCESS );

	}
	

	if ( gateway_class  &&  routing_class ) {
		fprintf( stderr, "Error - routing class can't be set while gateway class is in use !\n" );
		usage();
		exit(EXIT_FAILURE);
	}

	if ( gateway_class  &&  pref_gateway ) {
		fprintf( stderr, "Error - preferred gateway can't be set while gateway class is in use !\n" );
		usage();
		exit(EXIT_FAILURE);
	}

	/* use routing class 1 if none specified */
	if ( !routing_class  &&  pref_gateway )
		routing_class = 3;

	if ( ( routing_class  ||  gateway_class )  &&  !probe_tun(1) )
		exit(EXIT_FAILURE);

	/* this must be set for unix_clients and non-unix_clients */ 
	sprintf( unix_path, "%s.%d", DEF_UNIX_PATH, ogm_port);

	struct sockaddr_un unix_addr;
	
	memset( &unix_addr, 0, sizeof(struct sockaddr_un) );
	unix_addr.sun_family = AF_LOCAL;
	strcpy( unix_addr.sun_path, unix_path );
	

	
	if ( !client_mode ) {
		
		if ( debug_level != -1 ) {
			
			struct client_node *client_node = debugMalloc( sizeof(struct client_node), 205 );
			INIT_LIST_HEAD( &client_node->list );
			client_node->fd = STDOUT_FILENO;
			list_add( &client_node->list, (struct list_head_first *)&dbgl_clients[ debug_level ] );
				
		}
		
		char *init_string = get_init_string( argc, argv );
	
		debug_output(DBGL_SYSTEM, "Startup parameters: %s\n", init_string);
	
		debugFree( init_string, 1127 );


		
		// Testing for open and used unix socket
		
		unix_sock = socket( AF_LOCAL, SOCK_STREAM, 0 );

		if ( connect ( unix_sock, (struct sockaddr *)&unix_addr, sizeof(struct sockaddr_un) ) < 0 ) {

			close( unix_sock );
			unlink( unix_path );
			unix_sock = socket( AF_LOCAL, SOCK_STREAM, 0 );

		} else {
			
			printf( "Error - there is already a batmand running on unix socket %s ?\n", unix_path );
			cleanup_all( CLEANUP_FAILURE );
		
		}
		

		if ( bind ( unix_sock, (struct sockaddr *)&unix_addr, sizeof (struct sockaddr_un) ) < 0 ) {

			printf( "Error - can't bind unix socket '%s': %s\n", unix_path, strerror(errno) );
			cleanup_all( CLEANUP_FAILURE );

		}

		if ( listen( unix_sock, 10 ) < 0 ) {

			printf( "Error - can't listen unix socket '%s': %s\n", unix_path, strerror(errno) );
			cleanup_all( CLEANUP_FAILURE );

		}
		
		
		if ( argc <= found_args ) {

			fprintf( stderr, "\nError - no interface specified !\n\n" );
			usage();
			cleanup_all( CLEANUP_FAILURE );

		}

		signal( SIGINT, handler );
		signal( SIGTERM, handler );
		signal( SIGPIPE, SIG_IGN );
		signal( SIGSEGV, segmentation_fault );
		
		if ( flush_routes_rules(0 /* flush routes */) < 0 ) {

			cleanup_all( CLEANUP_FAILURE );

		}

		if ( !no_prio_rules ) {
			if ( flush_routes_rules(1 /* flush rules */) < 0 ) {
	
				cleanup_all( CLEANUP_FAILURE );
	
			}
		}

		debug_output( DBGL_SYSTEM, "   duplicate-address-detection timeout %ds, purge timeout %ds, originator interval %dms, window size %d \n",
		  dad_timeout, PURGE_TIMEOUT/1000, my_ogi, my_pws );

		
		if ( initial_seqno == 0 )
			initial_seqno = rand_num( FULL_SEQ_RANGE - (10*my_pws) );
	

		while ( argc > found_args ) {

			batman_if = debugMalloc( sizeof(struct batman_if), 206 );
			memset( batman_if, 0, sizeof(struct batman_if) );
			INIT_LIST_HEAD( &batman_if->list );

			list_add_tail( &batman_if->list, &if_list );
			
			batman_if->dev = argv[found_args];
			batman_if->if_num = found_ifs++;
			
			batman_if->out.ext_msg = NO;
			batman_if->out.bat_type = BAT_TYPE_OGM;
			batman_if->out.flags = 0x00;
			batman_if->out.size = 0x00;
			batman_if->out.pws     = my_pws;
			batman_if->out.seqno    = initial_seqno;

			// some configurable interface values - initialized to unspecified:
			batman_if->if_ttl_conf  = -1;
			batman_if->if_send_clones_conf  = -1;
			//batman_if->dont_make_ip_hna_if_conf = -1;
			batman_if->hna_if_conf = -1;
			batman_if->send_ogm_only_via_owning_if_conf = -1;
					
			while ( argc > found_args && strlen( argv[found_args] ) >= 2 && *argv[found_args] == '/') {

				if ( (argv[found_args])[1] == TTL_IF_SWITCH && argc > (found_args+1) ) {

					errno = 0;
					uint8_t tmp = strtol ( argv[ found_args+1 ], NULL , 10 );

					if ( tmp < MIN_TTL || tmp > MAX_TTL ) {

						printf( "Invalid ttl specified: %i.\nThe ttl must be >= %i and <= %i.\n", tmp, MIN_TTL, MAX_TTL );

						cleanup_all( CLEANUP_FAILURE );
					}

					batman_if->if_ttl_conf = tmp;

					found_args += 2;

				} else if ( (argv[found_args])[1] == CLONES_IF_SWITCH && argc > (found_args+1) ) {

					errno = 0;
					int16_t tmp = strtol ( argv[ found_args+1 ], NULL , 10 );
					//printf ("Interface %s specific option: /%c %d \n", batman_if->dev, ((argv[found_args])[1]), tmp );

					if ( tmp < MIN_WL_CLONES || tmp > MAX_WL_CLONES ) {

						printf( "Invalid /%c specified: %i.\n Value must be %i <= value <= %i.\n", 
								CLONES_IF_SWITCH, tmp, MIN_WL_CLONES, MAX_WL_CLONES );

						cleanup_all( CLEANUP_FAILURE );
					}

					batman_if->if_send_clones_conf = tmp;
					
					found_args += 2;

				
				} else if ( (argv[found_args])[1] == WLAN_IF_SWITCH && argc > (found_args) ) {

					errno = 0;

					batman_if->if_send_clones_conf = wl_clones;

					found_args += 1;

				
				} else if ( (argv[found_args])[1] == LAN_IF_SWITCH && argc > (found_args) ) {

					errno = 0;

					batman_if->if_send_clones_conf = DEF_LAN_CLONES;

					found_args += 1;

				
							
				} else if ( (argv[found_args])[1] == OGM_ONLY_VIA_OWNING_IF_SWITCH && argc > (found_args) ) {

					errno = 0;

					batman_if->send_ogm_only_via_owning_if_conf = YES;
					batman_if->if_ttl_conf = 1;

					found_args += 1;

				
				} else if ( (argv[found_args])[1] == NO_HNA_IF_SWITCH && argc > (found_args) ) {

					errno = 0;
					
					//batman_if->dont_make_ip_hna_if_conf = YES;
					batman_if->hna_if_conf = NO;
						
					found_args += 1;

							
				} else if ( (argv[found_args])[1] == HNA_IF_SWITCH && argc > (found_args) ) {

					errno = 0;
					
					//batman_if->dont_make_ip_hna_if_conf = YES;
					batman_if->hna_if_conf = YES;
						
					found_args += 1;

							
				} else {
					
					printf( "Invalid interface specific option specified! \n" );
					cleanup_all( CLEANUP_FAILURE );
				
				}
			
			}

			
			init_interface ( batman_if );
						
			found_args++;
					
		}
		
		if ( found_ifs == 0 ) {
			
			fprintf( stderr, "\nError - no valid interface specified !\n\n" );
			usage();
			cleanup_all( CLEANUP_FAILURE );

		}
			
		
		memset( my_pip_ext_array, 0, sizeof(struct ext_packet) );
		my_pip_ext_array->EXT_FIELD_MSG = YES;
		my_pip_ext_array->EXT_FIELD_TYPE = EXT_TYPE_PIP;
		my_pip_ext_array->EXT_PIP_FIELD_ADDR = (list_entry( (&if_list)->next, struct batman_if, list ))->addr.sin_addr.s_addr;
	
		if ( found_ifs > 1 ) 
			my_pip_ext_array_len = 1;
		else
			my_pip_ext_array_len = 0;


		/* old daemonize */

		/* add rule for hosts and announced interfaces */
		if( !no_prio_rules ) { 
		
			add_del_rule( 0, 0, BATMAN_RT_TABLE_INTERFACES, BATMAN_RT_PRIO_INTERFACES, 0, 1, 0, YES /*track*/ );
			add_del_rule( 0, 0, BATMAN_RT_TABLE_HOSTS, BATMAN_RT_PRIO_HOSTS, 0, 1, 0, YES /*track*/ );

		}

		/* add rule for hna networks */
		if( !no_prio_rules )
			add_del_rule( 0, 0, BATMAN_RT_TABLE_NETWORKS,   BATMAN_RT_PRIO_NETWORKS,   0, 1, 0, YES /*track*/ );

		
		
		if ( add_del_interface_rules( 0, (routing_class > 0 ? YES : NO), YES ) < 0 ) {

			cleanup_all( CLEANUP_FAILURE );

		}

		if ( routing_class > 0 ) {
			
			struct list_head *notun_pos;
			struct notun_node *notun_node;
			
			list_for_each(notun_pos, &notun_list) {
	
				notun_node = list_entry(notun_pos, struct notun_node, list);
		
				if ( notun_node->match_found == NO ) {
					addr_to_string( notun_node->addr, ifaddr_str, sizeof(ifaddr_str) );
					debug_output(0, "WARNING: NO interface found matching %s %s/%d \n", NO_TUNNEL_RULE_SWITCH, ifaddr_str, notun_node->netmask );
				}
			}
		}		


		if ( gateway_class != 0 )
			start_gw_service( );
		
		/* daemonize */
		if ( debug_level == -1 ) {

			if ( my_daemon() < 0 ) {

				debug_output( DBGL_SYSTEM, "Error - can't fork to background: %s\n", strerror(errno) );
				cleanup_all( CLEANUP_FAILURE );

			}

		}

		activate_debug_system( );
		


	/* connect to running batmand via unix socket */
	} else {

		struct list_head *list_pos, *list_tmp;
		struct cntl_msg cmsg;
		int send_req_end = YES;

		if ( list_empty( &cmsg_list ) ) {

			set_init_arg( "", "1", 1, 1, &info_output, REQ_DEFAULT ); 

		} 
		
		do {
			unix_sock = socket( AF_LOCAL, SOCK_STREAM, 0 );
		
			if ( connect ( unix_sock, (struct sockaddr *)&unix_addr, sizeof(struct sockaddr_un) ) < 0 ) {
	
				printf( "Error - can't connect to unix socket '%s': %s ! Is batmand running on this host ?\n", unix_path, strerror(errno) );
				close( unix_sock );
				exit(EXIT_FAILURE);
	
			}
			
			/* for all pending control messages */
			list_for_each( list_pos, &cmsg_list ) {
	
				struct cmsg_node *cmsg_node = list_entry(list_pos, struct cmsg_node, list);
	
				memcpy( &cmsg, &cmsg_node->cmsg, sizeof( struct cntl_msg ) );
				
				if ( cmsg.type != REQ_DBGL && cmsg.type != REQ_END )
					loop_mode = NO;
					
				if ( cmsg.type == REQ_DBGL  &&  
					(cmsg.val == DBGL_SYSTEM || cmsg.val == DBGL_CHANGES || cmsg.val == DBGL_TEST || cmsg.val == DBGL_ALL) ) {
					
					// if this is the only element in the list...
					if ( cmsg_list.next == (struct list_head*)cmsg_node && 
						cmsg_node->list.next == (struct list_head *)&cmsg_list ) {
						
						send_req_end = NO;
						
					} else {
						
						continue;
						
					}
				}			
	
				if ( write( unix_sock, &cmsg, sizeof( struct cntl_msg ) ) < 0 ) {
	
					printf( "Error - can't write to unix socket: %s\n", strerror(errno) );
					close( unix_sock );
					exit(EXIT_FAILURE);
	
				}
	
	
			}
			
			if ( send_req_end ) {
				memset( &cmsg, 0, sizeof( struct cntl_msg ) );
				cmsg.version = COMPAT_VERSION;
				cmsg.len = sizeof( struct cntl_msg );
				cmsg.type = REQ_END;
				
				if ( write( unix_sock, &cmsg, sizeof( struct cntl_msg ) ) < 0 ) {
		
					printf( "Error - can't write to unix socket: %s\n", strerror(errno) );
					close( unix_sock );
					exit(EXIT_FAILURE);
			
				}
			}
		
			char unix_buff[MAX_UNIX_MSG_SIZE+1];
			
			if ( loop_mode )
				system( "clear" );
				
			while ( ( recv_buff_len = read( unix_sock, unix_buff, MAX_UNIX_MSG_SIZE ) ) > 0 ) {
		
				unix_buff[recv_buff_len] = '\0';
		
				printf( "%s", unix_buff );
		
			}
		
			if ( recv_buff_len < 0 ) {
		
				printf( "Error - can't read from unix socket: %s\n", strerror(errno) );
				exit(EXIT_FAILURE);
		
			}
		
			close( unix_sock );
			unix_sock = 0;
			
			if ( loop_mode ) {
				
 				sleep ( 1 );
				
			} else {
				
				/* purge all control messages */
				list_for_each_safe( list_pos, list_tmp, &cmsg_list ) {
					struct cmsg_node *cmsg_node = list_entry(list_pos, struct cmsg_node, list);
					list_del( (struct list_head *)&cmsg_list, list_pos, &cmsg_list );
					debugFree( cmsg_node, 1700 );
				}
				
			}
			
		} while ( loop_mode );
			
		exit(EXIT_SUCCESS);

	}

}


void set_readfds()
{
	struct list_head *list_pos;
	struct batman_if *batman_if;
	struct client_node *client;
	int i;

	debug_all( "set_readfds():... \n");
	
	FD_ZERO(&receive_wait_set);
	receive_max_sock = 0;
	
	receive_max_sock = ifevent_sk;
	FD_SET(ifevent_sk, &receive_wait_set);
	
	if ( receive_max_sock < unix_sock )
		receive_max_sock = unix_sock;
	
	FD_SET(unix_sock,  &receive_wait_set);
	
	list_for_each( list_pos, &unix_clients ) {
		
		client = list_entry( list_pos, struct client_node, list );

		if ( receive_max_sock < client->fd )
			receive_max_sock = client->fd;
		
		FD_SET( client->fd, &receive_wait_set );
	
	}
	
	for ( i = DBGL_MIN; i <= DBGL_MAX; i++ ) {
		
		list_for_each( list_pos, &dbgl_clients[i] ) {
			
			client = list_entry( list_pos, struct client_node, list );
	
			if ( client->fd == STDOUT_FILENO )
				continue;
			
			if ( receive_max_sock < client->fd )
				receive_max_sock = client->fd;
			
			FD_SET( client->fd, &receive_wait_set );
		
		}
	}
	
	list_for_each(list_pos, &if_list) {
		
		batman_if = list_entry(list_pos, struct batman_if, list);

		if (batman_if->if_active && !batman_if->is_lo ) {
			
			if (batman_if->udp_recv_sock > receive_max_sock)
				receive_max_sock = batman_if->udp_recv_sock;

			FD_SET(batman_if->udp_recv_sock, &receive_wait_set);
			
			if (batman_if->udp_send_sock > receive_max_sock)
				receive_max_sock = batman_if->udp_send_sock;

			FD_SET(batman_if->udp_send_sock, &receive_wait_set);
			
		}
	}
}

int is_interface_up(char *dev)
{
	struct ifreq int_req;
	int sock;

	if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
		return 0;

	memset(&int_req, 0, sizeof (struct ifreq));
	strncpy(int_req.ifr_name, dev, IFNAMSIZ - 1);

	if (ioctl(sock, SIOCGIFFLAGS, &int_req) < 0)
		goto failure;

	if (!(int_req.ifr_flags & IFF_UP))
		goto failure;

	if (ioctl(sock, SIOCGIFADDR, &int_req) < 0)
		goto failure;
	
	close (sock);
	return 1;

failure:
	close (sock);
	return 0;
	
}


void deactivate_interface( struct batman_if *batman_if ) {

	debug_output(DBGL_SYSTEM, "deactivating interface: %s\n", batman_if->dev);
	
	if ( batman_if->if_num != 0 ) {
				
		prepare_add_del_own_hna( NULL, batman_if->addr.sin_addr.s_addr, 32, YES, A_TYPE_INTERFACE, REQ_NONE );
				
		add_del_own_hna( NO );	
		
	}
	
	if (batman_if->udp_recv_sock != 0)
		close(batman_if->udp_recv_sock);
	
	batman_if->udp_recv_sock = 0;

	if (batman_if->udp_send_sock != 0)
		close(batman_if->udp_send_sock);

	batman_if->udp_send_sock = 0;

	
	batman_if->if_active = 0;
	active_ifs--;

	restore_kernel_config ( batman_if );

	changed_readfds++;
}

void activate_interface(struct batman_if *bif)
{
	struct ifreq int_req;
	int set_on = 1, sock_opts;
	char ifaddr_str[ADDR_STR_LEN], str2[ADDR_STR_LEN]; 
	//char fake_arg[ADDR_STR_LEN + 4]
	
	bif->is_lo =  strcmp( "lo", bif->dev_phy ) == 0 ? YES : NO;

	if ( ( bif->udp_send_sock = socket( PF_INET, SOCK_DGRAM, 0 ) ) < 0 ) {

		debug_output(DBGL_SYSTEM, "Error - can't create send socket: %s\n", strerror(errno) );
		
		if ( bif->is_lo )
			cleanup_all( CLEANUP_FAILURE );
		
		goto error;

	}
	
	
	memset( &int_req, 0, sizeof (struct ifreq) );
	strncpy( int_req.ifr_name, bif->dev, IFNAMSIZ - 1 );

	if ( ioctl( bif->udp_send_sock, SIOCGIFADDR, &int_req ) < 0 ) {

		debug_output(DBGL_SYSTEM, "Error - can't get IP address of interface %s: %s\n", bif->dev, strerror(errno) );
		
		if ( bif->is_lo )
			cleanup_all( CLEANUP_FAILURE );
		
		goto error;

	}

	bif->addr.sin_family = AF_INET;
	bif->addr.sin_port = htons(ogm_port);
	bif->addr.sin_addr.s_addr = ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr;

	if (bif->addr.sin_addr.s_addr == 0) {

		debug_output(DBGL_SYSTEM, "Error - invalid ip address detected (0.0.0.0): %s\n", bif->dev);
		
		if ( bif->is_lo )
			cleanup_all( CLEANUP_FAILURE );
		
		goto error;

	}

	if ( ioctl( bif->udp_send_sock, SIOCGIFBRDADDR, &int_req ) < 0 ) {

		debug_output(DBGL_SYSTEM, "Error - can't get broadcast IP address of interface %s: %s\n", bif->dev, strerror(errno) );
		
		if ( bif->is_lo )
			cleanup_all( CLEANUP_FAILURE );
		
		goto error;

	}

	bif->broad.sin_family = AF_INET;
	bif->broad.sin_port = htons(ogm_port);
	bif->broad.sin_addr.s_addr = ((struct sockaddr_in *)&int_req.ifr_broadaddr)->sin_addr.s_addr;

	if ( bif->broad.sin_addr.s_addr == 0 ) {

		debug_output(DBGL_SYSTEM, "Error - invalid broadcast address detected (0.0.0.0): %s\n", bif->dev );
		
		if ( bif->is_lo )
			cleanup_all( CLEANUP_FAILURE );
		
		goto error;

	}

	
	if ( ioctl( bif->udp_send_sock, SIOCGIFINDEX, &int_req ) < 0 ) {

		debug_output(DBGL_SYSTEM, "Error - can't get index of interface %s: %s\n", bif->dev, strerror(errno) );
		
		if ( bif->is_lo )
			cleanup_all( CLEANUP_FAILURE );
		
		goto error;

	}

	bif->if_index = int_req.ifr_ifindex;

	if ( ioctl( bif->udp_send_sock, SIOCGIFNETMASK, &int_req ) < 0 ) {

		debug_output(DBGL_SYSTEM, "Error - can't get netmask address of interface %s: %s\n", bif->dev, strerror(errno) );
		
		if ( bif->is_lo )
			cleanup_all( CLEANUP_FAILURE );
		
		goto error;

	}

	bif->netaddr = ( ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr & bif->addr.sin_addr.s_addr );
	bif->netmask = get_set_bits( ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr );

	if ( bif->is_lo ) {
		
		if ( bif->if_num != 0 || bif->netmask != 32 || bif->addr.sin_addr.s_addr != bif->broad.sin_addr.s_addr ) {
			
			debug_output( DBGL_SYSTEM, "ERROR - loopback interface MUST BE primary interface\n");
			debug_output( DBGL_SYSTEM, "ERROR - netmask of loopback interface MUST BE 32\n");
			debug_output( DBGL_SYSTEM, "ERROR - ip address and broadcast address of loopback interface MUST BE the same\n");
			
			cleanup_all( CLEANUP_FAILURE );
		}
		
		debug_output( DBGL_SYSTEM, "detected loopback interface %s as primary interface\n", bif->dev, bif->dev);

	} else {
	
		/* check if interface is a wireless interface */
	
		if (  (bif->is_wlan = (ioctl( bif->udp_send_sock, SIOCGIWNAME, &int_req ) < 0 ? NO : YES ))  )
			debug_output( DBGL_SYSTEM, "detected wireless interface %s  (use %s /l to correct this assumption)\n", bif->dev, bif->dev);
		else 
			debug_output( DBGL_SYSTEM, "detected non-wireless interface %s  (use %s /w to correct this assumption)\n", bif->dev, bif->dev);
	
	}
	
	
	if ( setsockopt( bif->udp_send_sock, SOL_SOCKET, SO_BROADCAST, &set_on, sizeof(set_on) ) < 0 ) {

		debug_output(DBGL_SYSTEM, "Error - can't enable broadcasts: %s\n", strerror(errno) );
		goto error;

	}

	// bind send socket to interface name
	if ( bind_to_iface( bif->udp_send_sock, bif->dev_phy ) < 0 ) {

		debug_output(DBGL_SYSTEM, "Cannot bind socket to device %s : %s \n", bif->dev, strerror(errno));
		goto error;

	}
	
	// bind send socket to address 
	if ( bind( bif->udp_send_sock, (struct sockaddr *)&bif->addr, sizeof(struct sockaddr_in) ) < 0 ) {

		debug_output(DBGL_SYSTEM, "Error - can't bind send socket: %s\n", strerror(errno) );
		goto error;

	}

	// make udp send socket non blocking
	sock_opts = fcntl(bif->udp_send_sock, F_GETFL, 0);
	fcntl(bif->udp_send_sock, F_SETFL, sock_opts | O_NONBLOCK);

	
#ifdef SO_TIMESTAMP
	if (setsockopt(bif->udp_send_sock, SOL_SOCKET, SO_TIMESTAMP, &set_on, sizeof(set_on)))
		debug_output(DBGL_SYSTEM, "Warning: No SO_TIMESTAMP support, despite being defined, falling back to SIOCGSTAMP\n");
#else
	debug_output(DBGL_SYSTEM, "Warning: No SO_TIMESTAMP support, falling back to SIOCGSTAMP\n");
#endif

	if ( !bif->is_lo ) {

		// get recv socket
		if ( ( bif->udp_recv_sock = socket( PF_INET, SOCK_DGRAM, 0 ) ) < 0 ) {
	
			debug_output(3, "Error - can't create receive socket: %s\n", strerror(errno) );
			goto error;
	
		}
		
		// bind recv socket to interface name
		if ( bind_to_iface( bif->udp_recv_sock, bif->dev_phy ) < 0 ) {
	
			debug_output(3, "Cannot bind socket to device %s : %s \n", bif->dev, strerror(errno));
			goto error;
	
		}
	
		// bind recv socket to address 
		if ( bind( bif->udp_recv_sock, (struct sockaddr *)&bif->broad, sizeof(struct sockaddr_in) ) < 0 ) {
	
			debug_output(3, "Error - can't bind receive socket: %s\n", strerror(errno));
			goto error;
	
		}
	
	}
	
	check_kernel_config( bif, YES /*init*/ );
	
	//apply default values
	bif->packet_out_len = sizeof( struct bat_header );
	bif->if_send_clones = wl_clones;
	bif->if_ttl = ttl;
	bif->send_ogm_only_via_owning_if = NO;

	//overwrite default values with customized values
	if( !bif->is_wlan )
		bif->if_send_clones = DEF_LAN_CLONES;
	
	/*
	if ( bif->if_num != 0  &&  !(bif->dont_make_ip_hna_if_conf == YES) ) {
		
		//addr_to_string( bif->addr.sin_addr.s_addr, ifaddr_str, sizeof(ifaddr_str) );
		//sprintf( fake_arg, "%s/32", ifaddr_str);
		//prepare_add_del_own_hna( fake_arg,0,0, NO, A_TYPE_INTERFACE, REQ_NONE );
		prepare_add_del_own_hna( NULL, bif->addr.sin_addr.s_addr, 32, NO, A_TYPE_INTERFACE, REQ_NONE );

		bif->if_ttl = 1;
		bif->send_ogm_only_via_owning_if = YES;
	
	}
	*/
	
	if ( bif->if_num != 0  &&  ( bif->hna_if_conf == YES  ||  (nonprimary_hna == YES  &&  bif->hna_if_conf != NO) ) ) {
		
		prepare_add_del_own_hna( NULL, bif->addr.sin_addr.s_addr, 32, NO, A_TYPE_INTERFACE, REQ_NONE );
		
	}

	if ( bif->if_num != 0 ) {

		bif->if_ttl = 1;
		bif->send_ogm_only_via_owning_if = YES;
	
	}

	
	if ( bif->if_send_clones_conf != -1 )
		bif->if_send_clones =  bif->if_send_clones_conf;
	
	if ( bif->if_ttl_conf != -1 )
		bif->if_ttl = bif->if_ttl_conf;
	
	if ( bif->send_ogm_only_via_owning_if_conf  != -1 )
		bif->send_ogm_only_via_owning_if = bif->send_ogm_only_via_owning_if_conf;
	
	
	//prepare originator
	bif->out.ttl = bif->if_ttl;
	bif->out.orig = bif->addr.sin_addr.s_addr;
	
	
	//prepare extenson messages:
	my_pip_ext_array->EXT_PIP_FIELD_ADDR = (list_entry( (&if_list)->next, struct batman_if, list ))->addr.sin_addr.s_addr;


	bif->if_active = 1;
	active_ifs++;

	//activate selector for active interfaces
	changed_readfds++;
	
	addr_to_string( bif->addr.sin_addr.s_addr, ifaddr_str, sizeof(ifaddr_str) );
	addr_to_string( bif->broad.sin_addr.s_addr, str2, sizeof (str2));
	
	debug_output( DBGL_CHANGES, "activated interface %s %s/%d broadcast address %s\n", bif->dev, ifaddr_str, bif->netmask, str2 );

	return;

error:
	deactivate_interface( bif );
	
}

void init_interface(struct batman_if *batman_if)
{
	char *colon_ptr;

	if (strlen( batman_if->dev ) > IFNAMSIZ - 1) {
		printf("Error - interface name too long: %s\n", batman_if->dev);
		cleanup_all( CLEANUP_FAILURE );
	}

	sprintf( batman_if->dev_phy, "%s", batman_if->dev);

	/* if given interface is an alias record physical interface name*/
	if ( ( colon_ptr = strchr( batman_if->dev_phy, ':' ) ) != NULL )
		*colon_ptr = '\0';

	
	if (is_interface_up(batman_if->dev))
		activate_interface(batman_if);
	else 
		debug_output( DBGL_SYSTEM, "Not using interface %s (retrying later): interface not active\n", batman_if->dev);


}


void check_interfaces() {
	
	struct list_head *list_pos;
	struct batman_if *batman_if;
	uint8_t purge_origs = NO;
	//char ifaddr_str[ADDR_STR_LEN];
	//char fake_arg[ADDR_STR_LEN + 4]


	list_for_each(list_pos, &if_list) {
		
		int deactivate_if = NO;

		batman_if = list_entry(list_pos, struct batman_if, list);

		if ((!batman_if->if_active) && (is_interface_up(batman_if->dev))) {
			
			debug_output( 0, "WARNING: Detected active but unused interface:%s ! Going to activate\n", batman_if->dev );
			activate_interface(batman_if);
			add_del_own_hna( NO  /*do not purge*/ );
			
			if( batman_if->if_num == 0  &&  batman_if->if_active  &&  gateway_class  &&  (one_way_tunnel || two_way_tunnel)  &&  probe_tun(0) )
				start_gw_service();
		
		} else if ((batman_if->if_active) && (!is_interface_up(batman_if->dev))) {
			
			debug_output( 0, "WARNING: Detected inactive but used interface:%s ! Going to deactivate.. \n", batman_if->dev );
			deactivate_if = YES;

		/* Interface properties might have changed */
		} else if ((batman_if->if_active) && (is_interface_up(batman_if->dev))) {
			
			struct ifreq int_req;

			memset( &int_req, 0, sizeof (struct ifreq) );
			strncpy( int_req.ifr_name, batman_if->dev, IFNAMSIZ - 1 );

			if ( ioctl( batman_if->udp_send_sock, SIOCGIFADDR, &int_req ) < 0 ) {

				debug_output(0, "WARNING: can't get IP address of interface %s: %s\n", batman_if->dev, strerror(errno) );
				deactivate_if = YES;

			} else if ( batman_if->addr.sin_addr.s_addr != ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr ) {
				
				debug_output(0, "WARNING: IP address of interface %s: changed !!\n", batman_if->dev );
				deactivate_if = YES;
				
			} else if ( ioctl( batman_if->udp_send_sock, SIOCGIFBRDADDR, &int_req ) < 0 ) {

				debug_output(0, "WARNING: Can't get broadcast IP address of interface %s: %s\n", batman_if->dev, strerror(errno) );
				deactivate_if = YES;

			} else if ( batman_if->broad.sin_addr.s_addr != ((struct sockaddr_in *)&int_req.ifr_broadaddr)->sin_addr.s_addr ) {

				debug_output(0, "WARNING: Broadcast address of  interface %s changed \n", batman_if->dev );
				deactivate_if = YES;

			} else if ( ioctl( batman_if->udp_send_sock, SIOCGIFNETMASK, &int_req ) < 0 ) {

				debug_output(0, "WARNING: can't get netmask address of interface %s: %s\n", batman_if->dev, strerror(errno) );
				deactivate_if = YES;

			} else if ( batman_if->netaddr != ( ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr & batman_if->addr.sin_addr.s_addr ) ) {
				 
				debug_output(0, "WARNING: Net address of  interface %s changed \n", batman_if->dev );
				deactivate_if = YES;
			
			} else if ( batman_if->netmask != get_set_bits( ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr ) ) {
				
				debug_output(0, "WARNING: Netmask address of  interface %s changed from %d to %d \n", batman_if->dev, batman_if->netmask, get_set_bits( ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr ) );
				deactivate_if = YES;
			
			}

		}
		
		if ( deactivate_if ) {
				
			purge_origs = YES;
			
			deactivate_interface( batman_if );
			
				
			debug_output( 0, "WARNING: Interface %s deactivated \n", batman_if->dev );
		}
	
	}
	
	if ( purge_origs ) {
		
		// if there is a gw-client thread: stop it now, it restarts automatically
		del_default_route(); 
									
		// if there is a gw thread: stop it now
		stop_gw_service();
									
		purge_orig( 0 );
		
		if ( gateway_class  &&  (one_way_tunnel || two_way_tunnel)  &&  probe_tun(0) )
			start_gw_service();

	}
		
}








void stop_gw_service ( void ) {
	
	my_gw_ext_array_len = 0;
	memset( my_gw_ext_array, 0, sizeof(struct ext_packet) );

	gw_thread_finish = YES;
	
	if ( gw_thread_id > 0 ) {
		pthread_join( gw_thread_id, NULL );
		gw_thread_id = 0;
	}
	
	gw_thread_finish = NO;
	
}



void start_gw_service ( void ) {

	int32_t sock_opts;
	struct gw_listen_arg *gw_listen_arg;
	struct sockaddr_in addr;

	
	debug_output( 3, "start_gw_service () \n");
	
	// join old thread if not already done
	stop_gw_service();

	if (!( gw_thread_id == 0  &&  gateway_class  &&  ( two_way_tunnel || one_way_tunnel ) &&  (list_entry( (&if_list)->next, struct batman_if, list ))->if_active ) )
		return;
	
	/* TODO: This needs a better security concept...
	if ( my_gw_port == 0 ) */
		my_gw_port = ogm_port + 1;
	
	/* TODO: This needs a better security concept...
	if ( my_gw_addr == 0 ) */
		my_gw_addr = (list_entry( (&if_list)->next, struct batman_if, list ))->addr.sin_addr.s_addr ;
			

	
	memset( my_gw_ext_array, 0, sizeof(struct ext_packet) );
		
	my_gw_ext_array->EXT_FIELD_MSG  = YES;
	my_gw_ext_array->EXT_FIELD_TYPE = EXT_TYPE_GW;
	
	my_gw_ext_array->EXT_GW_FIELD_GWFLAGS = ( ( two_way_tunnel || one_way_tunnel ) ? gateway_class : 0 );
	my_gw_ext_array->EXT_GW_FIELD_GWTYPES = ( gateway_class ? ( (two_way_tunnel?TWO_WAY_TUNNEL_FLAG:0) | (one_way_tunnel?ONE_WAY_TUNNEL_FLAG:0) ) : 0);
	
	my_gw_ext_array->EXT_GW_FIELD_GWPORT = htons( my_gw_port );
	my_gw_ext_array->EXT_GW_FIELD_GWADDR = my_gw_addr;
	
	my_gw_ext_array_len = 1;
	
	
	gw_listen_arg = debugMalloc( sizeof( struct gw_listen_arg ), 223 );
	
	memset( gw_listen_arg, 0, sizeof( struct gw_listen_arg ) );

	gw_listen_arg->prefix = gw_tunnel_prefix;
	gw_listen_arg->netmask = gw_tunnel_netmask;
	gw_listen_arg->port = my_gw_port;
	gw_listen_arg->owt = one_way_tunnel;
	gw_listen_arg->twt = two_way_tunnel;
	gw_listen_arg->lease_time = tunnel_ip_lease_time;
	
	
	if( (gw_listen_arg->gw_client_list = debugMalloc( (0xFFFFFFFF>>gw_tunnel_netmask) * sizeof( struct gw_client* ), 210 ) ) == NULL ) {
	
		debug_output( 0, "Error - start_gw_service(): could not allocate memory for gw_client_list \n");
		cleanup_all( CLEANUP_FAILURE );
	}
	
	memset( gw_listen_arg->gw_client_list, 0, (0xFFFFFFFF>>gw_tunnel_netmask) * sizeof( struct gw_client* ) );

	gw_listen_arg->sock = socket( PF_INET, SOCK_DGRAM, 0 );

	if ( gw_listen_arg->sock < 0 ) {

		debug_output( 0, "Error - can't create tunnel socket: %s", strerror(errno) );
		cleanup_all( CLEANUP_FAILURE );

	}

	memset( &addr, 0, sizeof( struct sockaddr_in ) );
	addr.sin_family = AF_INET;
	addr.sin_port = htons( my_gw_port );
	addr.sin_addr.s_addr = (list_entry( (&if_list)->next, struct batman_if, list ))->addr.sin_addr.s_addr;
	
	if ( bind( gw_listen_arg->sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in) ) < 0 ) {

		debug_output( 0, "Error - can't bind tunnel socket: %s\n", strerror(errno) );
		cleanup_all( CLEANUP_FAILURE );

	}

	/* make udp socket non blocking */
	sock_opts = fcntl( gw_listen_arg->sock, F_GETFL, 0 );
	fcntl( gw_listen_arg->sock, F_SETFL, sock_opts | O_NONBLOCK );

	pthread_create( &gw_thread_id, NULL, &gw_listen, gw_listen_arg );

}


void debug_config( int fd )
{
	dprintf(fd, "source_version=%s\n", SOURCE_VERSION);
	dprintf(fd, "compat_version=%i\n", COMPAT_VERSION);
	dprintf(fd, "vis_compat_version=%i\n", VIS_COMPAT_VERSION);
	dprintf(fd, "ogm_port=%i\n", ogm_port );
	dprintf(fd, "gw_port=%i\n", my_gw_port );
	dprintf(fd, "vis_port=%i\n", vis_port );
	dprintf(fd, "unix_socket_path=%s\n", unix_path);
	dprintf(fd, "own_ogm_jitter=%i\n", JITTER);
	dprintf(fd, "default_ttl=%i\n", ttl);
	dprintf(fd, "originator_timeout=%i\n", PURGE_TIMEOUT);
	dprintf(fd, "rt_table_interfaces=%i\n", BATMAN_RT_TABLE_INTERFACES);
	dprintf(fd, "rt_table_networks=%i\n", BATMAN_RT_TABLE_NETWORKS);
	dprintf(fd, "rt_table_hosts=%i\n", BATMAN_RT_TABLE_HOSTS);
	dprintf(fd, "rt_table_unreach=%i\n", BATMAN_RT_TABLE_UNREACH);
	dprintf(fd, "rt_table_tunnel=%i\n", BATMAN_RT_TABLE_TUNNEL);
	
	dprintf(fd, "rt_prio_interfaces=%i\n", BATMAN_RT_PRIO_INTERFACES);
	dprintf(fd, "rt_prio_networks=%i\n", BATMAN_RT_PRIO_NETWORKS);
	dprintf(fd, "rt_prio_unreach=%i\n", BATMAN_RT_PRIO_UNREACH);
	dprintf(fd, "rt_prio_tunnel=%i\n", BATMAN_RT_PRIO_TUNNEL);
	
	
}


void debug_params( int fd )
{
	
	struct list_head *list_pos;
	char  str[ADDR_STR_LEN];

	
	dprintf( fd, "%s [not-all-options-displayed]", prog_name );

	if ( routing_class > 0 )
		dprintf( fd, " -r %i", routing_class );

	if ( pref_gateway > 0 ) {

		addr_to_string( pref_gateway, str, sizeof (str) );

		dprintf( fd, " -p %s", str );

	}

	if ( gateway_class > 0 ) {

		int download_speed, upload_speed;

		get_gw_speeds( gateway_class, &download_speed, &upload_speed );

		dprintf( fd, " -g %i%s/%i%s", 
			 ( download_speed > 2048 ? download_speed / 1024 : download_speed ), 
			   ( download_speed > 2048 ? "MBit" : "KBit" ), 
			     ( upload_speed > 2048 ? upload_speed / 1024 : upload_speed ),
			       ( upload_speed > 2048 ? "MBit" : "KBit" ) );

	}

	list_for_each( list_pos, &my_hna_list ) {

		struct hna_node *hna_node = list_entry( list_pos, struct hna_node, list );

		addr_to_string( hna_node->key.addr, str, sizeof (str) );
									
		if ( hna_node->enabled && hna_node->key.KEY_FIELD_ATYPE == A_TYPE_INTERFACE )
			dprintf( fd, " -a %s/%i", str, hna_node->key.KEY_FIELD_ANETMASK );

	}

	list_for_each( list_pos, &my_srv_list ) {

		struct srv_node *srv_node = list_entry( list_pos, struct srv_node, list );

		addr_to_string( srv_node->srv_addr, str, sizeof (str) );
									
		if ( srv_node->enabled )
			dprintf( fd, " --%s %s:%d:%i", ADD_SRV_SWITCH, str, srv_node->srv_port, srv_node->srv_seqno );

	}
								
	list_for_each( list_pos, &if_list ) {

		struct batman_if *batman_if = list_entry( list_pos, struct batman_if, list );
		
		dprintf( fd, " %s", batman_if->dev );

	}
	
	dprintf( fd, "\n" );

}
