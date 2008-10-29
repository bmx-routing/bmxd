/*
 * Copyright (C) 2006 BATMAN contributors:
 * Marek Lindner, Axel Neumann, Thomas Lopatic
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

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <arpa/inet.h>    /* inet_ntop() */
#include <errno.h>
#include <unistd.h>       /* close() */
#include <linux/if.h>     /* ifr_if, ifr_tun */
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "../batman.h"
#include "../os.h"
#include "../control.h"

int netlink_sock = -1;

int ifevent_sk = -1;


int32_t forward_orig=-1, if_rp_filter_all_orig=-1, if_rp_filter_default_orig=-1, if_send_redirects_all_orig=-1, if_send_redirects_default_orig=-1;

static char lo_dev_string[] = "lo\0 ";

SIMPEL_LIST( rules_list );

SIMPEL_LIST( routes_list );


int open_ifevent_netlink_sk( void ) {
	
	struct sockaddr_nl sa;
	
	memset (&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR;

	if ( ( ifevent_sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) ) < 0 ) {
		debug_output( 0, "Error - can't create af_netlink socket for reacting on if up/down events: %s", strerror(errno) );
		ifevent_sk = 0;
		return -1;
	}
	
	if ( ( bind( ifevent_sk, (struct sockaddr*)&sa, sizeof(sa) ) ) < 0 ) {
		debug_output( 0, "Error - can't bind af_netlink socket for reacting on if up/down events: %s", strerror(errno) );
		ifevent_sk = 0;
		return -1;
	}
	
	changed_readfds++;
	
	return ifevent_sk;

}

void close_ifevent_netlink_sk( void ) {
	
	if ( ifevent_sk > 0 )
		close( ifevent_sk );
	
	ifevent_sk = 0;

}

void recv_ifevent_netlink_sk( void ) {
	int len=0;
	char buf[4096]; //test this with a very small value !!
	struct iovec iov = { buf, sizeof(buf) };
	struct sockaddr_nl sa;
	struct msghdr msg = { (void *)&sa, sizeof(sa), &iov, 1, NULL, 0, 0 };

	len = recvmsg (ifevent_sk, &msg, 0);
	
	//so fare I just want to consume the pending message...	
	
}


int open_netlink_socket( void ) {
	
	if ( ( netlink_sock = socket( PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE ) ) < 0 ) {

		debug_output( 0, "Error - can't create netlink socket for routing table manipulation: %s", strerror(errno) );
		netlink_sock = 0;
		return -1;

	}
	
	
	if ( fcntl( netlink_sock, F_SETFL, O_NONBLOCK) < 0 ) {
		
		debug_output( 0, "Error - can't set netlink socket nonblocking : (%s)",  strerror(errno));
		close(netlink_sock);
		netlink_sock = 0;
		return -1;
	}
	
	return netlink_sock;

}

void close_netlink_socket( void ) {
	
	if ( netlink_sock > 0 )
		close( netlink_sock );
		
	netlink_sock = 0;

}

void init_route( void ) {
	
	if( open_netlink_socket() < 0 )
		exit(EXIT_FAILURE);
	
	if ( open_ifevent_netlink_sk() < 0 )
		exit(EXIT_FAILURE);
	
}

void cleanup_route( void ) {
	
	close_ifevent_netlink_sk();	
	
	close_netlink_socket();
	
}

/***
 *
 * route types: 0 = RTN_UNICAST, 1 = THROW, 2 = UNREACHABLE
 *
 ***/
 


void add_del_route( uint32_t dest, uint8_t netmask, uint32_t router, uint32_t source, int32_t ifi, char *dev, uint8_t rt_table, int8_t route_type, int8_t del, int8_t track, int8_t debug ) {

	int len;
	uint32_t my_router;
	char buf[4096], str1[16], str2[16], str3[16];
	struct rtattr *rta;
	struct sockaddr_nl nladdr;
	struct iovec iov = { buf, sizeof(buf) };
	struct msghdr msg;
	struct nlmsghdr *nh;
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
		char buff[4 * ( sizeof(struct rtattr) + 4 )];
	} req;

	if ( ( no_policy_routing ) && ( ( route_type == 1 ) || ( route_type == 2 ) ) )
		return;

	inet_ntop( AF_INET, &dest, str1, sizeof (str1) );
	inet_ntop( AF_INET, &router, str2, sizeof (str2) );
	inet_ntop( AF_INET, &source, str3, sizeof (str3) );

	if ( track ) {
		
		struct list_head *list_pos, *tmp_pos, *prev_pos = (struct list_head*)&routes_list;
		struct routes_node *rn=NULL;
		
		list_for_each_safe( list_pos, tmp_pos, &routes_list ) {
			
			rn = list_entry( list_pos, struct routes_node, list );
			
			if (    (rn->dest    == dest   )  &&  
				(rn->netmask == netmask)  &&
				(!router  || rn->router  == router )  &&
				(!source  || rn->source  == source )  &&
				rn->rt_table == rt_table &&
				rn->route_type == route_type ) 
			{
				break;
				
			} else {
				prev_pos = &rn->list;
				rn = NULL;
			}
		}
		
		if ( del && !rn)  {
			return;
		
		} else if ( del && rn ) {
			
			list_del( prev_pos, list_pos, &routes_list );
			debugFree( rn, 1742 );
			
		} else if ( !del && !rn ) {
			
			rn = debugMalloc( sizeof( struct routes_node ), 742 );
			memset( rn, 0, sizeof( struct routes_node ) );
			INIT_LIST_HEAD( &rn->list );
			rn->dest = dest;
			rn->netmask = netmask;
			rn->router = router;
			rn->source = source;
			rn->rt_table = rt_table;
			rn->route_type = route_type;
			
			list_add_tail( &rn->list, &routes_list );
			
		} else  { // (!del && rn)
			
			return;
			
		}
	
		if( debug )
			debug_output( DBGL_CHANGES, "%s route to %s via %s src %s dev %s, table %d, type %d \n", 
			      del?"del":"add", str1, str2, str3, dev, rt_table, route_type );

		
	}
	
	
	if ( router == dest ) {

		my_router = 0;

		if ( dest == 0 ) {

			if( debug )
				debug_all( "%s default route via %s %s (table %i)\n", del ? "Deleting" : "Adding", dev, str3, rt_table );

		} else {

			if( debug )
				debug_all( "%s route to %s via 0.0.0.0 (table %i - %s %s )\n", del ? "Deleting" : "Adding", str1, rt_table, dev, str3 );

		}

	} else {

		if( debug )
			debug_all( "%s %s to %s/%i via %s (table %i - %s %s )\n", del ? "Deleting" : "Adding", ( route_type == 1 ? "throw route" : ( route_type == 2 ? "unreachable route" : "route" ) ), str1, netmask, str2, rt_table, dev, str3 );
		
		my_router = router;

	}


	memset( &nladdr, 0, sizeof(struct sockaddr_nl) );
	memset( &req, 0, sizeof(req) );
	memset( &msg, 0, sizeof(struct msghdr) );

	nladdr.nl_family = AF_NETLINK;

	len = sizeof(struct rtmsg) + sizeof(struct rtattr) + 4;

	if ( route_type == 0 )
		len += 2 * ( sizeof(struct rtattr) + 4 );

	if ( source != 0 && route_type == 0 /* && my_router == 0 */ )
		len += 1 * ( sizeof(struct rtattr) + 4 );

	
	req.nlh.nlmsg_len = NLMSG_LENGTH(len);
	req.nlh.nlmsg_pid = getpid();
	req.rtm.rtm_family = AF_INET;
	req.rtm.rtm_table = rt_table;
	req.rtm.rtm_dst_len = netmask;

	if ( del ) {

		req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
		req.nlh.nlmsg_type = RTM_DELROUTE;
		req.rtm.rtm_scope = RT_SCOPE_NOWHERE;

	} else {

		req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
		req.nlh.nlmsg_type = RTM_NEWROUTE;
		
		if ( /* source != 0 && */ route_type == 0 && my_router == 0  ) {
			req.rtm.rtm_scope = RT_SCOPE_LINK;
		} else {
			req.rtm.rtm_scope = RT_SCOPE_UNIVERSE;
		}
		
		req.rtm.rtm_protocol = RTPROT_STATIC; // may be changed to some batman specific value - see <linux/rtnetlink.h>
		req.rtm.rtm_type = ( route_type == 1 ? RTN_THROW : ( route_type == 2 ? RTN_UNREACHABLE : RTN_UNICAST ) );

	}

	rta = (struct rtattr *)req.buff;
	rta->rta_type = RTA_DST;
	rta->rta_len = sizeof(struct rtattr) + 4;
	memcpy( ((char *)&req.buff) + sizeof(struct rtattr), (char *)&dest, 4 );

	if ( route_type == 0 ) {

		rta = (struct rtattr *)(req.buff + sizeof(struct rtattr) + 4);
		rta->rta_type = RTA_GATEWAY;
		rta->rta_len = sizeof(struct rtattr) + 4;
		memcpy( ((char *)&req.buff) + 2 * sizeof(struct rtattr) + 4, (char *)&my_router, 4 );

		rta = (struct rtattr *)(req.buff + 2 * sizeof(struct rtattr) + 8);
		rta->rta_type = RTA_OIF;
		rta->rta_len = sizeof(struct rtattr) + 4;
		memcpy( ((char *)&req.buff) + 3 * sizeof(struct rtattr) + 8, (char *)&ifi, 4 );

		if( source != 0 /* && my_router == 0 */ ) {
			rta = (struct rtattr *)(req.buff + 3 * sizeof(struct rtattr) + 12);
			rta->rta_type = RTA_PREFSRC;
			rta->rta_len = sizeof(struct rtattr) + 4;
			memcpy( ((char *)&req.buff) + 4 * sizeof(struct rtattr) + 12, (char *)&source, 4 );
		}
	}


	if ( sendto( netlink_sock, &req, req.nlh.nlmsg_len, 0, (struct sockaddr *)&nladdr, sizeof(struct sockaddr_nl) ) < 0 ) {

		if( debug )
			debug_output( 0, "Error - can't send message to kernel via netlink socket for routing table manipulation: %s", strerror(errno) );
		
		return;

	}

	
	while ( 1 ) {

		msg.msg_name = (void *)&nladdr;
		msg.msg_namelen = sizeof(nladdr);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = 0;
	
		len = recvmsg( netlink_sock, &msg, 0 );
	
		
		if ( len < 0 ) {
			
			if ( errno == EINTR ) {
				
				if( debug )
					debug_output( DBGL_SYSTEM, "WARNING - add_del_route(): (EINTR) %s \n", strerror(errno) );
				
				continue;
			}
			
			if ( errno == EWOULDBLOCK || errno == EAGAIN ) {
				//if( debug ) debug_output( DBGL_SYSTEM, "WARNING - add_del_route(): (EWOULDBLOCK || EAGAIN) %s \n", strerror(errno) );
				break;
			}
			
			if( debug )
				debug_output( DBGL_SYSTEM, "Error - add_del_route(): %s \n", strerror(errno) );
			
			continue;
				
		}
		
		if ( len == 0 ) {
			if( debug )
				debug_output( DBGL_SYSTEM, "Error - add_del_route(): netlink EOF\n" );
		}
		
		
		nh = (struct nlmsghdr *)buf;
	
		while ( NLMSG_OK(nh, len) ) {
	
			if ( nh->nlmsg_type == NLMSG_DONE )
				return;
	
			if ( ( nh->nlmsg_type == NLMSG_ERROR ) && ( ((struct nlmsgerr*)NLMSG_DATA(nh))->error != 0 ) ) {
				if( debug )
					debug_output( 0, "Error - can't %s %s to %s/%i via %s (table %i): %s\n", del ? "delete" : "add", ( route_type == 1 ? "throw route" : ( route_type == 2 ? "unreachable route" : "route" ) ), str1, netmask, str2, rt_table, strerror(-((struct nlmsgerr*)NLMSG_DATA(nh))->error) );
			}
	
			nh = NLMSG_NEXT( nh, len );
	
		}
	}
}



/***
 *
 * rule types: 0 = RTA_SRC, 1 = RTA_DST, 2 = RTA_IIF
 *
 ***/
 
void add_del_rule( uint32_t network, uint8_t netmask, uint8_t rt_table, uint32_t prio, char *iif, int8_t rule_type, int8_t del, int8_t track ) {

	int len;
	char buf[4096], str1[16];
	struct rtattr *rta;
	struct sockaddr_nl nladdr;
	struct iovec iov = { buf, sizeof(buf) };
	struct msghdr msg;
	struct nlmsghdr *nh;
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
		char buff[2 * ( sizeof(struct rtattr) + 4 )];
	} req;


	inet_ntop( AF_INET, &network, str1, sizeof (str1) );
	
	
	if ( no_policy_routing )
		return;
		
	if ( track ) {
		
		struct list_head *list_pos, *tmp_pos, *prev_pos = (struct list_head*)&rules_list;
		struct rules_node *rn = NULL;
		
		
		list_for_each_safe( list_pos, tmp_pos, &rules_list ) {
			
			rn = list_entry( list_pos, struct rules_node, list );
			
			if (    rn->network == network   &&  
				rn->netmask == netmask   &&
				rn->rt_table == rt_table &&
				rn->iif == iif &&
				rn->rule_type == rule_type ) 
			{
					
				break;
				
			} else {
				prev_pos = &rn->list;
				rn = NULL;
			}
			
		}
		
		if ( del && !rn)  {
			
			return;
			
		} else if ( del && rn ) {
			
			list_del( prev_pos, list_pos, &rules_list );
			debugFree( rn, 1741 );
			
		} else if ( !del && !rn ) {
			
			rn = debugMalloc( sizeof( struct rules_node ), 741 );
			memset( rn, 0, sizeof( struct rules_node ) );
			INIT_LIST_HEAD( &rn->list );
			rn->network = network;
			rn->netmask = netmask;
			rn->rt_table = rt_table;
			rn->prio = prio;
			rn->iif = iif;
			rn->rule_type = rule_type;
			
			list_add_tail( &rn->list, &rules_list );
			
		} else  { // (!del && rn)
			
			return;
			
		}

		debug_output(DBGL_CHANGES, "%s rule from %s/%d, table %d, prio %d, if %s, type %d \n",
			     del?"del":"add", str1, netmask, rt_table, prio, iif, rule_type );

		
	}
	
	memset( &nladdr, 0, sizeof(struct sockaddr_nl) );
	memset( &req, 0, sizeof(req) );
	memset( &msg, 0, sizeof(struct msghdr) );

	nladdr.nl_family = AF_NETLINK;

	len = sizeof(struct rtmsg) + sizeof(struct rtattr) + 4;

	if ( prio != 0 )
		len += sizeof(struct rtattr) + 4;

	req.nlh.nlmsg_len = NLMSG_LENGTH(len);
	req.nlh.nlmsg_pid = getpid();
	req.rtm.rtm_family = AF_INET;
	req.rtm.rtm_table = rt_table;

	debug_all( "%s ip rule pref %d %s %s/%d  lookup table %d \n", 
		      (del ? "Deleting" : "Adding"), 
		       prio, 
		       (rule_type == 0 ? "from" : (rule_type == 1 ? "to" : "dev" ) ), 
			((rule_type == 0 || rule_type == 1) ? str1: ( rule_type == 2 ? iif : "??" )), 
			netmask, 
    			rt_table );

	
	if ( del ) {

		req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
		req.nlh.nlmsg_type = RTM_DELRULE;
		req.rtm.rtm_scope = RT_SCOPE_NOWHERE;

	} else {

		req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
		req.nlh.nlmsg_type = RTM_NEWRULE;
		req.rtm.rtm_scope = RT_SCOPE_UNIVERSE;
		req.rtm.rtm_protocol = RTPROT_STATIC;
		req.rtm.rtm_type = RTN_UNICAST;

	}


	if ( rule_type != 2 ) {

		rta = (struct rtattr *)req.buff;

		if ( rule_type == 1 ) {

			req.rtm.rtm_dst_len = netmask;

			rta->rta_type = RTA_DST;

		} else {

			req.rtm.rtm_src_len = netmask;

			rta->rta_type = RTA_SRC;

		}

		rta->rta_len = sizeof(struct rtattr) + 4;
		memcpy( ((char *)&req.buff) + sizeof(struct rtattr), (char *)&network, 4 );

	} else {

		if ( del ) {

			rta = (struct rtattr *)req.buff;
			rta->rta_type = RTA_SRC;
			rta->rta_len = sizeof(struct rtattr) + 4;
			memcpy( ((char *)&req.buff) + sizeof(struct rtattr), (char *)&network, 4 );

		} else {

			rta = (struct rtattr *)req.buff;
			rta->rta_type = RTA_IIF;
			rta->rta_len = sizeof(struct rtattr) + 4;
			memcpy( ((char *)&req.buff) + sizeof(struct rtattr), iif, 4 );

		}

	}


	if ( prio != 0 ) {

		rta = (struct rtattr *)(req.buff + sizeof(struct rtattr) + 4);
		rta->rta_type = RTA_PRIORITY;
		rta->rta_len = sizeof(struct rtattr) + 4;
		memcpy( ((char *)&req.buff) + 2 * sizeof(struct rtattr) + 4, (char *)&prio, 4 );

	}


	if ( sendto( netlink_sock, &req, req.nlh.nlmsg_len, 0, (struct sockaddr *)&nladdr, sizeof(struct sockaddr_nl) ) < 0 ) {

		debug_output( 0, "Error - can't send message to kernel via netlink socket for routing rule manipulation: %s \n", strerror(errno) );
		return;

	}
	

	while ( 1 ) {
	
		msg.msg_name = (void *)&nladdr;
		msg.msg_namelen = sizeof(nladdr);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = 0;
	
		len = recvmsg( netlink_sock, &msg, 0 );
	
		
		if ( len < 0 ) {
			
			if ( errno == EINTR ) {
				debug_output( DBGL_SYSTEM, "WARNING - add_del_rule(): (EINTR) %s \n", strerror(errno) );
				continue;
			}
			
			if ( errno == EWOULDBLOCK || errno == EAGAIN ) {
				//debug_output( DBGL_SYSTEM, "WARNING - add_del_rule(): (EWOULDBLOCK || EAGAIN) %s \n", strerror(errno) );
				break;
			}
			
			debug_output( DBGL_SYSTEM, "Error - add_del_rule(): %s \n", strerror(errno) );
			
			continue;
				
		}
		
		if ( len == 0 ) 
			debug_output( DBGL_SYSTEM, "Error - add_del_rule(): netlink EOF\n" );
		
		
		nh = (struct nlmsghdr *)buf;
		
		while ( NLMSG_OK(nh, len) ) {
	
			if ( nh->nlmsg_type == NLMSG_DONE )
				return;
	
			if ( ( nh->nlmsg_type == NLMSG_ERROR ) && ( ((struct nlmsgerr*)NLMSG_DATA(nh))->error != 0 ) ) {
	
				debug_output( DBGL_SYSTEM, "Error ?? can't %s rule %s %s/%i table %d, prio %d: %s\n", del ? "delete" : "add", ( rule_type == 1 ? "to" : "from" ), str1, netmask, rt_table, prio, strerror(-((struct nlmsgerr*)NLMSG_DATA(nh))->error) );
				
	
			}
	
			nh = NLMSG_NEXT( nh, len );
	
		}
	}

}



int add_del_interface_rules( int8_t del, uint8_t setup_tunnel, uint8_t setup_networks ) {

	int32_t tmp_fd;
	uint32_t len, addr, netaddr;
	uint8_t netmask, if_count = 1;
	char *buf, *buf_ptr;
	struct ifconf ifc;
	struct ifreq *ifr, ifr_tmp;
	struct batman_if *batman_if;

	struct list_head *notun_pos;
	struct notun_node *notun_node;
	uint32_t no_netmask;

	if ( no_policy_routing )
		return 1;
	
	
	tmp_fd = socket( AF_INET, SOCK_DGRAM, 0 );

	if ( tmp_fd < 0 ) {
		debug_output( 0, "Error - can't %s interface rules (udp socket): %s\n", del ? "delete" : "add", strerror(errno) );
		return -1;
	}


	len = 10 * sizeof(struct ifreq); /* initial buffer size guess (10 interfaces) */

	while ( 1 ) {

		buf = debugMalloc( len, 601 );
		ifc.ifc_len = len;
		ifc.ifc_buf = buf;

		if ( ioctl( tmp_fd, SIOCGIFCONF, &ifc ) < 0 ) {

			debug_output( 0, "Error - can't %s interface rules (SIOCGIFCONF): %s\n", del ? "delete" : "add", strerror(errno) );
			close( tmp_fd );
			debugFree( buf, 1601 );
			return -1;

		} else {

			if ( ifc.ifc_len < len )
				break;

		}

		len += 10 * sizeof(struct ifreq);
		debugFree( buf, 1601 );

	}

	for ( buf_ptr = buf; buf_ptr < buf + ifc.ifc_len; ) {

		ifr = (struct ifreq *)buf_ptr;
		buf_ptr += ( ifr->ifr_addr.sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr) ) + sizeof(ifr->ifr_name);

		/* ignore if not IPv4 interface */
		if ( ifr->ifr_addr.sa_family != AF_INET )
			continue;


		memset( &ifr_tmp, 0, sizeof (struct ifreq) );
		strncpy( ifr_tmp.ifr_name, ifr->ifr_name, IFNAMSIZ - 1 );

		if ( ioctl( tmp_fd, SIOCGIFFLAGS, &ifr_tmp ) < 0 ) {

			debug_output( 0, "Error - can't get flags of interface %s (interface rules): %s\n", ifr->ifr_name, strerror(errno) );
			close( tmp_fd );
			debugFree( buf, 1602 );
			return -1;

		}

		/* ignore if not up and running */
		if ( !( ifr_tmp.ifr_flags & IFF_UP ) || !( ifr_tmp.ifr_flags & IFF_RUNNING ) )
			continue;


		if ( ioctl( tmp_fd, SIOCGIFADDR, &ifr_tmp ) < 0 ) {

			debug_output( 0, "Error - can't get IP address of interface %s (interface rules): %s\n", ifr->ifr_name, strerror(errno) );
			close( tmp_fd );
			debugFree( buf, 1603 );
			return -1;

		}

		addr = ((struct sockaddr_in *)&ifr_tmp.ifr_addr)->sin_addr.s_addr;

		if ( ioctl( tmp_fd, SIOCGIFNETMASK, &ifr_tmp ) < 0 ) {

			debug_output( 0, "Error - can't get netmask address of interface %s (interface rules): %s\n", ifr->ifr_name, strerror(errno) );
			close( tmp_fd );
			debugFree( buf, 1604 );
			return -1;

		}

		netaddr = ( ((struct sockaddr_in *)&ifr_tmp.ifr_addr)->sin_addr.s_addr & addr );
		netmask = get_set_bits( ((struct sockaddr_in *)&ifr_tmp.ifr_addr)->sin_addr.s_addr );

		if( !no_throw_rules && setup_tunnel )
			add_del_route( netaddr, netmask, 0, 0, 0, ifr->ifr_name, BATMAN_RT_TABLE_TUNNEL,   1, del, YES/*track*/, YES );

		
		if( !no_prio_rules && setup_tunnel ) {
			uint8_t add_this_rule = YES;
			
			list_for_each(notun_pos, &notun_list) {

				notun_node = list_entry(notun_pos, struct notun_node, list);
				
				no_netmask = htonl( 0xFFFFFFFF<<(32 - notun_node->netmask ) );

				if ( ((notun_node->addr & no_netmask) == (netaddr & no_netmask))  ) {
					add_this_rule = NO;
					notun_node->match_found = YES;
				}
				
			}
			
			if ( no_lo_rule  &&  (netaddr & htonl( 0xFF000000 ) ) == ( htonl( 0x7F000000 /*127.0.0.0*/ ) ) ) {
				add_this_rule = NO;
			}

			
			if ( add_this_rule ) {
				add_del_rule( netaddr, netmask, BATMAN_RT_TABLE_TUNNEL, ( del ? 0 : BATMAN_RT_PRIO_TUNNEL /*+ if_count*/ ), 0, 0, del, YES /*track*/ );
				if_count++;
			}
			
			if ( !no_lo_rule && strncmp( ifr->ifr_name, "lo", IFNAMSIZ - 1 ) == 0 )
				add_del_rule( 0, 0, BATMAN_RT_TABLE_TUNNEL, BATMAN_RT_PRIO_TUNNEL, lo_dev_string, 2, del, YES /*track*/ );


		}
		
		if ( is_batman_if( ifr->ifr_name, &batman_if ) )
			continue;
		
		
		if( !no_throw_rules && setup_networks)
			add_del_route( netaddr, netmask, 0, 0, 0, ifr->ifr_name, BATMAN_RT_TABLE_NETWORKS, 1, del, YES/*track*/, YES  );
		

	}

	list_for_each(notun_pos, &notun_list) {

		notun_node = list_entry(notun_pos, struct notun_node, list);
				
		no_netmask = htonl( 0xFFFFFFFF<<(32 - notun_node->netmask ) );

		add_del_route( (notun_node->addr & no_netmask), notun_node->netmask, 0, 0, 0, "unknown", BATMAN_RT_TABLE_TUNNEL, 1, del, YES/*track*/, YES  );

	}

	
	close( tmp_fd );
	debugFree( buf, 1605 );

	return 1;

}

void flush_tracked_rules_and_routes( void ) {
	
	while ( !list_empty(&rules_list) ) {
		
		struct rules_node *rn = list_entry( (&rules_list)->next, struct rules_node, list );
		
		add_del_rule( rn->network, rn->netmask, rn->rt_table, rn->prio, rn->iif, rn->rule_type, YES, YES );
		
	}
	
	while ( !list_empty(&routes_list) ) {
		
		struct routes_node *rn = list_entry( (&routes_list)->next, struct routes_node, list );
		
		add_del_route( rn->dest, rn->netmask, rn->router, rn->source, 0, 0, rn->rt_table, rn->route_type, YES, YES, YES  );
		
	}

}

int flush_routes_rules( int8_t is_rule ) {

	int len, rtl;
	int32_t dest = 0, router = 0, ifi = 0;
	uint32_t prio = 0;
	int8_t rule_type = 0;
	char buf[8192], *dev = NULL;
	struct sockaddr_nl nladdr;
	struct iovec iov = { buf, sizeof(buf) };
	struct msghdr msg;
	struct nlmsghdr *nh;
	struct rtmsg *rtm;
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
	} req;
	struct rtattr *rtap;


	if ( ( no_policy_routing ) && ( is_rule ) )
		return 1;
	
	
	memset( &nladdr, 0, sizeof(struct sockaddr_nl) );
	memset( &req, 0, sizeof(req) );
	memset( &msg, 0, sizeof(struct msghdr) );

	nladdr.nl_family = AF_NETLINK;

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req));
	req.nlh.nlmsg_pid = getpid();
	req.rtm.rtm_family = AF_INET;

	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_type = ( is_rule ? RTM_GETRULE : RTM_GETROUTE );
	req.rtm.rtm_scope = RTN_UNICAST;

	if ( sendto( netlink_sock, &req, req.nlh.nlmsg_len, 0, (struct sockaddr *)&nladdr, sizeof(struct sockaddr_nl) ) < 0 ) {

		debug_output( 0, "Error - can't send message to kernel via netlink socket for flushing the routing table: %s", strerror(errno) );
		return -1;

	}

	msg.msg_name = (void *)&nladdr;
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;

	len = recvmsg( netlink_sock, &msg, 0 );
	nh = (struct nlmsghdr *)buf;

	while ( NLMSG_OK(nh, len) ) {

		if ( nh->nlmsg_type == NLMSG_DONE )
			break;

		if ( ( nh->nlmsg_type == NLMSG_ERROR ) && ( ((struct nlmsgerr*)NLMSG_DATA(nh))->error != 0 ) ) {

			debug_output( 0, "Error - can't flush %s: %s \n", ( is_rule ? "routing rules" : "routing table" ), strerror(-((struct nlmsgerr*)NLMSG_DATA(nh))->error) );
			return -1;

		}

		rtm = (struct rtmsg *)NLMSG_DATA(nh);
		rtap = (struct rtattr *)RTM_RTA(rtm);
		rtl = RTM_PAYLOAD(nh);

		nh = NLMSG_NEXT( nh, len );

		if ( ( rtm->rtm_table != BATMAN_RT_TABLE_UNREACH ) && ( rtm->rtm_table != BATMAN_RT_TABLE_INTERFACES ) && ( rtm->rtm_table != BATMAN_RT_TABLE_NETWORKS ) && ( rtm->rtm_table != BATMAN_RT_TABLE_HOSTS ) && ( rtm->rtm_table != BATMAN_RT_TABLE_TUNNEL ) )
			continue;

		if ( ( no_policy_routing ) && ( rtm->rtm_table != BATMAN_RT_TABLE_INTERFACES ) && ( rtm->rtm_table != BATMAN_RT_TABLE_NETWORKS ) && ( rtm->rtm_table != BATMAN_RT_TABLE_HOSTS ) )
			continue;
		
		while ( RTA_OK(rtap, rtl) ) {

			switch( rtap->rta_type ) {

				case RTA_DST:
					dest = *((int32_t *)RTA_DATA(rtap));
					rule_type = 1;
					break;

				case RTA_SRC:
					dest = *((int32_t *)RTA_DATA(rtap));
					rule_type = 0;
					break;

				case RTA_GATEWAY:
					router = *((int32_t *)RTA_DATA(rtap));
					break;

				case RTA_OIF:
					ifi = *((int32_t *)RTA_DATA(rtap));
					break;

				case RTA_PRIORITY:
					prio = *((uint32_t *)RTA_DATA(rtap));
					break;

				case RTA_IIF:
					dev = ((char *)RTA_DATA(rtap));
					rule_type = 2;
					break;

				case 15:  /* FIXME: RTA_TABLE is not always available - not needed but avoid warning */
					break;

				case RTA_PREFSRC:  /* rta_type 7 - not needed but avoid warning */
					break;

				default:
					debug_output( 0, "Error - unknown rta type: %i \n", rtap->rta_type );
					break;

			}

			rtap = RTA_NEXT(rtap,rtl);

		}

		char str1[16], str2[16];
		
		if ( is_rule ) {
			
			add_del_rule( ( rule_type == 2 ? 0 : dest ), ( rule_type == 2 ? 0 : ( rule_type == 1 ? rtm->rtm_dst_len : rtm->rtm_src_len ) ), rtm->rtm_table, prio, ( rule_type == 2 ? dev : 0 ) , rule_type, 1/*del*/, NO /*do not track*/ );
		
			inet_ntop( AF_INET, &dest, str1, sizeof (str1) );

			debug_output( DBGL_SYSTEM, "WARNING - flushing orphan rule type dest? %s,  %d, table %d, prio %d \n", 
				      rule_type == 2 ? "none" : str1, rule_type, rtm->rtm_table, prio );

		
		} else {
			
			inet_ntop( AF_INET, &dest, str1, sizeof (str1) );
			inet_ntop( AF_INET, &router, str2, sizeof (str2) );

			add_del_route( dest, rtm->rtm_dst_len, router, 0, ifi, "unknown", rtm->rtm_table, rtm->rtm_type, 1, NO/*no track*/, YES  );
			debug_output( DBGL_SYSTEM, "WARNING - flushing orphan route to %s via %s type %d, table %d \n", str1, str2, rtm->rtm_type, rtm->rtm_table );
		
		}
		

	}

	return 1;

}



int8_t bind_to_iface( int32_t sock, char *dev ) {

	if ( setsockopt( sock, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen( dev ) + 1 ) < 0 ) {

		printf( "Cannot bind socket to device %s : %s \n", dev, strerror(errno) );
		return -1;

	}

	return 1;

}



void check_proc_sys( char *file, int32_t desired, int32_t *init_state ) {
	
	FILE *f;
	int32_t state = 0;
	char filename[100];
	
	sprintf( filename, "/proc/sys/%s", file );
	
	if((f = fopen(filename, "r" )) == NULL) {
		
		debug_output( DBGL_SYSTEM, "ERROR - conf_proc_sys(): can't open %s for reading! retry later... \n", filename );
		
		if ( init_state )
			cleanup_all( CLEANUP_FAILURE );
		
		return;
	}
	
	fscanf(f, "%d", &state);
	fclose(f);
	
	if ( init_state )
		*init_state = state;
	
	if ( state != desired ) {
			
		debug_output( DBGL_SYSTEM, "changing %s from %d to %d \n", filename, state, desired );
		
		if((f = fopen(filename, "w" )) == NULL) {
		
			debug_output( DBGL_SYSTEM, "ERROR - conf_proc_sys(): can't open %s for writing! retry later... \n", filename );
			return;
		}
		
		fprintf(f, "%d", desired?1:0 );
		fclose(f);
		
	}
	
}

// check for further traps: http://lwn.net/Articles/45386/
void check_kernel_config( struct batman_if *batman_if, int8_t init ) {
	
	if ( batman_if ) {
		
		char filename[100];

		sprintf( filename, "net/ipv4/conf/%s/rp_filter", batman_if->dev_phy);
		check_proc_sys( filename, 0, init ? &batman_if->if_rp_filter_orig : NULL );

		sprintf( filename, "net/ipv4/conf/%s/send_redirects", batman_if->dev_phy);
		check_proc_sys( filename, 0, init ? &batman_if->if_send_redirects_orig : NULL );
		
	} else { 
		
		check_proc_sys( "net/ipv4/conf/all/rp_filter", 		0, init ? &if_rp_filter_all_orig : NULL );
		check_proc_sys( "net/ipv4/conf/default/rp_filter", 	0, init ? &if_rp_filter_default_orig : NULL );
		check_proc_sys( "net/ipv4/conf/all/send_redirects", 	0, init ? &if_send_redirects_all_orig : NULL );
		check_proc_sys( "net/ipv4/conf/default/send_redirects", 0, init ? &if_send_redirects_default_orig : NULL );
		check_proc_sys( "net/ipv4/ip_forward", 			1, init ? &forward_orig : NULL );
		
	}
}



void restore_kernel_config ( struct batman_if *batman_if ) {
	
	if ( batman_if ) {
		
		char filename[100];
		
		if (batman_if->if_rp_filter_orig > -1) {
			sprintf( filename, "net/ipv4/conf/%s/rp_filter", batman_if->dev_phy);
			check_proc_sys( filename, batman_if->if_rp_filter_orig, NULL );
		}
		
		batman_if->if_rp_filter_orig = -1;

		
		if (batman_if->if_send_redirects_orig > -1) {
			sprintf( filename, "net/ipv4/conf/%s/send_redirects", batman_if->dev_phy);
			check_proc_sys( filename, batman_if->if_send_redirects_orig, NULL );
		}
		
		batman_if->if_send_redirects_orig = -1;
		
	} else {
		
		if( if_rp_filter_all_orig != -1 )
			check_proc_sys( "net/ipv4/conf/all/rp_filter", if_rp_filter_all_orig, NULL );
		
		if_rp_filter_all_orig = -1;
		
		if( if_rp_filter_default_orig != -1 )
			check_proc_sys( "net/ipv4/conf/default/rp_filter", if_rp_filter_default_orig,  NULL );
		
		if_rp_filter_default_orig = -1;
		
		if( if_send_redirects_all_orig != -1 )
			check_proc_sys( "net/ipv4/conf/all/send_redirects", if_send_redirects_all_orig, NULL );
		
		if_send_redirects_all_orig = -1;
	
		if( if_send_redirects_default_orig != -1 )
			check_proc_sys( "net/ipv4/conf/default/send_redirects", if_send_redirects_default_orig, NULL );
		
		if_send_redirects_default_orig = -1;
	
		if( forward_orig != -1 )
			check_proc_sys( "net/ipv4/ip_forward", forward_orig, NULL );
		
		forward_orig = -1;

	}

}
