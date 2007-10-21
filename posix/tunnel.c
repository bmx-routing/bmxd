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



#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__Darwin__)
#include <sys/sockio.h>
#endif
#include <net/if.h>
#include <fcntl.h>        /* open(), O_RDWR */


#include "../os.h"
#include "../batman.h"



#define TUNNEL_DATA 0x01
#define TUNNEL_IP_REQUEST 0x02
#define TUNNEL_IP_INVALID 0x03

#define GW_STATE_UNKNOWN  0x01
#define GW_STATE_VERIFIED 0x02

#define ONE_MINUTE                60000

#define GW_STATE_UNKNOWN_TIMEOUT  (1  * ONE_MINUTE)
#define GW_STATE_VERIFIED_TIMEOUT (5  * ONE_MINUTE)

#define IP_LEASE_TIMEOUT          (20 * ONE_MINUTE)

#define MAX_TUNNEL_IP_REQUESTS 12

static int changed_packet_headers = 0;
static int stored_packet_headers = 0;

unsigned short bh_udp_ports[] = BH_UDP_PORTS;

void init_bh_ports()
{
	int i;

	for (i = 0; i < sizeof(bh_udp_ports)/sizeof(short); i++)
		bh_udp_ports[i] = htons(bh_udp_ports[i]);
}



int chksum(void *data, int len)
{
	uint16_t *sdata = data;
	uint32_t sum;


	for (sum = 0; len > 1; len -= 2)
		sum += *sdata++;

	if (len)
		sum += (unsigned short)(*(unsigned char *)sdata);

	return sum;
}

uint16_t chksum_l3(uint16_t l3_buff[], uint16_t l3_buff_len)
{
	uint32_t sum, tmp_sum;

	tmp_sum = chksum(l3_buff, l3_buff_len);

	sum = (tmp_sum & 0xffff) + (tmp_sum >> 16);
	sum += (sum >> 16);

	return ~(sum & 0xffff);
}

uint16_t chksum_l4(uint16_t l4_buff[], uint16_t l4_buff_len, uint32_t src, uint32_t dest, uint8_t proto)
{
	uint32_t sum, tmp_sum;

	tmp_sum = chksum(l4_buff, l4_buff_len);

	sum = (tmp_sum & 0xffff) + (tmp_sum >> 16);
	sum += (sum >> 16);

	if (l4_buff_len % 2 != 0)
		tmp_sum = (sum & 0xff << 8) | (sum & 0xff00 >> 8);
	else
		tmp_sum = sum;

	tmp_sum += (src & 0xffff);
	tmp_sum += ((src >> 16) & 0xffff);
	tmp_sum += (dest & 0xffff);
	tmp_sum += ((dest >> 16) & 0xffff);

	tmp_sum += htons(proto);
	tmp_sum += htons(l4_buff_len);

	sum = (tmp_sum & 0xffff) + (tmp_sum >> 16);
	sum += (sum >> 16);

	return ~(sum & 0xffff);
}


/* ip_sum_calc from Richard Stevens Book */
uint16_t ip_sum_calc(uint16_t ip_header_len, uint16_t ip_header_buff[])
{
	uint32_t sum = 0;

	while (ip_header_len > 1) {
		sum += *ip_header_buff++;

		if (sum & 0x80000000)   /* if high order bit set, fold */
			sum = (sum & 0xFFFF) + (sum >> 16);

		ip_header_len -= 2;
	}

	if (ip_header_len)       /* take care of left over byte */
		sum += (uint16_t) *((unsigned char *)ip_header_buff);

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;

}

void calculate_chcksum(struct iphdr *iphdr, int32_t buff_len)
{
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;

	iphdr->check = 0;
	iphdr->check = chksum_l3((uint16_t *)(iphdr), iphdr->ihl*4);

	if (iphdr->protocol == IPPROTO_UDP) {

		udphdr = (struct udphdr *)((unsigned char*)iphdr + iphdr->ihl*4);
		udphdr->check = 0;
		udphdr->check = chksum_l4((uint16_t *)udphdr, ntohs(udphdr->len), iphdr->saddr, iphdr->daddr, IPPROTO_UDP);

	} else if (iphdr->protocol == IPPROTO_TCP) {

		tcphdr = (struct tcphdr *)((unsigned char*)iphdr + iphdr->ihl*4);
		tcphdr->check = 0;
		tcphdr->check = chksum_l4((uint16_t *)tcphdr, buff_len - iphdr->ihl*4, iphdr->saddr, iphdr->daddr, IPPROTO_TCP);

	}
}



int8_t get_tun_ip( struct sockaddr_in *gw_addr, int32_t udp_sock, uint32_t *tun_addr ) {

	struct sockaddr_in sender_addr;
	struct timeval tv;
	unsigned char buff[100]; //question: why so large ??
	int32_t res, buff_len;
	uint32_t addr_len;
	int8_t i = MAX_TUNNEL_IP_REQUESTS;
	fd_set wait_sockets;


	addr_len = sizeof(struct sockaddr_in);
	memset( &buff, 0, sizeof(buff) );


	while ( ( !is_aborted() ) && ( curr_gateway != NULL ) && ( i > 0 ) ) {

		buff[0] = TUNNEL_IP_REQUEST;

		if ( sendto( udp_sock, buff, sizeof(buff), 0, (struct sockaddr *)gw_addr, sizeof(struct sockaddr_in) ) < 0 ) {

			debug_output( 0, "Error - can't send ip request to gateway: %s \n", strerror(errno) );

		} else {

			tv.tv_sec = 0;
			tv.tv_usec = 250000;

			FD_ZERO(&wait_sockets);
			FD_SET(udp_sock, &wait_sockets);

			res = select( udp_sock + 1, &wait_sockets, NULL, NULL, &tv );

			if ( res > 0 ) {

				/* gateway message */
				if ( FD_ISSET( udp_sock, &wait_sockets ) ) {

					if ( ( buff_len = recvfrom( udp_sock, buff, sizeof(buff) - 1, 0, (struct sockaddr *)&sender_addr, &addr_len ) ) < 0 ) {

						debug_output( 0, "Error - can't receive ip request: %s \n", strerror(errno) );

					} else {

						if ( ( sender_addr.sin_addr.s_addr == gw_addr->sin_addr.s_addr ) && ( buff_len > 4 ) ) {

							memcpy( tun_addr, buff + 1, 4 );
							return 1;

						} else {

							debug_output( 0, "Error - can't receive ip request: sender IP or packet size (%i) do not match \n", buff_len );

						}

					}

				}

			} else if ( ( res < 0 ) && ( errno != EINTR ) ) {

				debug_output( 0, "Error - can't select: %s \n", strerror(errno) );
				break;

			}

		}

		i--;

	}

	if ( i == 0 )
		debug_output( 0, "Error - can't receive ip from gateway: number of maximum retries reached \n" );

	return -1;

}

void search_packet_list( struct list_head_first *packet_list, struct iphdr *iphdr, int32_t packet_len ) {
	struct list_head *list_pos, *list_pos_tmp, *prev_list_head;
	struct data_packet *data_packet;
	struct iphdr *iphdr_packet;
	uint16_t dst_udp_port = 0, dst_tcp_port = 0;
	
	prev_list_head = (struct list_head *)packet_list;

	list_for_each_safe(list_pos, list_pos_tmp, packet_list) {

		data_packet = list_entry(list_pos, struct data_packet, list);

		iphdr_packet = (struct iphdr *)data_packet->header_buff;

		if (iphdr->saddr != iphdr_packet->daddr) {
			prev_list_head = &data_packet->list;
			continue;
		}

		if (iphdr->protocol != iphdr_packet->protocol) {
			prev_list_head = &data_packet->list;
			continue;
		}
									
		if (iphdr->protocol == IPPROTO_UDP) {
			dst_udp_port = ntohs( ((struct udphdr *)((unsigned char*)iphdr + iphdr->ihl*4))->dest );
			if( ((struct udphdr *)((unsigned char*)iphdr + iphdr->ihl*4))->dest != ((struct udphdr *)((unsigned char*)iphdr_packet + iphdr_packet->ihl*4))->source   ) {
				prev_list_head = &data_packet->list;
				continue;
			}
		}
									
		if (iphdr->protocol == IPPROTO_TCP ) { 
			dst_tcp_port = ntohs( ((struct tcphdr *)((unsigned char*)iphdr + iphdr->ihl*4))->dest );
			if ( ((struct tcphdr *)((unsigned char*)iphdr + iphdr->ihl*4))->dest != ((struct tcphdr *)((unsigned char*)iphdr_packet + iphdr_packet->ihl*4))->source   ) {
				prev_list_head = &data_packet->list;
				continue;
			}
		}

		/* probably our packet */
		iphdr->daddr = iphdr_packet->saddr;
		calculate_chcksum(iphdr, packet_len);

		list_del(prev_list_head, list_pos, packet_list);
		debugFree(data_packet, 1218);
		stored_packet_headers--;
		debug_output( 3, "found and removed dst_udp_port: %d, dst_tcp_port: %d (%d left in stack) ...\n", dst_udp_port, dst_tcp_port, stored_packet_headers);
		break;

	}

}

void store_header( struct list_head_first *packet_list, struct iphdr *iphdr, int32_t packet_len ) {
	struct data_packet *data_packet;
		
	data_packet = debugMalloc( sizeof(struct data_packet), 210 );

	memcpy(data_packet->header_buff, (unsigned char*)iphdr, (packet_len > sizeof(data_packet->header_buff) ? sizeof(data_packet->header_buff) : packet_len));

	INIT_LIST_HEAD(&data_packet->list);
	list_add_tail(&data_packet->list, packet_list);
	
	changed_packet_headers++;
	stored_packet_headers++;
	debug_output( 3, "adding %d packet header, (%d in stack)...\n", changed_packet_headers, stored_packet_headers );
	
}

void purge_packet_list( struct list_head_first *packet_list ) {
	struct list_head *list_pos, *list_pos_tmp;
	struct data_packet *data_packet;

	if (!list_empty(packet_list)) {
		list_for_each_safe(list_pos, list_pos_tmp, packet_list) {
		
			data_packet = list_entry(list_pos, struct data_packet, list);
		
			list_del((struct list_head *)packet_list, list_pos, packet_list);
		
			debugFree(data_packet, 1219);
			stored_packet_headers--;
			debug_output( 3, "purging packet header, (%d left in stack)...\n", stored_packet_headers );
		
		}
	} 
		
	changed_packet_headers = 0;
	stored_packet_headers = 0;

}


void *client_to_gw_tun( void *arg ) {

	struct curr_gw_data *curr_gw_data = (struct curr_gw_data *)arg;
	struct sockaddr_in gw_addr, my_addr, sender_addr;
	struct iphdr *iphdr;
	struct timeval tv;
	struct list_head_first packet_list;
	int32_t res, max_sock, udp_sock, tun_fd, tun_ifi, sock_opts;
	uint32_t addr_len, current_time, ip_lease_time = 0, gw_state_time = 0, prev_ip_time = 0, new_ip_time = 0, my_tun_addr = 0;
	uint32_t last_invalidip_warning = 0;
	char tun_if[IFNAMSIZ], my_str[ADDR_STR_LEN], is_str[ADDR_STR_LEN], gw_str[ADDR_STR_LEN], gw_state = GW_STATE_UNKNOWN, prev_gw_state = GW_STATE_UNKNOWN;
	int32_t tunnel_ip_packet_len, tunnel_packet_len;
	struct tunnel_buff tunnel_buff;
	fd_set wait_sockets, tmp_wait_sockets;
	uint16_t dns_port = htons( 53 );


	addr_len = sizeof (struct sockaddr_in);

	INIT_LIST_HEAD_FIRST(packet_list);

	memset( &gw_addr, 0, sizeof(struct sockaddr_in) );
	memset( &my_addr, 0, sizeof(struct sockaddr_in) );

	gw_addr.sin_family = AF_INET;
	gw_addr.sin_port = htons(PORT + 1);
	gw_addr.sin_addr.s_addr = curr_gw_data->orig;

	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(PORT + 1);
	my_addr.sin_addr.s_addr = curr_gw_data->batman_if->addr.sin_addr.s_addr;


	/* connect to server (establish udp tunnel) */
	if ( ( udp_sock = socket( PF_INET, SOCK_DGRAM, 0 ) ) < 0 ) {

		debug_output( 0, "Error - can't create udp socket: %s\n", strerror(errno) );
		curr_gateway = NULL;
		debugFree( arg, 1209 );
		return NULL;

	}

	if ( bind( udp_sock, (struct sockaddr *)&my_addr, sizeof(struct sockaddr_in) ) < 0 ) {

		debug_output( 0, "Error - can't bind tunnel socket: %s\n", strerror(errno) );
		close( udp_sock );
		curr_gateway = NULL;
		debugFree( arg, 1210 );
		return NULL;

	}


	/* make udp socket non blocking */
	sock_opts = fcntl( udp_sock, F_GETFL, 0 );
	fcntl( udp_sock, F_SETFL, sock_opts | O_NONBLOCK );


	if ( add_dev_tun( curr_gw_data->batman_if, 0, tun_if, sizeof(tun_if), &tun_fd, &tun_ifi ) > 0 ) {

		add_del_route( 0, 0, 0, 0, tun_ifi, tun_if, BATMAN_RT_TABLE_TUNNEL, 0, 0 );

	} else {

		close( udp_sock );
		curr_gateway = NULL;
		debugFree( arg, 1211 );
		return NULL;

	}


	addr_to_string( curr_gw_data->orig, gw_str, sizeof(gw_str) );


	FD_ZERO(&wait_sockets);
	FD_SET(udp_sock, &wait_sockets);
	FD_SET(tun_fd, &wait_sockets);

	max_sock = ( udp_sock > tun_fd ? udp_sock : tun_fd );

	while ( ( !is_aborted() ) && ( curr_gateway != NULL ) && ( ! curr_gw_data->gw_node->deleted ) ) {

		tv.tv_sec = 0;
		tv.tv_usec = 250; // question: why so small? to react faster on pthread_join?

		memcpy( &tmp_wait_sockets, &wait_sockets, sizeof(fd_set) );

		res = select( max_sock + 1, &tmp_wait_sockets, NULL, NULL, &tv );

		current_time = get_time();

		if ( res > 0 ) {

			/* udp message (tunnel data) from gateway */
			if ( FD_ISSET( udp_sock, &tmp_wait_sockets ) ) {

				while ( ( tunnel_packet_len = recvfrom( udp_sock, (unsigned char*)&tunnel_buff.align.type, sizeof(tunnel_buff.align.type) + sizeof(tunnel_buff.ip_packet), 0, (struct sockaddr *)&sender_addr, &addr_len ) ) > 0 ) {

					tunnel_ip_packet_len = tunnel_packet_len - sizeof(tunnel_buff.align.type);
					
					if ( ( tunnel_ip_packet_len > 0 ) && ( sender_addr.sin_addr.s_addr == gw_addr.sin_addr.s_addr ) ) {

						/* got data from gateway */
						if ( tunnel_buff.align.type == TUNNEL_DATA ) {

							if ( tunnel_ip_packet_len >= sizeof(struct iphdr) && ((struct iphdr *)(tunnel_buff.ip_packet))->version == 4 ) {
							
								/* if the source address of the original packet was wrong set it back know */
								if (!list_empty(&packet_list)) {
	
									search_packet_list( &packet_list, (struct iphdr *)(tunnel_buff.ip_packet), tunnel_ip_packet_len );
	
								}
	
								if ( write( tun_fd, tunnel_buff.ip_packet, tunnel_ip_packet_len ) < 0 )
									debug_output( 0, "Error - can't write packet: %s\n", strerror(errno) );
	
								// deactivate unresponsive GW check only based on non-icmp data
								//14:08:11.528658 IP 169.254.0.1.32770 > 141.1.1.1.53:  4+ A? open-mesh.net. (25)
								//14:08:14.533070 IP 192.168.2.3 > 169.254.0.1: ICMP host 141.1.1.1 unreachable, length
								if ( !no_unresponsive_check ) {
									
									if( ((struct iphdr *)(tunnel_buff.ip_packet))->protocol != IPPROTO_ICMP  ) {
							
										gw_state = GW_STATE_VERIFIED;
										gw_state_time = current_time;
										if( prev_gw_state != gw_state ) 
										debug_output( 3, "changed GW state: %d, incoming IP protocol: %d\n", prev_gw_state = gw_state, ((struct iphdr *)(tunnel_buff.ip_packet))->protocol );
										
									}
	
								} else {
								
									gw_state = GW_STATE_VERIFIED;
									gw_state_time = current_time;
									if( prev_gw_state != gw_state ) 
										debug_output( 3, "changed GW state: %d\n", prev_gw_state = gw_state );
	
								}
							
							} else {
								
								debug_output( 3, "only IPv4 packets supported so fare !!!\n");
								
							}
								
						/* gateway told us that we have no valid ip */
							
						} else if ( tunnel_buff.align.type == TUNNEL_IP_INVALID ) {

							addr_to_string( my_tun_addr, my_str, sizeof(my_str) );
							debug_output( 3, "Gateway client - gateway (%s) says: IP (%s) is expired \n", gw_str, my_str );

							if ( get_tun_ip( &gw_addr, udp_sock, &my_tun_addr ) < 0 ) {

								curr_gw_data->gw_node->last_failure = current_time;
								curr_gw_data->gw_node->unavail_factor++;

								curr_gateway = NULL;

								errno = EWOULDBLOCK;

								break;

							}

							addr_to_string( my_tun_addr, my_str, sizeof(my_str) );
							debug_output( 3, "Gateway client - got IP (%s) from gateway: %s \n", my_str, gw_str );

							if ( set_tun_addr( udp_sock, my_tun_addr, tun_if ) < 0 )
								break;

						}

					} else {

						addr_to_string( sender_addr.sin_addr.s_addr, my_str, sizeof(my_str) );
						debug_output( 0, "Error - ignoring gateway packet from %s: packet too small (%i)\n", my_str, tunnel_packet_len );

					}

				}

				if ( errno != EWOULDBLOCK ) {

					debug_output( 0, "Error - gateway client can't receive packet: %s\n", strerror(errno) );
					break;

				}

				ip_lease_time = current_time;

			/* Got data to be send to gateway */
			} else if ( FD_ISSET( tun_fd, &tmp_wait_sockets ) ) {

				while ( ( tunnel_ip_packet_len = read( tun_fd, tunnel_buff.ip_packet, sizeof(tunnel_buff.ip_packet) /*TBD: why -2 here? */ ) ) > 0 ) {
					tunnel_packet_len = tunnel_ip_packet_len + sizeof(tunnel_buff.align.type);
					
					if ( my_tun_addr == 0 ) {

						if ( get_tun_ip( &gw_addr, udp_sock, &my_tun_addr ) < 0 ) {

							curr_gw_data->gw_node->last_failure = current_time;
							curr_gw_data->gw_node->unavail_factor++;

							curr_gateway = NULL;

							errno = EWOULDBLOCK;

							break;

						}

						addr_to_string( my_tun_addr, my_str, sizeof(my_str) );
						debug_output( 3, "Gateway client - got IP (%s) from gateway: %s \n", my_str, gw_str );

						if ( set_tun_addr( udp_sock, my_tun_addr, tun_if ) < 0 )
							break;

						ip_lease_time = current_time;
						prev_ip_time = new_ip_time;
						new_ip_time = current_time;

					}

					tunnel_buff.align.type = TUNNEL_DATA;

					/* fill in new ip - the packets in the buffer don't know it yet */
					// some applications tend to set their own IP or an IP from another interface. This would trigger the GW to complain 
					iphdr = (struct iphdr *)(tunnel_buff.ip_packet);

					if (iphdr->saddr == my_tun_addr) {
						
						if ( sendto( udp_sock, (unsigned char*) &tunnel_buff.align.type, tunnel_packet_len, 0, (struct sockaddr *)&gw_addr, sizeof (struct sockaddr_in) ) < 0 )
							debug_output( 0, "Error - can't send data to gateway: %s\n", strerror(errno) );
					
					} else if ( new_ip_time + MAX_IP_FIX_TIME > current_time && changed_packet_headers <= 10 
							&& (((iphdr->protocol == IPPROTO_UDP) && (((struct udphdr *)((unsigned char*)iphdr + iphdr->ihl*4))->dest == dns_port)))
						  ) {

							if( prev_ip_time != new_ip_time ) {
								prev_ip_time = new_ip_time;
								purge_packet_list( &packet_list );
							}
						
							/* save packet headers for later */
							
							store_header( &packet_list, iphdr, tunnel_ip_packet_len );
							iphdr->saddr = my_tun_addr;
							calculate_chcksum( iphdr, tunnel_ip_packet_len );
							
							if ( sendto( udp_sock, (unsigned char*)&tunnel_buff.align.type, tunnel_packet_len, 0, (struct sockaddr *)&gw_addr, sizeof (struct sockaddr_in) ) < 0 )
							debug_output( 0, "Error - can't send data to gateway: %s\n", strerror(errno) );


					} else if ( ( last_invalidip_warning == 0 || last_invalidip_warning + WARNING_PERIOD < current_time ) ) {
						
						last_invalidip_warning = current_time;
							
						addr_to_string( my_tun_addr,  my_str, sizeof(my_str) );
						addr_to_string( iphdr->saddr, is_str, sizeof(is_str) );
						debug_output( 3, "Gateway client - IP age: %d, modified headers: %d, Still Invalid outgoing src IP: %s, should be %s! Dropping packet\n", (current_time - new_ip_time), changed_packet_headers, is_str,  my_str );
						
					}
				}

				if ( errno != EWOULDBLOCK ) {

					debug_output( 0, "Error - gateway client can't read tun data: %s\n", strerror(errno) );
					break;

				}

				// activate unresponsive GW check only based on TCP and DNS data
				if ( ( !no_unresponsive_check && gw_state == GW_STATE_UNKNOWN ) && ( gw_state_time == 0 ) ) {
					if( ( (((struct iphdr *)(tunnel_buff.ip_packet))->protocol == IPPROTO_TCP )  || 
						( (((struct iphdr *)(tunnel_buff.ip_packet))->protocol == IPPROTO_UDP)  && 
					(((struct udphdr *)(tunnel_buff.ip_packet + ((struct iphdr *)(tunnel_buff.ip_packet))->ihl*4))->dest == dns_port)  )
					    ) ) {
						
						gw_state_time = current_time;
						if( prev_gw_state != gw_state ) 
							debug_output( 3, "changed GW state: %d\n", prev_gw_state = gw_state );
					
					}

				}
			
			}

		} else if ( ( res < 0 ) && ( errno != EINTR ) ) {

			debug_output( 0, "Error - can't select: %s\n", strerror(errno) );
			break;

		}


		/* drop unused IP */
		if ( ( my_tun_addr != 0 ) && ( ( ip_lease_time + IP_LEASE_TIMEOUT ) < current_time ) ) {

			addr_to_string( my_tun_addr, my_str, sizeof(my_str) );
			debug_output( 3, "Gateway client - releasing unused IP after timeout: %s \n", my_str );

			my_tun_addr = 0;

			if ( set_tun_addr( udp_sock, my_tun_addr, tun_if ) < 0 )
				break;

			/* kernel deletes routes after setting the interface ip to 0 */
			add_del_route( 0, 0, 0, 0, tun_ifi, tun_if, BATMAN_RT_TABLE_TUNNEL, 0, 0 );

		}

		/* drop connection to gateway if the gateway does not respond */
		if ( !no_unresponsive_check && ( gw_state == GW_STATE_UNKNOWN ) && ( gw_state_time != 0 ) && ( ( gw_state_time + GW_STATE_UNKNOWN_TIMEOUT ) < current_time ) ) {
			
			debug_output( 3, "Gateway client - disconnecting from unresponsive gateway: %s \n", gw_str );

			curr_gw_data->gw_node->last_failure = current_time;
			curr_gw_data->gw_node->unavail_factor++;

			break;

		}
		
		/* change back to unknown state if gateway did not respond in time */
		if ( ( gw_state == GW_STATE_VERIFIED ) && ( ( gw_state_time + GW_STATE_VERIFIED_TIMEOUT ) < current_time ) ) {

			gw_state = GW_STATE_UNKNOWN;
			gw_state_time = 0; // the timer is not started before the next packet is send to the GW
			if( prev_gw_state != gw_state ) 
				debug_output( 3, "changed GW state: %d\n", prev_gw_state = gw_state );

		}

		if ((!list_empty(&packet_list)) && (new_ip_time + MAX_IP_FIX_TIME < current_time))
			purge_packet_list( &packet_list );

	}

	debug_output( 3, "terminating client_to_gw_tun thread: is_aborted(): %s, curr_gateway: %ld, deleted: %d \n", (is_aborted()? "YES":"NO"), curr_gateway, curr_gw_data->gw_node->deleted );
	
	/* cleanup */
	purge_packet_list( &packet_list );
	
	add_del_route( 0, 0, 0, 0, tun_ifi, tun_if, BATMAN_RT_TABLE_TUNNEL, 0, 1 );

	close( udp_sock );

	del_dev_tun( tun_fd );

	curr_gateway = NULL;
	debugFree( arg, 1212 );

	return NULL;

}

int8_t get_ip_addr( uint32_t client_addr, uint8_t *ip_byte_4, struct gw_client *gw_client[] ) {

	uint8_t i, first_free = 0;

	for ( i = 1; i < 255; i++ ) {

		if ( gw_client[i] != NULL ) {

			if ( gw_client[i]->addr == client_addr ) {

				*ip_byte_4 = i;
				return 1;

			}

		} else {

			if ( first_free == 0 ) {

				first_free = i;
				break;

			}

		}

	}

	if ( first_free == 0 ) {

		debug_output( 0, "Error - can't get IP for client: maximum number of clients reached\n" );
		return -1;

	}

	gw_client[first_free] = debugMalloc( sizeof(struct gw_client), 208 );

	gw_client[first_free]->addr = client_addr;
	gw_client[first_free]->last_keep_alive = get_time();

	*ip_byte_4 = first_free;

	return 1;

}



void *gw_listen( void *arg ) {

	struct batman_if *batman_if = (struct batman_if *)arg;
	struct timeval tv;
	struct sockaddr_in addr, client_addr /*, pack_dest */;
	struct gw_client *gw_client[256];
	char gw_addr[16], str[16], /* str2[16], */ tun_dev[IFNAMSIZ];
	unsigned char buff[1501];
	int32_t res, max_sock, buff_len, tun_fd, tun_ifi, raw_fd;
	uint32_t addr_len, client_timeout, current_time;
	uint8_t i, my_tun_ip[4];
	fd_set wait_sockets, tmp_wait_sockets;


	my_tun_ip[0] = ((uint8_t*)&gw_tunnel_prefix)[0];
	my_tun_ip[1] = ((uint8_t*)&gw_tunnel_prefix)[1];
	my_tun_ip[2] = batman_if->if_num;
	my_tun_ip[3] = 0;

	addr_len = sizeof (struct sockaddr_in);
	client_timeout = get_time();

	for ( i = 0; i < 255; i++ ) {
		gw_client[i] = NULL;
	}

	if ( ( raw_fd = socket( PF_INET, SOCK_RAW, IPPROTO_RAW ) ) < 0 ) {

		debug_output( 0, "Error - can't create raw socket: %s\n", strerror(errno) );
		return NULL;

	}

	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(PORT + 1);

	
	if ( add_dev_tun( batman_if, *(uint32_t *)my_tun_ip, tun_dev, sizeof(tun_dev), &tun_fd, &tun_ifi ) < 0 )
		return NULL;

	add_del_route( *(uint32_t *)my_tun_ip, 24, 0, 0, tun_ifi, tun_dev, 254, 0, 0 );


	FD_ZERO(&wait_sockets);
	FD_SET(batman_if->udp_tunnel_sock, &wait_sockets);
	FD_SET(tun_fd, &wait_sockets);

	max_sock = ( batman_if->udp_tunnel_sock > tun_fd ? batman_if->udp_tunnel_sock : tun_fd );

	while ( ( !is_aborted() ) && ( gateway_class > 0 ) ) {

		tv.tv_sec = 0;
		tv.tv_usec = 250;
		memcpy( &tmp_wait_sockets, &wait_sockets, sizeof(fd_set) );

		res = select( max_sock + 1, &tmp_wait_sockets, NULL, NULL, &tv );

		if ( res > 0 ) {

			/* is udp packet from GW-Client*/
			if ( FD_ISSET( batman_if->udp_tunnel_sock, &tmp_wait_sockets ) ) {

				while ( ( buff_len = recvfrom( batman_if->udp_tunnel_sock, buff, sizeof(buff) - 1, 0, (struct sockaddr *)&addr, &addr_len ) ) > 0 ) {

					if ( buff_len > 1 ) {

						if ( buff[0] == TUNNEL_DATA ) {

							/* check whether client IP is known */
							if ( ( buff[13] != ((uint8_t*)&gw_tunnel_prefix)[0] ) || ( buff[14] != ((uint8_t*)&gw_tunnel_prefix)[1] ) || ( buff[15] != batman_if->if_num ) || ( gw_client[(uint8_t)buff[16]] == NULL ) || ( gw_client[(uint8_t)buff[16]]->addr != addr.sin_addr.s_addr ) ) {

								buff[0] = TUNNEL_IP_INVALID;
								addr_to_string( addr.sin_addr.s_addr, str, sizeof(str) );

								debug_output( 0, "Error - got packet from unknown client: %s (virtual ip %i.%i.%i.%i) \n", str, (uint8_t)buff[13], (uint8_t)buff[14], (uint8_t)buff[15], (uint8_t)buff[16] );

								if ( sendto( batman_if->udp_tunnel_sock, buff, buff_len, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in) ) < 0 )
									debug_output( 0, "Error - can't send invalid ip information to client (%s): %s \n", str, strerror(errno) );

								continue;

							}
														
							if ( write( tun_fd, buff + 1, buff_len - 1 ) < 0 )  
					                        debug_output( 0, "Error - can't write packet: %s\n", strerror(errno) );  
							
						} else if ( buff[0] == TUNNEL_IP_REQUEST ) {

							if ( get_ip_addr( addr.sin_addr.s_addr, &my_tun_ip[3], gw_client ) > 0 ) {

								memcpy( buff + 1, (char *)my_tun_ip, 4 );

								if ( sendto( batman_if->udp_tunnel_sock, buff, 100, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in) ) < 0 ) {

									addr_to_string( addr.sin_addr.s_addr, str, sizeof (str) );
									debug_output( 0, "Error - can't send requested ip to client (%s): %s \n", str, strerror(errno) );

								} else {

									addr_to_string( *(uint32_t *)my_tun_ip, str, sizeof(str) );
									addr_to_string( addr.sin_addr.s_addr, gw_addr, sizeof(gw_addr) );
									debug_output( 3, "Gateway - assigned %s to client: %s \n", str, gw_addr );

								}

							}

						}

					}

				}

				if ( errno != EWOULDBLOCK ) {

					debug_output( 0, "Error - gateway can't receive packet: %s\n", strerror(errno) );
					break;

				}

			/* /dev/tunX activity */
			} else if ( FD_ISSET( tun_fd, &tmp_wait_sockets ) ) {

				while ( ( buff_len = read( tun_fd, buff + 1, sizeof(buff) - 2 ) ) > 0 ) {

					my_tun_ip[3] = buff[20];

					if ( gw_client[(uint8_t)my_tun_ip[3]] != NULL ) {

						client_addr.sin_addr.s_addr = gw_client[(uint8_t)my_tun_ip[3]]->addr;
						gw_client[(uint8_t)my_tun_ip[3]]->last_keep_alive = get_time();

						/* addr_to_string( client_addr.sin_addr.s_addr, str, sizeof(str) );
						tmp_client_ip = buff[17] + ( buff[18]<<8 ) + ( buff[19]<<16 ) + ( buff[20]<<24 );
						addr_to_string( tmp_client_ip, gw_addr, sizeof(gw_addr) );
						debug_output( 3, "Gateway - packet resolved: %s for client %s \n", str, gw_addr ); */

						buff[0] = TUNNEL_DATA;

						if ( sendto( batman_if->udp_tunnel_sock, buff, buff_len + 1, 0, (struct sockaddr *)&client_addr, sizeof(struct sockaddr_in) ) < 0 )
							debug_output( 0, "Error - can't send data to client (%s): %s \n", str, strerror(errno) );

					} else {

						addr_to_string( *(uint32_t *)my_tun_ip, gw_addr, sizeof(gw_addr) );
						debug_output( 3, "Gateway - could not resolve packet: %s \n", gw_addr );

					}

				}

				if ( errno != EWOULDBLOCK ) {

					debug_output( 0, "Error - gateway can't read tun data: %s\n", strerror(errno) );
					break;

				}

			}

		} else if ( ( res < 0 ) && ( errno != EINTR ) ) {

			debug_output( 0, "Error - can't select: %s\n", strerror(errno) );
			break;

		}


		/* close unresponsive client connections (free unused IPs) */
		current_time = get_time();

		if ( ( client_timeout + 60000 ) < current_time ) {

			client_timeout = current_time;

			for ( i = 1; i < 255; i++ ) {

				if ( gw_client[i] != NULL ) {

					if ( ( gw_client[i]->last_keep_alive + IP_LEASE_TIMEOUT ) < current_time ) {

						debugFree( gw_client[i], 1216 );
						gw_client[i] = NULL;

					}

				}

			}

		}

	}

	/* delete tun device and routes on exit */
	my_tun_ip[3] = 0;
	add_del_route( *(uint32_t *)my_tun_ip, 24, 0, 0, tun_ifi, tun_dev, 254, 0, 1 );

	del_dev_tun( tun_fd );


	for ( i = 1; i < 255; i++ ) {

		if ( gw_client[i] != NULL )
			debugFree( gw_client[i], 1217 );

	}

	close( batman_if->udp_tunnel_sock );

	return NULL;

}

