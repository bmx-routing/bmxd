/*
 * Copyright (C) 2006 BATMAN contributors:
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
 
/*
  #include <stdlib.h> 
  #include <string.h> 
  #include <stdio.h> 
  #include "bmex.h"
  #include "list.h" 
*/
#include "bmex.h"

/* "-debug" is the command line switch for the debug level,
 * specify it multiple times to increase verbosity
 * 0 gives a minimum of messages to save CPU-Power
 * 1 normal
 * 2 verbose 
 * 3 very verbose
 * 4
 * 5
 * Beware that high debugging levels eat a lot of CPU-Power
 */
 



void output(int importance, char *format, ...)
{
  va_list args;
  if( arg_debug >= importance ) {
    get_time_internal( &now_tv );
    printf("[%10ld %6ld] ", now_tv.tv_sec, now_tv.tv_usec);
    
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
  }
}

void output_nt(int importance, char *format, ...)
{
  va_list args;
  if( arg_debug >= importance ) {
    
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
  }
}

static void handler(int sig)
{
  stop = 1;
}

static void finishNow(void)
{
  // TBD: release of memory is currenly left to OS - why not?

  delAllRoutes();

  set_forwarding(forward_old);

  closeAllSockets();

  exit( -1 );
}


static void usage(void)
{
  fprintf(stderr, "Usage: batman interface\n");
}




int is_aborted()
{
  return stop != 0;
}

void *alloc_memory(int len)
{
  void *res = malloc(len);

  if (res == NULL)
    {
      fprintf(stderr, "Out of memory\n");
      finishNow();
      exit( 1 );
    }

  return res;
}

void free_memory(void *mem)
{
  free(mem);
}

void addr_to_string(unsigned int addr, char *str, int len)
{
  inet_ntop(AF_INET, &addr, str, len);
}

int rand_num(int limit)
{
  if( limit == 0 ) return 0;
  return rand() % limit;
}

/* this function finds or creates an originator entry for the given address if
   it does not exits */
struct orig_node *get_orig_node( unsigned int addr )
{
  struct list_head *pos;
  struct orig_node *orig_node;
  dbg(4, "get_orig_node(): \n");
  
  list_for_each(pos, &orig_list) {
    orig_node = list_entry(pos, struct orig_node, list);
    if (orig_node->addr == addr)
      return orig_node;
  }
  
  dbg(5, "get_orig_node(): Creating new originator\n");
  
  orig_node = (struct orig_node*) alloc_memory(sizeof(struct orig_node));
  memset(orig_node, 0, sizeof(struct orig_node));
  INIT_LIST_HEAD(&orig_node->list);
  INIT_LIST_HEAD(&orig_node->pack_list);
  
  orig_node->addr = addr;
  orig_node->min_originated_oview_tstmp = MAX_OF_LONG; //(unsigned long) -1;
  orig_node->min_originated_rview_tstmp = MAX_OF_LONG; //(unsigned long) -1;
  orig_node->minTtpc = MAX_OF_LONG;

  list_add_tail(&orig_node->list, &orig_list);

  return orig_node;
}


int init_device( char *arg_device ) {

  int  on = 1;
  struct device_node *device_node = NULL;
  char str1[16], str2[16], str3[16];
    
  struct ifreq ifr;
    
  if (strlen(arg_device) > IFNAMSIZ - 1)
    {
      fprintf(stderr, "init_device(): Interface name too long \n");
      finishNow();      exit( -1 );
    }
    
  if ( device_list_size >= MAX_DEVICE_LIST_SIZE ) 
    {
      fprintf(stderr, "init_device(): So fare only %d interface is supported \n", 
	      MAX_DEVICE_LIST_SIZE );
      finishNow();      exit( -1 );
    }
    	
    
  output(1, "init_device(): using device %s. \n", arg_device  );
    
  /*** first generate new device_node   */
    
  output(1, "init_device(): Creating new device node \n");
    
  device_node = &device_node_array[device_list_size];
  memset(device_node, 0, sizeof(struct device_node));
  INIT_LIST_HEAD(&device_node->list);
  INIT_LIST_HEAD(&device_node->forw_list );

  device_node->device_node_index = device_list_size;
  strcpy( device_node->arg_device, arg_device );
  device_node->seqno=1;
  device_list_size++;
    
  /*** then initiate that device and complete device_node,   */
    
  output(1, "init_device(): Configuring device with start ttl: %d \n", arg_ttl);
  device_node->ttl = arg_ttl;

  //if more than one interface, others are by default configured with ttl 1 to reduce overhead
  arg_ttl = TTL_MULTIPLE_DEVICES;

  // get socket
  device_node->snd_sock = socket( PF_INET, SOCK_DGRAM, 0 );
  if (device_node->snd_sock < 0)
    {
      fprintf(stderr, "init_device(): Cannot create receive socket: %s", 
	      strerror(errno));
      finishNow();      exit( -1 );
    }


  // Get flags (and check if interface exists)
  memset(&ifr, 0, sizeof (struct ifreq));
  strcpy(ifr.ifr_name, device_node->arg_device);
  if (ioctl(device_node->snd_sock, SIOCGIFFLAGS, &ifr) < 0) 
    {
      fprintf(stderr, "init_device(): cannot get interface flags: %s \n", 
	      strerror(errno));
      finishNow();      exit( -1 );
    }
  device_node->int_flags = ifr.ifr_flags;      
  
  // check if interface up
  if ((device_node->int_flags & IFF_UP) == 0)
    {
      fprintf(stderr, "init_device(): interface not up \n");
      finishNow();      exit( -1 );
    }
  
  // check if loopback interface 
  if ((device_node->int_flags & IFF_LOOPBACK))
    {
      fprintf(stderr, "init_device(): interface is loopback interface \n");
      finishNow();      exit( -1 );
    }

  // check broadcast 
  if ((device_node->int_flags & IFF_BROADCAST) == 0)
    {
      fprintf(stderr, "init_device(): interface without broadcast \n");
      finishNow();      exit( -1 );
    }

  // get interface MTU 
  if (ioctl(device_node->snd_sock, SIOCGIFMTU, &ifr) < 0)
    {
      fprintf(stderr, "init_device(): can not get device MTU \n");
      finishNow();      exit( -1 );
    }
  device_node->int_mtu = ifr.ifr_mtu;


  // get ip address of interface
  memset(&ifr, 0, sizeof (struct ifreq));
  strcpy(ifr.ifr_name, device_node->arg_device);
  if (ioctl(device_node->snd_sock, SIOCGIFADDR, &ifr) < 0)
    {
      fprintf(stderr, "init_device(): Cannot get IP address of interface %s\n", 
	      device_node->arg_device);
      close(device_node->snd_sock);
      finishNow();      exit( -1 );
    }
  device_node->snd_addr.sin_addr.s_addr = 
    ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

  // generate and initialize orig_node, store int_address
  device_node->orig_node = get_orig_node( device_node->snd_addr.sin_addr.s_addr );
  device_node->orig_node->this_device_node = device_node;  


  // get multicast address of interface
  if (ioctl(device_node->snd_sock, SIOCGIFNETMASK , &ifr) < 0)
    {
      fprintf(stderr, "init_device(): Cannot get multicast IP address of interface %s\n", 
	      device_node->arg_device);
      close(device_node->snd_sock);
      finishNow();      exit( -1 );
    }
  device_node->mc_addr.sin_addr.s_addr = 
    ((struct sockaddr_in *)&(ifr.ifr_netmask))->sin_addr.s_addr;

    
  // get broadcast address of interface
  if (ioctl(device_node->snd_sock, SIOCGIFBRDADDR, &ifr) < 0)
    {
      fprintf(stderr, "init_device(): Cannot get broadcast IP address of interface %s\n", 
	      device_node->arg_device);
      close(device_node->snd_sock);
      finishNow();      exit( -1 );
    }


  // assign accuired send Broadcast address and port to device_node->snd_broad
  device_node->snd_broad.sin_family = AF_INET;
  device_node->snd_broad.sin_port = htons(RCV_PORT);
  device_node->snd_broad.sin_addr.s_addr = 
    ((struct sockaddr_in *)&(ifr.ifr_broadaddr))->sin_addr.s_addr;
  // give some feedback
  addr_to_string(device_node->snd_addr.sin_addr.s_addr, str1, sizeof (str1));
  addr_to_string(device_node->snd_broad.sin_addr.s_addr, str2, sizeof (str2));
  addr_to_string(device_node->mc_addr.sin_addr.s_addr, str3, sizeof (str3));
  printf("init_device(): Using IP %s, broadcast %s, multicast %s\n", str1, str2, str3);



  on = 1;
  // enable broadcast on socket
  if (setsockopt(device_node->snd_sock, SOL_SOCKET, SO_BROADCAST, 
		 &on, sizeof (int)) < 0)
    {
      fprintf(stderr, "init_device(): Cannot enable broadcasts: %s\n", 
	      strerror(errno));
      close(device_node->snd_sock);
      finishNow();      exit( -1 );
    }

  // enable reuse of not yet released sockets
  if (setsockopt(device_node->snd_sock, SOL_SOCKET, SO_REUSEADDR, 
		 &on, sizeof (int)) < 0)
    {
      fprintf(stderr, "init_device(): Cannot enable SO_REUSEADDE on socket: %s\n", 
	      strerror(errno));
      close(device_node->snd_sock);
      finishNow();      exit( -1 );
    }


  // bind socket to interface
  // TBD: this is problematic with virtual interfaces

  size_t vlen;
  vlen = strcspn( arg_device, ":" );
  strncpy( device_node->phy_device, arg_device, vlen );
  device_node->phy_device[vlen]='\0';
  output(1, "init_device(): binding socket to phy device %s. \n", device_node->phy_device );

  if (setsockopt(device_node->snd_sock, SOL_SOCKET, SO_BINDTODEVICE,  
		 device_node->phy_device, strlen(device_node->phy_device)+1 ) < 0)
    {
      fprintf(stderr, "init_device(): Cannot bind socket to device: %s\n", 
	      strerror(errno));
      close(device_node->snd_sock);
      finishNow();      exit( -1 );
    } 

    
  // bind socket to PORT for reception on RCV_PORT
  device_node->snd_null.sin_family = AF_INET;
  device_node->snd_null.sin_port = htons( RCV_PORT );
  device_node->snd_null.sin_addr.s_addr = 0;
  if (bind(device_node->snd_sock, (struct sockaddr *)&device_node->snd_null, 
	   sizeof (struct sockaddr_in)) < 0)
    {
      fprintf(stderr, "init_device(): Cannot bind socket: %s\n", strerror(errno));
      close(device_node->snd_sock);
      finishNow();      exit( -1 );
    }
    
  dbg(4, "init_device(): return... \n");
  return 2;
}



void apply_init_args(int argc, char** argv)
{
  int last_argc;
  char *cmd_switch;
  int consumed_args;
  
  /* Consume command name */
  argc--; 
  last_argc = argc+1;
  argv++;


  /* Consume remaining options and parameters */
  while ((argc >= 1) && ( (*argv)[0] == '-') && (argc < last_argc) )
    {
      last_argc = argc;
      cmd_switch = (argv[0])+1;
      if ( argc >= 1 ) {
        consumed_args = process_arg( cmd_switch, /*(argv+1)[0]*/ argv, argc );
	if (!(consumed_args >= 1 && consumed_args <= argc)) {
	  printf("Error in startup parameters!...\n");

	  usage();
	  finishNow();	  exit(EXIT_FAILURE);
	}
        argc = argc - consumed_args;
        argv = argv + consumed_args;
      }
    }

}
 
void help() {
  printf("example:# batman -dev wlan0 \n");
  printf("  \n");
  printf("  -help:  \n");
  printf("  -dev:     <interface-name> \n");
  printf("  -debug    <%d..%d> (default: %d) : Setting debug level \n", MIN_DEBUG, MAX_DEBUG, arg_debug);
  printf("  -ttl      <%d..%d> (default: %d) : will configure next device with ttl \n", MIN_TTL, MAX_TTL, arg_ttl );
  printf("  -rmetric  <%d..%d> (default: %d) : Setting routing metric to \n", MIN_ROUTING_METRIC, MAX_ROUTING_METRIC, arg_routing_metric );
  printf("  -cpolicy  <%d..%d> (default: %d) : Setting consider policy to \n", MIN_CONSIDER_POLICY, MAX_CONSIDER_POLICY, arg_consider_policy );
  printf("  -fpolicy  <%d..%d> (default: %d) : Setting forward policy to \n",  MIN_FORWARD_POLICY, MAX_FORWARD_POLICY, arg_forward_policy );
  printf("  -mbundle  <%d..%d> (default: %d) : Setting max originator bundling to  \n", MIN_ORIG_BUNDLE, MAX_ORIG_BUNDLE, arg_max_orig_bundle  );
  printf("  -origival <%d..%d> (default: %d) : Setting average originator interval to d ms  \n", MIN_ORIG_INTERVAL, MAX_ORIG_INTERVAL, arg_orig_interval_ms   );
  printf("  -bidito   <%d..%d> (default: %d) : Setting nidirectional neighbor timeout to d ms  \n", MIN_BIDIRECT_TO, MAX_BIDIRECT_TO, arg_bidirect_to_ms );
  printf("  -origjit  <%d..%d> (default: %d) : Setting originator emission jitter to d ms  \n", MIN_ORIG_JITTER, MAX_ORIG_JITTER, arg_orig_jitter_ms  );
  printf("  -fwjit    <%d..%d> (default: %d) : Setting forward (rcvd-orig-re-broadcast) jitter to d ms  \n", MIN_FW_JITTER, MAX_FW_JITTER, arg_fw_jitter_ms  );

}


int process_arg(char *argp, char** argv, int argc)
{
  int vali;

  if(!memcmp((&(argp[0])),"debug",5) && argc >= 2){
    vali = atoi( *(argv+1) );
    if( vali < MIN_DEBUG || vali > MAX_DEBUG ) return 0;
    arg_debug = vali;
    printf("Setting debug level to %d \n", arg_debug);
    return 2;
  }

  if(!memcmp((&(argp[0])),"ttl",3) && argc >= 2){
    vali = atoi( *(argv+1) );
    if( vali < MIN_TTL || vali > MAX_TTL ) return 0;
    arg_ttl = vali;
    printf("will configure next device with ttl %d \n", arg_ttl);
    return 2;
  }

  else if (!memcmp((&(argp[0])),"dev",3) && argc >= 2){
    return init_device ( *(argv+1) );
  }

  else if (!memcmp((&(argp[0])),"help",4) && argc >= 1){
    help();
    finishNow();    exit(0);
  }
   
  else if(!memcmp((&(argp[0])),"rmetric",7) && argc >= 2){
    vali = atoi( *(argv+1) );
    if( vali < MIN_ROUTING_METRIC || vali > MAX_ROUTING_METRIC ) return 0;
    arg_routing_metric = vali;
    printf("Setting routing metric to %d \n", arg_routing_metric );
    return 2;
  }

  else if(!memcmp((&(argp[0])),"cpolicy",7) && argc >= 2){
    vali = atoi( *(argv+1) );
    if( vali < MIN_CONSIDER_POLICY || vali > MAX_CONSIDER_POLICY ) return 0;
    arg_consider_policy = vali;
    printf("Setting consider policy to %d \n", arg_consider_policy );
    return 2;
  }

  else if(!memcmp((&(argp[0])),"fpolicy",7) && argc >= 2){
    vali = atoi( *(argv+1) );
    if( vali < MIN_FORWARD_POLICY || vali > MAX_FORWARD_POLICY ) return 0;
    arg_forward_policy = vali;
    printf("Setting forward policy to %d \n", arg_forward_policy );
    return 2;
  }

  else if(!memcmp((&(argp[0])),"mbundle",7) && argc >= 2){
    vali = atoi( *(argv+1) );
    if( vali < MIN_ORIG_BUNDLE || vali > MAX_ORIG_BUNDLE ) return 0;
    arg_max_orig_bundle = vali;
    printf("Setting max originator bundling to %d \n", arg_max_orig_bundle );
    return 2;
  }

  else if(!memcmp((&(argp[0])),"origival",8) && argc >= 2){
    vali = atoi( *(argv+1) );
    if( vali < MIN_ORIG_INTERVAL || vali > MAX_ORIG_INTERVAL ) return 0;
    arg_orig_interval_ms = vali;
    printf("Setting average originator interval to %d ms \n", arg_orig_interval_ms );
    return 2;
  }
  
  else if(!memcmp((&(argp[0])),"bidito",6) && argc >= 2){
    vali = atoi( *(argv+1) );
    if( vali < MIN_BIDIRECT_TO || vali > MAX_BIDIRECT_TO ) return 0;
    arg_bidirect_to_ms = vali;
    printf("Setting nidirectional neighbor timeout to %d ms \n", arg_bidirect_to_ms );
    return 2;
  }

  else if(!memcmp((&(argp[0])),"origjit",7) && argc >= 2){
    vali = atoi( *(argv+1) );
    if( vali < MIN_ORIG_JITTER || vali > MAX_ORIG_JITTER ) return 0;
    arg_orig_jitter_ms = vali;
    printf("Setting originator emission jitter to %d ms \n", arg_orig_jitter_ms );
    return 2;
  }

  else if(!memcmp((&(argp[0])),"fwjit",5) && argc >= 2){
    vali = atoi( *(argv+1) );
    if( vali < MIN_FW_JITTER || vali > MAX_FW_JITTER ) return 0;
    arg_fw_jitter_ms = vali;
    printf("Setting forward (rcvd-orig-re-broadcast) jitter to %d ms \n", arg_fw_jitter_ms );
    return 2;
  }
  

  return 0;

}


long tv2time( struct timeval *tv )
{
  return tv->tv_sec * 1000 + tv->tv_usec / 1000;  
}

void time2tv( struct timeval *tv, long time_ms )
{
  tv->tv_sec = time_ms / 1000;
  tv->tv_usec = (time_ms - (tv->tv_sec * 1000)) * 1000 ;
  return;
}

void addTime2tv( struct timeval *tv, long time_ms )
{
  int sec = (time_ms / 1000);
  int msec = (time_ms - (sec * 1000));
  tv->tv_sec = tv->tv_sec + sec;
  tv->tv_usec = tv->tv_usec + (msec*1000);
  if  ( tv->tv_usec >= 1000000 ) {
    tv->tv_usec = tv->tv_usec - 1000000;
    tv->tv_sec++;
  }
  return;
}


void abs2relTv(  struct timeval *tv_abs,  struct timeval *tv_rel )
{
  get_time_internal(&now_tv);
  if( timercmp( &now_tv, tv_abs,>= ) ){
    timerclear(tv_rel);
  } else {
    timersub(tv_abs, &now_tv, tv_rel);
  }
  return;
}

void debug_event_list( void ) {
  struct list_head *list_pos;
  struct to_node *to_node;
  dbg(5, "debug_event_list():\n");
  list_for_each( list_pos, &to_list){
    to_node = list_entry( list_pos, struct to_node, list );
    dbg(5, "  event: %d, s:%ld us:%ld \n", to_node->event, to_node->to.tv_sec, to_node->to.tv_usec);
  }
}





static void get_time_internal(struct timeval *tv)
{
/*   int sec; */
/*   int usec; */
/*   unsigned long ret; */
  gettimeofday(tv, NULL);

  timersub( tv, &start_time_tv, tv );

}

static unsigned long get_time( struct timeval *tv )
{
  struct timeval ttv;
  if (tv==NULL) tv = &ttv;
  unsigned long ret;

  get_time_internal(tv);
	
  ret =  ( ( tv->tv_sec * 1000 ) + ( tv->tv_usec / 1000 ) );
  dbg(5, "  get_time: %ldms (exactly %ld %ld) \n", ret, tv->tv_sec, tv->tv_usec);
  return ret;
}



void set_forwarding(int state)
{
  FILE *f;

  if((f = fopen("/proc/sys/net/ipv4/ip_forward", "w")) == NULL)
    return;
	
  fprintf(f, "%d", state);
  fclose(f);
}

int get_forwarding(void)
{
  FILE *f;
  int state = 0;
	
  if((f = fopen("/proc/sys/net/ipv4/ip_forward", "r")) == NULL)
    return 0;
	
  fscanf(f, "%d", &state);
  fclose(f);

  return state;
}



char addrIsMine(  unsigned int neigh ) {
  int dnap;
  for( dnap=0; dnap < device_list_size; dnap++ ) {
    if (device_node_array[dnap].orig_node->addr == neigh)
      return YES;
  }
  return NO;
}


void add_del_route(struct orig_node *dest_node, struct orig_node *router_node, 
		   int del, struct device_node *via_device_node )
{
  struct rtentry route;
  char str1[16], str2[16];
  struct sockaddr_in *addr;
  unsigned int dest;
  unsigned int router;
	
  if( dest_node == NULL || router_node == NULL ) {
    output(1, "add_del_route() calles with dest_node or router_node = NULL !!!!!!!!!!!!!!!!!!\n");
  }
	
  dest = dest_node->addr;
  router = router_node->addr;
	
  inet_ntop(AF_INET, &dest, str1, sizeof (str1));
  inet_ntop(AF_INET, &router, str2, sizeof (str2));

  dbg(2, "add_del_route(): %s route to %s via %s\n", del ? "Deleting" : "Adding", str1, str2);

  memset(&route, 0, sizeof (struct rtentry));

  addr = (struct sockaddr_in *)&route.rt_dst;

  addr->sin_family = AF_INET;
  addr->sin_addr.s_addr = dest;

  addr = (struct sockaddr_in *)&route.rt_genmask; 

  addr->sin_family = AF_INET;
  addr->sin_addr.s_addr = 0xffffffff;

  route.rt_flags = RTF_HOST | RTF_UP;
	
  if (dest != router)
    {
      addr = (struct sockaddr_in *)&route.rt_gateway;

      addr->sin_family = AF_INET;
      addr->sin_addr.s_addr = router;

      route.rt_flags |= RTF_GATEWAY;
    }

  route.rt_metric = 1;

  if( del ) {
    if( dest_node->configured_device_node == NULL ) {
      fprintf(stderr, " add_del_route called for del with dest_node without configured_device_node !!!!! \n");
      finishNow();      exit(-1);
    }
    route.rt_dev = dest_node->configured_device_node->arg_device;

    // TBD: using socket of dest_node->configured_device_node for configuring routes
    if (ioctl(dest_node->configured_device_node->snd_sock , SIOCDELRT , &route) < 0){
      fprintf(stderr, "Cannot delete route to %s via %s: %s\n", str1, str2, strerror(errno));
      finishNow();      exit(-1);
    }
    dest_node->configured_device_node = NULL;
		
  } else {
    if( via_device_node == NULL || dest_node->configured_device_node != NULL) {
      fprintf(stderr, " add_del_route called for add with via_device_node==NULL or dest_node->configured_device_node!=NULL !!!!! \n");
      finishNow();      exit(-1);
    }
		
    route.rt_dev = via_device_node->arg_device;

    // TBD: using socket of via_device_node for configuring roues
    if (ioctl( via_device_node->snd_sock ,  SIOCADDRT, &route) < 0){
      fprintf(stderr, "Cannot add route to %s via %s, dev %s: %s\n", str1, str2, via_device_node->arg_device, strerror(errno));
      finishNow();      exit(-1);
    }
    dest_node->configured_device_node = via_device_node;
  }
}




int send_packet(unsigned char *buff, int len, struct device_node *device_node)
{
  if (sendto(device_node->snd_sock, buff, len, 0, 
	     (struct sockaddr *)&(device_node->snd_broad), sizeof (struct sockaddr_in)) < 0)
    {
      fprintf(stderr, "Cannot send packet: %s\n", strerror(errno));
      return -1;
    }
  return 0;
}



long currentlyBidirectionalNeighFunc( struct orig_node *neigh_node,
				     int via_device_node_index )
{
  char neigh_str[ADDR_STR_LEN];
  addr_to_string(neigh_node->addr, neigh_str, sizeof (neigh_str));

  dbg(5, "currentlyBidirectionalNeighFunc(): called for %s \n", neigh_str);

  if ( neigh_node->this_device_node != NULL ) {
    output(1, "currentlyBidirectionalNeighFunc(): called for own orig_node !!!!!!!!!!!!!!!!!!!!!!!!! \n");
    return -1;
  }
  
  time2tv( &then_tv, (long) arg_bidirect_to_ms );
  get_time_internal( &now_tv );
  timeradd( &neigh_node->lastConfAsNb[via_device_node_index], &then_tv, &then_tv );
  if( timercmp( &then_tv, &now_tv, <  )) {
    dbg(5, "currentlyBidirectionalNeighFunc(): return -1 \n");
    return -1;
  } else {
    timersub( &then_tv, &now_tv, &then_tv );
    dbg(5, "currentlyBidirectionalNeighFunc(): return %ld \n", tv2time( &then_tv ));
    return tv2time( &then_tv );
  }
}




struct pack_node *createOtherPackNode( unsigned char treatmentFlags, 
				       struct orig_node *orig_node, struct orig_node *neigh_node,
				       struct device_node *via_device_node,
				       struct packet_orig *in, 
/* 					 struct timeval *ooptim_originated_rview_tstmp,  */
				       struct timeval *received )
{
  struct pack_node *pack_node;
  dbg(5, "createOtherPackNode():  \n"); 
	
  if( orig_node == NULL || neigh_node == NULL || via_device_node == NULL || in == NULL 
      //  	|| pack_node->orig_node->addr != in->orig || pack_node->seqno != in->seqno 
      ){
    output(1, "createOtherPackNode(): missing pointer !!!!!!!!!!!!!!!!!!!!!!!!!!!!! \n"); 
    finishNow();
  }

  if( treatmentFlags & ORIG_RCVD_UNI_FLAG) {
    output(1, "createOtherPackNode(): called for orig with rcvd unidirectional flag  !!!!!!!!!!!!!!!!!!!!!!!!!!!!! \n"); 
    finishNow();
  } 
  
  dbg(4, "Creating new packet_node\n");
  pack_node = (struct pack_node*) alloc_memory(sizeof(struct pack_node));
  memset(pack_node, 0, sizeof(struct pack_node));
  INIT_LIST_HEAD(&pack_node->list);
  pack_node->seqno = in->seqno;
  pack_node->orig_node = orig_node;

  //TBD: _tail
  list_add(&pack_node->list, &orig_node->pack_list);
  
  pack_node->via_orig_node = neigh_node;
  pack_node->via_device_node = via_device_node;
  pack_node->treatmentFlags = treatmentFlags;
  pack_node->flags = in->flags; // unidirectinal flag may be reassigned later
  if( !(treatmentFlags & ORIG_BDNB_FLAG) ) {
    pack_node->flags = pack_node->flags | UNIDIRECTIONAL_FLAG;
  } 
  timeradd( received, &tv_null, &pack_node->received );
  pack_node->hold_back_time = in->hold_back_time;
/*   timeradd( ooptim_originated_rview_tstmp, &tv_null, &pack_node->ooptim_originated_rview_tstmp ); */
  pack_node->ttl = in->ttl - 1;
  pack_node->originated_oview_tstmp = in->originated_oview_tstmp;
      
  return pack_node;
}


struct pack_node *generateOwnPackNode( struct device_node *device_node  ) {
  struct orig_node *orig_node = NULL;
  struct pack_node *pack_node;
  int device_node_index = device_node->device_node_index;
  get_time_internal( &now_tv );
  if( device_node->orig_node == NULL ) {
    output(1, "generateOwnPackNode called with device_node not containing valid orig_node !!!!!");
    finishNow();    exit(1);
  }
  orig_node = device_node->orig_node;
  dbg(4, "Creating new own_pack_node \n");
  pack_node = (struct pack_node*) alloc_memory(sizeof(struct pack_node));
  memset(pack_node, 0, sizeof(struct pack_node));
  INIT_LIST_HEAD(&pack_node->list);
  pack_node->seqno = orig_node->this_device_node->seqno++;
  pack_node->orig_node = orig_node;
  pack_node->via_orig_node = orig_node;
  pack_node->flags = orig_node->this_device_node->flags;
  pack_node->ttl = device_node->ttl;

  pack_node->originated_oview_tstmp = get_time(NULL);

  pack_node->hold_back_time = 0;
  //  timeradd( &now_tv, &tv_null, &pack_node->ooptim_originated_rview_tstmp );
  timeradd( &now_tv, &tv_null, &pack_node->received   );
  timeradd( &now_tv, &tv_null, &orig_node->lastSeenAsNb[device_node_index]   );
  timeradd( &now_tv, &tv_null, &orig_node->lastConfAsNb[device_node_index]   );

  //TBD: _tail
  list_add(&pack_node->list, &orig_node->pack_list);
  return pack_node;
}



unsigned char origTreatmentFunc(struct orig_node *orig_node, 
				struct packet_orig *in, 
				struct orig_node *neigh_node, 
				int rcvd_via_device_node_index )
{
  struct pack_node *pack_node;
  struct list_head *pack_pos;
  struct device_node *rcvd_via_device_node = &(device_node_array[ rcvd_via_device_node_index ]);
  unsigned int neigh = neigh_node->addr;
  unsigned char maxSeenTtl = 0;
  unsigned char resultFlags = 0;

  dbg(5, "origTreatmentFunc(): every packet \n"); 

    if ( in->flags & UNIDIRECTIONAL_FLAG ) {
      resultFlags = resultFlags | ORIG_RCVD_UNI_FLAG; 
    }


  if( currentlyBidirectionalNeighFunc( neigh_node, rcvd_via_device_node_index ) >= 0 )
    {
      resultFlags = resultFlags | ORIG_BDNB_FLAG; 
    }

  list_for_each(pack_pos, &orig_node->pack_list) {
    pack_node = list_entry(pack_pos, struct pack_node, list);
    if ( !(resultFlags & ORIG_RCVD_UNI_FLAG) && pack_node->seqno == in->seqno ) {

      resultFlags = resultFlags | ORIG_OS_FLAG; 
	  	
      maxSeenTtl = maxOf( maxSeenTtl, pack_node->ttl );
	  	   	
      if( pack_node->already_scheduled_for_rebroadcast_via_all_devs ) {
	resultFlags = resultFlags | ORIG_BROADCASTED_FLAG;
      }

      if( pack_node->via_orig_node->addr == neigh && pack_node->via_device_node == rcvd_via_device_node ) {
	resultFlags = resultFlags | ORIG_OSND_FLAG;
      }
    }
  } 

  
  // ------------ consider policy evaluation  ---------------------------
  if( arg_consider_policy == CONSIDER_POLICY_MAX_TTL ) {

    if( !(resultFlags & ORIG_OS_FLAG) )  {
      resultFlags = resultFlags | ORIG_CONSIDER_FLAG;
    } else {
      if( maxSeenTtl <= in->ttl-1 ) { /* in->ttl-1 because in->ttl has not been decremented yet */
	resultFlags = resultFlags | ORIG_CONSIDER_FLAG;
      }
    }
	

  } else if( arg_consider_policy == CONSIDER_POLICY_MAX_TTL_MINUS_ONE ) {

    if( !(resultFlags & ORIG_OS_FLAG) )  {
      resultFlags = resultFlags | ORIG_CONSIDER_FLAG;
    } else {
      if( maxSeenTtl-1 <= in->ttl-1) { /* in->ttl-1 because in->ttl has not been decremented yet */
	resultFlags = resultFlags | ORIG_CONSIDER_FLAG;
      }
    }
	

  } else /* if( arg_consider_policy == CONSIDER_POLICY_STRICTLY_FIRST_SEEN )*/ { 
    if( !(resultFlags & ORIG_OS_FLAG) )  {
      resultFlags = resultFlags | ORIG_CONSIDER_FLAG;
    }
  }
    		
  return resultFlags;
}





void add_event_to( int event, struct device_node *datap /*data not to be removed after event*/ 
		   ,unsigned long to_ms )   /* register event timeout in to_list */
{
  int added=0;
  struct to_node *to_node, *new_to_node;
  struct list_head *list_pos;
  new_to_node = (struct to_node*) alloc_memory(sizeof(struct to_node));
  memset(new_to_node, 0, sizeof(struct to_node));
  INIT_LIST_HEAD(&new_to_node->list);
  new_to_node->event = event;
  new_to_node->datap = datap;
  get_time_internal( &new_to_node->to );
  addTime2tv( &new_to_node->to, to_ms );
  dbg(4, "add_event_to(): event %d (%s), to be scheduled in %ld ms, at: %ld:%ld \n",
	 event, debug_event( event ), to_ms, new_to_node->to.tv_sec, new_to_node->to.tv_usec );

  if ( list_empty( &to_list ) ){
    list_add( &new_to_node->list, &to_list );
    return;
  } else {
    list_for_each( list_pos, &to_list){
      to_node = list_entry( list_pos, struct to_node, list );
      if( timercmp( &new_to_node->to, &to_node->to, < ) ) {
	list_add_tail( &new_to_node->list, list_pos );
	added=1;
	return;
      }
    }
    if( !added ) {
      list_add_tail( &new_to_node->list, &to_list );
    }
  }
}

int  get_pend_event(struct device_node **datap ){         /* gets pending and removes event from to_list */
  /* returns 0 if no event */
  int ret;
  struct to_node *to_node;
  struct list_head *list_pos;
  get_time_internal( &now_tv );
  list_for_each( list_pos, &to_list){
    to_node = list_entry( list_pos, struct to_node, list );
    if( timercmp( &now_tv, &to_node->to, >= ) ) {
      ret = to_node->event;
      *datap=to_node->datap;
      list_del(list_pos);
      free_memory(to_node);

      dbg(4, "get_pend_event(): event %d (%s), to be scheduled at %ld:%ld \n",
	     ret, debug_event( ret ), to_node->to.tv_sec, to_node->to.tv_usec );


      return ret;
    } else {
      return 0;
    }
  }
  return 0;
}

    


void get_next_to( struct timeval *tv )     /* get next scheduled to in ms from to_list */
{
  struct to_node *to_node;
  struct list_head *list_pos;
  list_for_each( list_pos, &to_list ){
    to_node = list_entry( list_pos, struct to_node, list );
    tv->tv_sec  = to_node->to.tv_sec;
    tv->tv_usec = to_node->to.tv_usec;
    return;
  }
  return;
}

int jitter( int jitter ) {
  return ( rand_num( jitter * 2 ) - jitter );
}


void addToAllForwLists( struct pack_node *pack_node, int delay ) {
  int dnap=0;
  pack_node->already_scheduled_for_rebroadcast_via_all_devs = YES;
  for( dnap=0; dnap < device_list_size; dnap++ ) {
    addToForwList( pack_node, delay, dnap );
  }
  dbg(5, "addToAllForwLists(): end \n");
}

/* adds pack_node to forw_list 
 */ 
void addToForwList( struct pack_node *pack_node, int delay, short via_device_node_item )
{
  struct device_node *device_node;
	
  if( via_device_node_item < 0 || via_device_node_item >= device_list_size ) {
    output(1, "addToForwList(): called with invalid via_device_node_item %d \n", via_device_node_item);
    finishNow();
  }

    //	list_for_each( device_pos, &device_list){
    int added=0;
    struct forw_node  *forw_node,  *new_forw_node;
    struct list_head *forw_pos;
    device_node = &device_node_array[via_device_node_item];
  
    dbg(4, "addToAllForwLists(): adding to forw list of IF %s \n", device_node->arg_device );
    new_forw_node = (struct forw_node*) alloc_memory(sizeof(struct forw_node));
    memset(new_forw_node, 0, sizeof(struct forw_node));
    INIT_LIST_HEAD(&new_forw_node->list);
    new_forw_node->pack_node = pack_node;
    timeradd( &pack_node->received, &tv_null, &new_forw_node->order);
    addTime2tv( &new_forw_node->order, delay );

    if ( list_empty( &device_node->forw_list ) ){
      dbg(5, "addToAllForwLists(): init empty list \n");
      list_add( &new_forw_node->list, &device_node->forw_list );
      added=1;
    } else {
      dbg(5, "addToAllForwLists(): init non-empty list \n");
      list_for_each( forw_pos, &device_node->forw_list){
	forw_node = list_entry( forw_pos, struct forw_node, list );
	if( timercmp( &new_forw_node->order, &forw_node->order, < ) ) {
	  list_add_tail( &new_forw_node->list, forw_pos );
	  added=1;
	  return;
	}
      }
      if(!added ) {
	list_add_tail( &new_forw_node->list, &device_node->forw_list );
      }
    }
    dbg(5, "addToAllForwLists(): scheduling...\n");
    device_node->forw_list_size++;
    if( device_node->forw_list_size % arg_max_orig_bundle == 0 ) {
      add_event_to( EVENT_FW_JITTER, device_node, 
		    arg_fw_jitter_ms + jitter( arg_fw_jitter_ms ) );
    }

}

int wait_for_packet(unsigned char *buff, int len, unsigned int *neigh,
		    int *rcvd_via_device_node_item, struct timeval *tv_to_abs, int *more_data)
{
  fd_set wait_set;
  int res;
  struct sockaddr_in addr;
  unsigned int addr_len;
  struct timeval tv_rel;
  int max_rcv_sock;
  int dli;

  //  while (true) {
  max_rcv_sock=0;
  dbg(4, "wait_for_packet(): of max size %d  \n", len);

  *more_data = NO;
	
  abs2relTv( tv_to_abs, &tv_rel );

  if ( device_list_size <= 0 ){
    fprintf(stderr, "Device list empty !!!!!!! \n");
    return -1;
  }

  FD_ZERO(&wait_set);

  for ( dli=0; dli< device_list_size; dli++ ) {
    FD_SET(device_node_array[dli].snd_sock, &wait_set);
    max_rcv_sock = maxOf( max_rcv_sock, device_node_array[dli].snd_sock );
  }

  for (;;)
    {
      res = select(max_rcv_sock + 1, &wait_set, NULL, NULL, &tv_rel);

      if (res >= 0)
	break;

      if (errno != EINTR)
	{
	  fprintf(stderr, "Cannot select: %s\n", strerror(errno));
	  return -1;
	}
    }

  if (res == 0)
    return 0;

  if (res > 1) {
    *more_data = YES;
  } 

  for ( dli=0; dli< device_list_size; dli++ ) {
    if( FD_ISSET(device_node_array[dli].snd_sock, &wait_set) ) {
      addr_len = sizeof (struct sockaddr_in);
      res = recvfrom(device_node_array[dli].snd_sock, buff, len, 0, (struct sockaddr *)&addr, &addr_len);
      if (res == len) {
	output(1, "wait_for_packet(): socket may have received more data than could be collected, am'I scheduled again ????? !!!!!!!!!!!!!!!!!!!!!!! \n");
	*more_data = YES;
      } 
      
      if (res < 0)
	{
	  fprintf(stderr, "Cannot receive packet: %s\n", strerror(errno));
	  finishNow();	  exit( -1 );
	}
      *neigh = addr.sin_addr.s_addr;
      //      unsigned long src =  addr.sin_addr.s_addr;
      *rcvd_via_device_node_item = dli;
      char str1[16];
      //      char str2[16];
      addr_to_string(*neigh, str1, sizeof (str1));
      //      addr_to_string(src, str2, sizeof (str2));

      dbg(3, "wait_for_packet(): received %d bytes via sock %d, dev %s, from srcIP: %s, dstIP %s  \n", 
	  res, device_node_array[dli].snd_sock, device_node_array[dli].arg_device, str1,"????????????" );

      return res;
    }
  }

  return res;
  //  }
}


void broadcastFwList( struct device_node *device_node ) {
  int i=0;
  struct list_head *forw_pos;
  struct forw_node *forw_node=NULL;
  struct packet_orig in_stream[MAX_ORIG_BUNDLE];
  struct packet_orig *packet_orig;
  char orig_str[ADDR_STR_LEN], neigh_str[ADDR_STR_LEN];
  	
  dbg(4, "broadcastFwList(): bundling %d of %d waiting packets in device_node->forw_list !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! \n",
	 arg_max_orig_bundle, device_node->forw_list_size );
  get_time_internal( &now_tv );
  while( device_node->forw_list_size >= 1 && i < (arg_max_orig_bundle) ) {
    packet_orig = &in_stream[i++];
    memset( packet_orig, 0, sizeof( struct packet_orig ) );
    forw_pos = device_node->forw_list.next;
    forw_node = list_entry( forw_pos, struct forw_node, list );
    packet_orig->orig = forw_node->pack_node->orig_node->addr;
    packet_orig->seqno = forw_node->pack_node->seqno;
    packet_orig->flags = forw_node->pack_node->flags;
    packet_orig->ttl = forw_node->pack_node->ttl;
    timeradd( &now_tv, &tv_null, &forw_node->pack_node->forwarded );
/*     timersub( &now_tv, &forw_node->pack_node->ooptim_originated_rview_tstmp, &then_tv ); */
    timersub( &now_tv, &forw_node->pack_node->received, &then_tv );
    packet_orig->hold_back_time = forw_node->pack_node->hold_back_time + tv2time( &then_tv );
    packet_orig->originated_oview_tstmp = forw_node->pack_node->originated_oview_tstmp;

    addr_to_string(packet_orig->orig, orig_str, sizeof (orig_str));
    addr_to_string(device_node->orig_node->addr , neigh_str, sizeof (neigh_str));
    dbg(3, "bundling %d. packet, originator %s, seqno %d, ttl %d, flags %d, hold_back_time: %d "
	   " via IF: %s, IF orig %s \n", 
	   i, orig_str, packet_orig->seqno, packet_orig->ttl, 
	   packet_orig->flags, packet_orig->hold_back_time, device_node->arg_device, neigh_str );
      	
    list_del( forw_pos );
    free_memory( forw_node );
    device_node->forw_list_size--;
  }
	
  send_packet( (unsigned char*)&in_stream[0], (i*sizeof(struct packet_orig)), device_node);
  dbg(3, "send packet ... \n");

}


/* creates, updates, and returns orig_node of given neigh_ip */
struct orig_node *update_neighbour(struct packet_orig *in, 
				   unsigned int neigh, 
				   int via_device_node_index,
				   struct timeval *received )
{
  struct orig_node *neigh_node;
  struct device_node *via_device_node = &(device_node_array[ via_device_node_index ]);

  dbg(2, "update_neighbour(): Searching neighbour originator entry of forwarder of received packet \n");

  neigh_node = get_orig_node( neigh );
  timeradd( received, &tv_null, &neigh_node->lastSeenAsNb[ via_device_node_index ] );
  
  if (neigh != via_device_node->orig_node->addr && 
      in->orig == via_device_node->orig_node->addr && in->ttl == via_device_node->ttl - 1)	{
    dbg(2, "received my own packet from neighbour indicating bidirectional link, updating last_reply stamp \n");  
    timeradd( received, &tv_null, &neigh_node->lastConfAsNb[ via_device_node_index ] );
    //    neigh_node->via_device_node = via_device_node;
  }
  
  return neigh_node;
  
}

/* purge orig_nodes' pack_nodes find and update best route */
void purgePackNodes( struct orig_node *orig_node ){
  struct list_head *pack_pos;
  struct pack_node *pack_node; 
  char once_again=YES;
  int packets=0;
  
  dbg(4, "purgePackNodes() \n");
  get_time_internal( &now_tv );
  /* purge outdated pack_nodes, calculate metrics for up-to-date pack_nodes */

  while(once_again==YES){
    once_again=NO;
    packets=0;
    list_for_each(pack_pos, &orig_node->pack_list ) {
      pack_node = list_entry(pack_pos, struct pack_node, list);
      packets++;
      time2tv( &then_tv, arg_purge_to_ms );
      timeradd( &pack_node->received, &then_tv, &then_tv );
      if ( timercmp( &then_tv, &now_tv, < ) ) {
	dbg(4, "purgePackNodes(): deleting pack_node \n");
	list_del( pack_pos );
	free_memory( pack_node );
	once_again=YES;
	break;
      } 
    }
    dbg(4, "purgePackNodes() completed after %d pack_nodes\n", packets);
  }
  
  if( list_empty(&orig_node->pack_list ) )  dbg(5, "purgePackNodes(): list empty !!! \n");
  
  dbg(5, "purgePackNodes(): return \n");

}

// TBD: is this correct ???
char  aGreaterB_us_wraparounds( unsigned short a_us, unsigned short b_us) {
  long amb = ((long)a_us) - ((long)b_us);
  if( (0 < amb && amb < 32768) || amb < -32768) return YES;
  return NO;
}

struct summary_node *getMetricNode( struct orig_node *orig_node ){

  struct summary_node *summary_node = NULL;
  struct list_head *summary_pos;
  int hmvdaPos;

  list_for_each(summary_pos, &summary_list) {
    summary_node = list_entry(summary_pos, struct summary_node, list);
    if( summary_node->orig_node == NULL || summary_node->orig_node == orig_node ) {
      break;
    } else {
      summary_node = NULL;
    }
  }

  if ( summary_node == NULL ) {
    dbg(3, "getMetricNode(): allocating mem for new summary_node \n");
    summary_node = (struct summary_node*) alloc_memory(sizeof(struct summary_node));
    memset(summary_node, 0, sizeof(struct summary_node));
    INIT_LIST_HEAD(&summary_node->list);
    summary_node->orig_node = NULL;
    list_add_tail(&summary_node->list, &summary_list);
  }

  if ( summary_node->orig_node == NULL ) {
      dbg(3, "getMetricNode(): init empty summary_node \n");

      summary_node->orig_node = orig_node;
      summary_node->rcvdOrigs   = 0;
      summary_node->sumTtl   = 0;
      summary_node->minTtl   = (unsigned char) -1;
      summary_node->maxTtl   = 0;
      summary_node->minSeqno = (unsigned long) -1;
      summary_node->maxSeqno = 0;
      summary_node->minTtpc  = MAX_OF_LONG;
      summary_node->maxTtpc  = MIN_OF_LONG;

      memset( summary_node->hmvda, 0, sizeof( summary_node->hmvda ) );
    
    for (hmvdaPos=0; hmvdaPos < device_list_size; hmvdaPos++ ) {
      summary_node->hmvda[hmvdaPos].minTtl   = (unsigned char) -1;
      summary_node->hmvda[hmvdaPos].minSeqno = (unsigned long) -1;
      summary_node->hmvda[hmvdaPos].minTtpc  = MAX_OF_LONG;
      summary_node->hmvda[hmvdaPos].maxTtpc  = MIN_OF_LONG;
    }
  }

  return summary_node;
}

long get_tripTimePlusConst ( struct pack_node *pack_node ) 
{
  long ret;
  struct orig_node *orig_node = pack_node->orig_node;
  
  ret = ( ( ( tv2time( &pack_node->received ) - orig_node->min_originated_rview_tstmp )  - 
	    ( pack_node->originated_oview_tstmp - orig_node->min_originated_oview_tstmp ) ) - 
	  pack_node->hold_back_time );

  if( ret > TRIP_TIME_PLUS_CONST_RESET_THRESHOLD || ret < -TRIP_TIME_PLUS_CONST_RESET_THRESHOLD ) {
    char orig_str[ADDR_STR_LEN];
    orig_node->min_originated_oview_tstmp = pack_node->originated_oview_tstmp;
    orig_node->min_originated_rview_tstmp = tv2time( &pack_node->received ) ;
    orig_node->minTtpc = MAX_OF_LONG;

    addr_to_string( orig_node->addr, orig_str, sizeof (orig_str) );
    output(1, "get_tripTimePlusConst(): Orig: %s restarted!, resetting min_originated_oview_tstmp \n", orig_str);

    ret = ( ( ( tv2time( &pack_node->received ) - orig_node->min_originated_rview_tstmp )  - 
	      ( pack_node->originated_oview_tstmp - orig_node->min_originated_oview_tstmp ) ) - 
	    pack_node->hold_back_time );
  }

  return ret;
}

int updateHelperMetricsForOrig( struct orig_node *orig_node ) 
{
  char orig_str[ADDR_STR_LEN];
  char neigh_str[ADDR_STR_LEN];
  struct list_head *pack_pos;
  struct pack_node *pack_node;
  struct list_head *summary_pos;
  struct summary_node *summary_node = NULL;

  int hmvdaPos=0;
  int bdnbRcvdOrigs = 0;

  if( orig_node->this_device_node ) {
    output(1, "updateHelperMetricsForOrig(): called with own orig_node \n");
    finishNow();
  }

  dbg(3, "updateHelperMetricsForOrig(): purging summary_list \n");
  list_for_each(summary_pos, &summary_list) {
    summary_node = list_entry(summary_pos, struct summary_node, list);
    if( summary_node->orig_node == NULL ) {
      break;
    } else {
      summary_node->orig_node = NULL;
    }

  }
  
  dbg(3, "updateHelperMetricsForOrig(): calculate summary \n");
  /* calculate summary for up-to-date pack_nodes of this orig */
  summary_node = NULL;
  list_for_each(pack_pos, &orig_node->pack_list) {

    pack_node = list_entry(pack_pos, struct pack_node, list);
    
    if( pack_node->seqno + arg_received_seq_range > orig_node->maxSeqno ) {

      if( !(pack_node->treatmentFlags & ORIG_RCVD_UNI_FLAG) && (pack_node->treatmentFlags & ORIG_OSND_FLAG)) {
	dbg(1, "updateHelperMetricsForOrig(): !ORIG_RCVD_UNI_FLAG && ORIG_OSND_FLAG !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!1 \n");
      }
      //      if( pack_node->treatmentFlags & ORIG_BDNB_FLAG ) {
      if( !(pack_node->treatmentFlags & ORIG_RCVD_UNI_FLAG) && !(pack_node->treatmentFlags & ORIG_OSND_FLAG)) {
	
	if( summary_node == NULL || summary_node->orig_node != pack_node->via_orig_node ){
	  summary_node = getMetricNode( pack_node->via_orig_node );
	}
	
	if( summary_node == NULL || summary_node->orig_node != pack_node->via_orig_node ){
	  output(1, "updateHelperMetricsForOrig(): getMetricNode returned trash !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! \n");
	  finishNow();
	}
	
	bdnbRcvdOrigs++;
	
	summary_node->rcvdOrigs++;

	if( !pack_node->treatmentFlags & ORIG_OS_FLAG ) 
	  summary_node->rcvd1Origs++;
	
	summary_node->sumTtl+=pack_node->ttl;
	
	summary_node->minTtl = minOf( summary_node->minTtl, pack_node->ttl );
	summary_node->maxTtl = maxOf( summary_node->maxTtl, pack_node->ttl );
	
	summary_node->minSeqno = minOf(summary_node->minSeqno, pack_node->seqno);
	summary_node->maxSeqno = maxOf(summary_node->maxSeqno, pack_node->seqno);

	long ttpc = get_tripTimePlusConst( pack_node );
	summary_node->minTtpc = minOf(summary_node->minTtpc, ttpc);
	summary_node->maxTtpc = maxOf(summary_node->maxTtpc, ttpc);
	summary_node->sumTtpc+=ttpc;
	if(summary_node->maxSeqno == pack_node->seqno) 
	  summary_node->latestTtpc = ttpc;
	orig_node->minTtpc = minOf(orig_node->minTtpc, ttpc);

	hmvdaPos = pack_node->via_device_node->device_node_index;
	
	summary_node->hmvda[hmvdaPos].rcvdOrigs++;
/* 	if( summary_node->hmvda[hmvdaPos].rcvdOrigs > arg_received_seq_range ){ */
/* 	  dbg(0, "updateHelperMetricsForOrig(): summary_node->hmvda[hmvdaPos].rcvdOrigs > arg_received_seq_range !!!!!!!???????? \n"); */
/* 	  finishNow(); */
/* 	} */

	if( !(pack_node->treatmentFlags & ORIG_OS_FLAG) ) 
	  summary_node->hmvda[hmvdaPos].rcvd1Origs++;
	summary_node->hmvda[hmvdaPos].sumTtl+= pack_node->ttl;
	summary_node->hmvda[hmvdaPos].minTtl = minOf( summary_node->hmvda[hmvdaPos].minTtl, pack_node->ttl);
	summary_node->hmvda[hmvdaPos].maxTtl = maxOf( summary_node->hmvda[hmvdaPos].maxTtl, pack_node->ttl);
	summary_node->hmvda[hmvdaPos].maxSeqno = maxOf( summary_node->hmvda[hmvdaPos].maxSeqno, pack_node->seqno);
	summary_node->hmvda[hmvdaPos].minSeqno = minOf( summary_node->hmvda[hmvdaPos].minSeqno, pack_node->seqno);
	summary_node->hmvda[hmvdaPos].minTtpc = minOf(summary_node->hmvda[hmvdaPos].minTtpc, ttpc);
	summary_node->hmvda[hmvdaPos].maxTtpc = maxOf(summary_node->hmvda[hmvdaPos].maxTtpc, ttpc);
	summary_node->hmvda[hmvdaPos].sumTtpc+=ttpc;
	if(summary_node->hmvda[hmvdaPos].maxSeqno == pack_node->seqno) 
	  summary_node->hmvda[hmvdaPos].latestTtpc = ttpc;
	
	
	if( arg_debug >= 5 ) {
	  addr_to_string(orig_node->addr, orig_str, sizeof (orig_str));
	  addr_to_string(summary_node->orig_node->addr, neigh_str, sizeof (neigh_str));
	  dbg(5, "updateHelperMetricsForOrig(): updated %s via neigh %s, rcvdOrigs %d, maxSeqno %d \n", 
	      orig_str, neigh_str,
	      summary_node->rcvdOrigs,
	      summary_node->maxSeqno
	      );
	}
      }
    } else {
      break;
    }


  }
  
  dbg(5, "updateHelperMetricsForOrig(): return \n");
  return bdnbRcvdOrigs;
}


float avgTtl( struct summary_node *summary_node ) 
{
  return ((summary_node->rcvdOrigs>=1)?
	  (((float)(summary_node->sumTtl))/
	   ((float)(summary_node->rcvdOrigs))):(0));
}

float avgTtl_dev( struct summary_node *summary_node, int dev_index ) 
{
  return (( summary_node->hmvda[dev_index].rcvdOrigs >= 1 )?
	  (((float)(summary_node->hmvda[dev_index].sumTtl))/
	   ((float)(summary_node->hmvda[dev_index].rcvdOrigs))):(0));
}

float avgTtpc_dev( struct summary_node *summary_node, int dev_index ) 
{
  return (( summary_node->hmvda[dev_index].rcvdOrigs >= 1 )?
	  (((float)(summary_node->hmvda[dev_index].sumTtpc))/
	   ((float)(summary_node->hmvda[dev_index].rcvdOrigs))):(0));
}

void output_route( char *orig_str, char* hop_str, struct orig_node *orig_node, int hmvdaPos, struct summary_node *summary_node) 
{
  output_nt(1, "%15s %15s  %4ld %6s %3d %2d  %4.1f %3d %3d  %5d %5d  %6.1f %4ld %4ld %4ld\n", 
	    orig_str, hop_str, 
	    ( currentlyBidirectionalNeighFunc( summary_node->orig_node, hmvdaPos ) ),
	    device_node_array[hmvdaPos].arg_device,
	    summary_node->hmvda[hmvdaPos].rcvdOrigs,
	    summary_node->hmvda[hmvdaPos].rcvd1Origs,
	    avgTtl_dev( summary_node, hmvdaPos ),
	    summary_node->hmvda[hmvdaPos].minTtl,
	    summary_node->hmvda[hmvdaPos].maxTtl, 
	    summary_node->hmvda[hmvdaPos].minSeqno,
	    summary_node->hmvda[hmvdaPos].maxSeqno,
	    avgTtpc_dev( summary_node, hmvdaPos ) - (float)orig_node->minTtpc,
	    summary_node->hmvda[hmvdaPos].minTtpc    - orig_node->minTtpc,
	    summary_node->hmvda[hmvdaPos].maxTtpc    - orig_node->minTtpc,
	    summary_node->hmvda[hmvdaPos].latestTtpc - orig_node->minTtpc
	    );


  if( summary_node->hmvda[hmvdaPos].rcvdOrigs > arg_received_seq_range ){ 
    dbg(0, "output_route(): summary_node->hmvda[hmvdaPos].rcvdOrigs > arg_received_seq_range !!!!!!!???????? \n"); 
    finishNow(); 
  } 


}

void showRoutes( struct list_head *debug_orig_list )
{
  char orig_str[ADDR_STR_LEN], hop_str[ADDR_STR_LEN], metric_str[ADDR_STR_LEN];
  struct list_head *orig_pos;
  struct orig_node *orig_node; 
  struct list_head *summary_pos;
  struct summary_node *summary_node;
  int	hmvdaPos=0, devPos=0;

  output_nt(1, "\nshowRoutes() ");

  for (devPos=0; devPos<device_list_size; devPos++) {
    addr_to_string(device_node_array[devPos].orig_node->addr, orig_str, sizeof (orig_str));
    output_nt(1, " dev:%s ip:%s ttl:%d seq:%ld ", 
	      device_node_array[devPos].arg_device, orig_str, device_node_array[devPos].ttl, device_node_array[devPos].seqno);
  }
  output_nt(1, "rmetric:%d, cpolicy:%d, fpolicy:%d \n",
	 arg_routing_metric, arg_consider_policy, arg_forward_policy );

  output_nt(1, "to_orig         via_NB_orig      BDNB device all/1.  av/mi/ma-Ttl  mi/ma-SeqNo  av/mi/ma/la-ttpc \n");
  //  output_nt(1, "123.123.123.123 123.123.123.123  1234 eth0:0 123 12  12.4 100 100  12345 12345  1234 1234 1234\n");
      
  list_for_each(orig_pos, debug_orig_list) {
    orig_node = list_entry(orig_pos, struct orig_node, list);
    if( !addrIsMine( orig_node->addr ) ) {
    	
      updateHelperMetricsForOrig( orig_node );

      // -------- print selected router to origin
      if( orig_node->configured_router != NULL ) {

	addr_to_string(orig_node->addr, orig_str, sizeof (orig_str));
	addr_to_string(orig_node->configured_router->addr, hop_str, sizeof (hop_str));
	hmvdaPos = orig_node->configured_device_node->device_node_index;
	summary_node = getMetricNode( orig_node->configured_router );

	output_route( orig_str, hop_str, orig_node, hmvdaPos, summary_node);

	if ( device_list_size > 1 ) {
	  for ( hmvdaPos=0; hmvdaPos < device_list_size ; hmvdaPos++ ) {
	    if(	hmvdaPos != orig_node->configured_device_node->device_node_index && 
		summary_node->hmvda[hmvdaPos].rcvdOrigs >= 1 ) {

	      output_route( "   alt. dev", hop_str, orig_node, hmvdaPos, summary_node);

	    }
	  }
	}
	
	// -------- print alternative router to origin
	list_for_each(summary_pos, &summary_list) {
	  summary_node = list_entry(summary_pos, struct summary_node, list);
	  if( summary_node->orig_node != NULL && 
	      !addrIsMine( summary_node->orig_node->addr ) && 
	      summary_node->orig_node != orig_node->configured_router && 
	      summary_node->rcvdOrigs > 0 ) {
			    
	    addr_to_string(summary_node->orig_node->addr, metric_str, sizeof (metric_str));
	    if( device_list_size >= 1 ) {
	      for ( hmvdaPos=0; hmvdaPos < device_list_size ; hmvdaPos++ ) {
		if (  summary_node->hmvda[hmvdaPos].rcvdOrigs >= 1 ) {

		  output_route( "   alt. NB", metric_str, orig_node, hmvdaPos, summary_node);

		}
	      }
	    }	
	  }
	  if( summary_node->orig_node == NULL ) break;
	}
      }
    }
  }
}


void findBestNeigh( struct orig_node *orig_node, struct best_route *best_route ) 
{
  struct list_head *summary_pos;
  struct summary_node *summary_node;
  //  struct summary_node *best_summary_node;
  char orig_str[ADDR_STR_LEN], /*old_str[ADDR_STR_LEN],*/ metric_str[ADDR_STR_LEN];

  int best_summary_hmvda_best = 0;
  int best_summary_hmvda_best_rcvdOrigs = 0;
  int best_summary_hmvda_best_sumTtl = 0;
  int best_summary_hmvda_best_rcvd1Origs = 0;
  unsigned long best_summary_hmvda_best_maxSeqno = 0;
  
  //  memset( &best_metric, 0, sizeof(struct helper_metric) );

  if ( orig_node == NULL || best_route == NULL || orig_node->this_device_node != NULL) {
    output(1, "findBestNeigh() ERROR or ywith own_orig_node makes no sense !!!!!!!!!!! \n");
    finishNow();    exit( -1 );
  }

  addr_to_string(orig_node->addr, orig_str, sizeof (orig_str));
  
  dbg(3, "findBestNeigh() for orig_node %s \n", orig_str);
  
  updateHelperMetricsForOrig( orig_node );

  /* find best neighbour as router for given orig_node */
  list_for_each(summary_pos, &summary_list) {
    summary_node = list_entry(summary_pos, struct summary_node, list);

    if( summary_node->orig_node == NULL ) break;

    addr_to_string(summary_node->orig_node->addr, metric_str, sizeof (metric_str));
    dbg( 3, "evaluating route via %s to %s: %s, All IFs: rcvdBDNOrigs: %2d, avgTtl: %4.1f, minTtl: %2d, maxTtl: %2d: \n", 
	    metric_str, orig_str, 
	    ( arg_routing_metric == ROUTING_METRIC_ORIGS ? "ROUTING_METRIC_ORIGS" : 
	      ( arg_routing_metric == ROUTING_METRIC_AVG_TTL ? "ROUTING_METRIC_AVG_TTL" : 
		"ROUTING_METRIC_INVALID" ) ),
	    summary_node->rcvdOrigs,
	    avgTtl( summary_node ),
	    summary_node->minTtl,
	    summary_node->maxTtl);
    
    if ( arg_routing_metric == ROUTING_METRIC_AVG_TTL ) {
      
      output(1, "not implemented yet !!!!!!!!!!!!!!!!!!!!!!! \n");
      finishNow();
      
    } else {
      
      //    if ( arg_routing_metric == ROUTING_METRIC_ORIGS ) {
      int hmvdaPos;
      for( hmvdaPos=0; hmvdaPos < device_list_size; hmvdaPos++ ) {

	dbg(3, "          device %d, %s: rcvd1Origs %d, rcvdOrigs %d, sumTtl %d, minTtl %d, maxTtl %d, minSeqno %ld, maxSeqno %ld : ",
	       hmvdaPos, 
	       device_node_array[hmvdaPos].arg_device,
	       summary_node->hmvda[ hmvdaPos ].rcvd1Origs,
	       summary_node->hmvda[ hmvdaPos ].rcvdOrigs,
	       summary_node->hmvda[ hmvdaPos ].sumTtl,
	       summary_node->hmvda[ hmvdaPos ].minTtl,
	       summary_node->hmvda[ hmvdaPos ].maxTtl,
	       summary_node->hmvda[ hmvdaPos ].minSeqno,
	       summary_node->hmvda[ hmvdaPos ].maxSeqno );

	if( ( summary_node->hmvda[ hmvdaPos ].rcvd1Origs > best_summary_hmvda_best_rcvd1Origs ) ||  
	    
	    ( summary_node->hmvda[ hmvdaPos ].rcvd1Origs == best_summary_hmvda_best_rcvd1Origs && 
	      summary_node->hmvda[ hmvdaPos ].rcvdOrigs > best_summary_hmvda_best_rcvdOrigs) ||  
	    
	    ( summary_node->hmvda[ hmvdaPos ].rcvd1Origs == best_summary_hmvda_best_rcvd1Origs && 
	      summary_node->hmvda[ hmvdaPos ].rcvdOrigs ==  best_summary_hmvda_best_rcvdOrigs &&
	      summary_node->hmvda[ hmvdaPos ].sumTtl >  best_summary_hmvda_best_sumTtl ) ||

	    ( summary_node->hmvda[ hmvdaPos ].rcvd1Origs == best_summary_hmvda_best_rcvd1Origs && 
	      summary_node->hmvda[ hmvdaPos ].rcvdOrigs ==  best_summary_hmvda_best_rcvdOrigs &&
	      summary_node->hmvda[ hmvdaPos ].sumTtl ==  best_summary_hmvda_best_sumTtl &&
	      summary_node->hmvda[ hmvdaPos ].maxSeqno >  best_summary_hmvda_best_maxSeqno  )  
	    ) {

	  best_summary_hmvda_best = hmvdaPos;
	  best_summary_hmvda_best_rcvd1Origs = summary_node->hmvda[ hmvdaPos ].rcvd1Origs;
	  best_summary_hmvda_best_rcvdOrigs  = summary_node->hmvda[ hmvdaPos ].rcvdOrigs;
	  best_summary_hmvda_best_sumTtl     = summary_node->hmvda[ hmvdaPos ].sumTtl;
	  best_summary_hmvda_best_maxSeqno   = summary_node->hmvda[ hmvdaPos ].maxSeqno;
	  
	  //	  memcpy( &best_metric, &metric_node->helper_metric, sizeof( struct helper_metric ) );

	  best_route->best_router = summary_node->orig_node;
	  best_route->best_router_device_index = hmvdaPos;

	  dbg(3, "best (so fare) \n");
	  
	} else {
	  dbg(3, "\n");
	}

      }
      // ??????????????????????????????????????????????????????????????????????	
      /*
      if ( metric_node->helper_metric.rcvdOrigs > best_metric.rcvdOrigs ) {
      memcpy( &best_metric, &metric_node->helper_metric, sizeof( struct helper_metric ) );
      best_route->best_router = metric_node;
      dbg(3, "best \n");
      } else {
      dbg(3, "\n");
      }
      */      


    }

  }
  return;
}


int best_device_index ( unsigned short *best_device_nodes )
{
  int best_pos = 0, best_value = 0; 
  int i = 0;
  for( i=0; i<MAX_DEVICE_LIST_SIZE; i++ ) {
    if( best_device_nodes[ i ] > best_value ) {
      best_value = best_device_nodes[ i ];
      best_pos = i;
    }
  }
  return best_pos;
}
      

/* for orig_nodes' pack_nodes find and update best route */

/* TODO: check what happens if best_route does not exist, e.g. only outdated packets */
void updateRoutes( struct orig_node *orig_node, struct best_route *best_route ) {
  char orig_str[ADDR_STR_LEN], old_str[ADDR_STR_LEN], metric_str[ADDR_STR_LEN];

  if ( orig_node == NULL || best_route == NULL ) {
    output(1, "updateRoutes() error !!!!!!!!!!! \n");
    finishNow();    exit( -1 );
  }

  if ( best_route->best_router == NULL ) {
    output(1, "updateRoutes() no best router identified yet ???????????????? !!!!!!!!!!!!!!!!!!!!!!!!! \n");
    return;
  }

  /*
  // find best_router:best_device_node
  int best_device_node = best_device_index( &(best_route->best_device_nodes[0] ) );
  int best_device_node_value = best_route->best_device_nodes[ best_device_node ];
  if( best_device_node_value == 0 ) {
    output(1, "updateRoutes() best_device_node_value == 0  !!!!!!!!!!! \n");
    exit( -1 );
  }
  */
  
  if ( orig_node->this_device_node != NULL ) {
    output(1, "updateRoutes with own_orig_node makes no sense !!!!!!!!!!! \n");
    finishNow();    exit( -1 );
  }
  
  addr_to_string(orig_node->addr, orig_str, sizeof (orig_str));
  
  dbg(3, "updateRoutes() for orig_node %s \n", orig_str);
  
  /* apply best router to orig if changed */
  if ( best_route->best_router != orig_node->configured_router ||
       &(device_node_array[ best_route->best_router_device_index ]) != orig_node->configured_device_node ) {

    if( (*orig_node).configured_router != NULL ) {
      dbg(3, "updateRoutes() (*orig_node).router != NULL \n");
      addr_to_string(orig_node->configured_router->addr, old_str, sizeof (old_str));
      dbg(3, "deletin routing enty to %s via old:%s \n", orig_str, old_str);
      add_del_route(orig_node, orig_node->configured_router, 1, NULL); /* del route */
      orig_node->configured_router = NULL;
    }

    if( best_route->best_router != NULL ) {
      addr_to_string(best_route->best_router->addr, metric_str, sizeof (metric_str));
      dbg(3, "adding routing enty to %s via new: %s \n", orig_str, metric_str);
      add_del_route(orig_node, best_route->best_router, 0, 
		    &(device_node_array[ best_route->best_router_device_index ]) ); /* add route */
      orig_node->configured_router = best_route->best_router;
    }
    
  }
   
}


void updateOrigAPacketAForwARouteList( unsigned int neigh, struct packet_orig *in, 
				       short rcvd_via_device_node_item ) 
{
  struct device_node *rcvd_via_device_node = &( device_node_array[ rcvd_via_device_node_item ] );

  if( (rcvd_via_device_node->mc_addr.sin_addr.s_addr & rcvd_via_device_node->orig_node->addr) != 
      (rcvd_via_device_node->mc_addr.sin_addr.s_addr & neigh) ) {

    if (arg_debug >= 2)  {
      char neigh_str[16], dev_ip_str[16], dev_mc_str[16], dev_bc_str[16];
      addr_to_string(neigh, neigh_str, sizeof (neigh_str));
      addr_to_string(rcvd_via_device_node->orig_node->addr, dev_ip_str, sizeof (dev_ip_str));
      addr_to_string(rcvd_via_device_node->mc_addr.sin_addr.s_addr, dev_mc_str, sizeof (dev_mc_str));
      addr_to_string(rcvd_via_device_node->snd_broad.sin_addr.s_addr, dev_bc_str, sizeof (dev_bc_str));
      dbg(2, "Received srcIp %s via dev %s with devIp %s, mcast %s, bcast %s , ignoring packet !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n",
	  neigh_str, rcvd_via_device_node->arg_device, dev_ip_str, dev_mc_str, dev_bc_str );
    }
    return;
  }

  if ( addrIsMine( neigh ) ) {
    dbg(4, "Ignoring all zero-hop packets directly send by me \n");
    return;
  }

  if( in->ttl > MAX_TTL) {
    output( 1, "updateOrigAPacketAForwARouteList() ERROR: Received packet with ttl > MAX_TTL !!!!!!!!!!!! \n");
    finishNow();    exit( -1 );
  }

  char orig_str[ADDR_STR_LEN], neigh_str[ADDR_STR_LEN];
  struct timeval received;
  //  struct timeval ooptim_originated_rview_tstmp;  /* received - hold_back_time */
  struct orig_node *orig_node, *neigh_node;
  struct best_route best_route;
  struct pack_node *pack_node;
  //  struct device_node *device_node;
  //  struct list_head *device_pos;
  char origAddrIsMine = NO;
  unsigned char treatmentFlags = 0;

  memset( &best_route, 0, sizeof( struct best_route ) );

  if( in==NULL || rcvd_via_device_node == NULL ) {
    output(1, "updateOrigAPacketAForwARouteList() ERROR: relevant parameter were NULL !!!\n");
    finishNow();    exit( -1);
  }

  //  long now_ms = get_time ( &received );
  get_time_internal ( &received );
/*   time2tv( &ooptim_originated_rview_tstmp, in->hold_back_time ); */
/*   timersub( &received, &ooptim_originated_rview_tstmp, &ooptim_originated_rview_tstmp ); */

  if (arg_debug >= 3)  {
    addr_to_string(in->orig, orig_str, sizeof (orig_str));
    addr_to_string(neigh, neigh_str, sizeof (neigh_str));
    dbg(3, "Received packet from neighbor %s "
	   "(originator %s, seqno %d, ttl %d, flags %d, received %ld:%6ld, hold_back_time %d, tripTimePlusConst %ld )"
	   " via IF: %s \n", 
	   neigh_str, orig_str, in->seqno, in->ttl, in->flags, 
	   received.tv_sec, received.tv_usec, in->hold_back_time, -1,
	   rcvd_via_device_node->arg_device ); 
  }
 	
  origAddrIsMine = addrIsMine( in->orig );
 	
  neigh_node = update_neighbour( in,  neigh, rcvd_via_device_node_item, &received );
  orig_node = get_orig_node( in->orig );

  //RULE: 
  if( !origAddrIsMine ) {

    if( in->seqno > orig_node->maxSeqno ) {
      orig_node->maxSeqno = in->seqno;

    } else if( in->seqno + arg_received_seq_range <= orig_node->maxSeqno ) { 

      addr_to_string(in->orig, orig_str, sizeof (orig_str));
      output(1, "updateOrigAPacketAForwARouteList(): Orig: %s restarted?, checking valid orig-packets\n", orig_str);

      if( updateHelperMetricsForOrig( orig_node ) == 0 ) {
	orig_node->maxSeqno = 0; 
	output(1, "updateOrigAPacketAForwARouteList(): Orig: %s restarted!, resetting maxSeqno\n", orig_str);
      }

    }

  }

  treatmentFlags = origTreatmentFunc( orig_node, in, neigh_node,
				      rcvd_via_device_node_item );

  if (arg_debug >= 3) {
    dbg(3, "Rcvd orig from neighb.:   %s \n", (in->orig == neigh?"YES":"NO"));
    dbg(3, "My Originator packet:     %s \n", (origAddrIsMine?"YES":"NO"));
    dbg(3, "Unidirectional flag:      %s \n", (treatmentFlags & ORIG_RCVD_UNI_FLAG )?"YES":"NO");
    dbg(3, "via curr. bidirect neighb %s \n", (treatmentFlags & ORIG_BDNB_FLAG     )?"YES":"NO");
    dbg(3, "known orig&seq:           %s \n", (treatmentFlags & ORIG_OS_FLAG       )?"YES":"NO");
    dbg(3, "known orig&seq&neigh&dev: %s \n", (treatmentFlags & ORIG_OSND_FLAG     )?"YES":"NO");
    dbg(3, "worthConsider:            %s \n", (treatmentFlags & ORIG_CONSIDER_FLAG )?"YES":"NO");
  }
  
/*   if( treatmentFlags & ORIG_OSND_FLAG ){ */
/*     dbg(1, "updateOrigAPacketAForwARouteList(): treatmentFlags & ORIG_OSND_FLAG !!!!!!!???????? \n"); */
/*     finishNow(); */
/*   } */

  /* if one-hop packet from neighbour via bi- and non-bi- directional link 
   * the exceptional case because packet is considered and forwarded anyway */
  if( in->orig == neigh &&  in->ttl >= 1 &&
      !( treatmentFlags & ORIG_RCVD_UNI_FLAG) ) 
    {
      pack_node = createOtherPackNode( ( treatmentFlags ), 
				       orig_node, neigh_node, 
				       rcvd_via_device_node, in, /* &ooptim_originated_rview_tstmp, */ &received );

      if( pack_node == NULL ) { 
	output(0, "pack_node == NULL !!!!!!!!!!!!!!!!!! \n"); 
	finishNow();	exit( -1 );
      }
      
      if ( treatmentFlags & ORIG_BDNB_FLAG ) {
	findBestNeigh( orig_node, &best_route );
	updateRoutes( orig_node, &best_route );
      }

      /* RULE: In case of non-best neigh, unidirectional-flag must be set, 
       * orig must only be re-broadcasted only on rcvd device
       */
      if( !(treatmentFlags & ORIG_BDNB_FLAG) || 
	  best_route.best_router != orig_node || 
	  best_route.best_router_device_index != rcvd_via_device_node_item ) {

	pack_node->flags = pack_node->flags | UNIDIRECTIONAL_FLAG;
	
	dbg(3, "updateOrigAPacketAForwARouteList(): re-broadcasting on receiving device... \n"); 
	addToForwList( pack_node,
			   /*only used to randomize the order, actual fw-schedule is randomized later */
			   (arg_keep_forw_order ? 1 : 
			    (arg_fw_jitter_ms + jitter( arg_fw_jitter_ms ))),
		       rcvd_via_device_node_item );
	
	
      } else {


	//RULE: orig-seqno-touples must only be rebroadcasted once, (NOT a second time if received twice via other device)
	if ( !(treatmentFlags & ORIG_BROADCASTED_FLAG) ){
	  dbg(3, "updateOrigAPacketAForwARouteList(): re-broadcasting on all devices... \n"); 
	  addToAllForwLists( pack_node,
			     /*only used to randomize the order, actual fw-schedule is randomized later */
			     (arg_keep_forw_order ? 1 : 
			      (arg_fw_jitter_ms + jitter( arg_fw_jitter_ms ))) );
	}
      }

    } 
      /* the usual case - treatmentFlags are respected */
  else if (!origAddrIsMine && in->ttl >= 1 &&
	   (  treatmentFlags & ORIG_BDNB_FLAG)  &&  // this might be dropped, then non-bidirectional packets are also maintained
	   !( treatmentFlags & ORIG_RCVD_UNI_FLAG) &&
	   (  treatmentFlags & ORIG_CONSIDER_FLAG ) ) 
    {
      
      pack_node = createOtherPackNode( (treatmentFlags),
				       orig_node, neigh_node,
				       rcvd_via_device_node, in, /* &ooptim_originated_rview_tstmp, */ &received );
      
      if( pack_node == NULL ) { 
	output(0, "pack_node == NULL !!!!!!!!!!!!!!!!!! \n"); 
	finishNow();	exit( -1 );
      }
      

  // ------------ update and re-broadcast policy evaluation  ---------------------------


      if ( (treatmentFlags & ORIG_BDNB_FLAG) && in->ttl >= 1  ) {
	findBestNeigh( orig_node, &best_route );
	updateRoutes( orig_node, &best_route );
	
	//RULE: orig-seqno-touples must only be rebroadcasted once, (NOT a second time if received twice via other device)
	if ( in->ttl >= 2 &&  !(treatmentFlags & ORIG_BROADCASTED_FLAG) ) {

	  if( arg_forward_policy == FORWARD_POLICY_BEST_NB ) {
	    if( best_route.best_router == neigh_node )  {
	      dbg(3, "updateOrigAPacketAForwARouteList(): FORWARD_POLICY_BEST_NB, re-broadcasting on all devices... \n"); 
	      addToAllForwLists( pack_node , 
				 /*only used to randomize the order, actual fw-schedule is randomized later */
				 (arg_keep_forw_order ? 1 : (arg_fw_jitter_ms + jitter( arg_fw_jitter_ms ))) );
	    }
	    
	  } else { // FORWARD_POLICY_STRICTLY_FIRST_SEEN, TBD: can be removed, can cause loops
	    if( !( treatmentFlags & ORIG_OS_FLAG) ) {
	      dbg(3, "updateOrigAPacketAForwARouteList(): FORWARD_POLICY_STRICTLY_FIRST_SEEN, re-broadcasting on all devices... \n"); 
	      addToAllForwLists( pack_node ,
				 /*only used to randomize the order, actual fw-schedule is randomized later */
				 (arg_keep_forw_order ? 1 : (arg_fw_jitter_ms + jitter( arg_fw_jitter_ms ))) );
	    } 
	  }

	}

      }

    } 
  else
    {
      dbg(4, "Ignoring packet...\n" );
    } 
}    
  




void purgePacketsAOrigsARoutes(){
  char orig_str[ADDR_STR_LEN], old_str[ADDR_STR_LEN];
  struct list_head *orig_pos;
  struct orig_node *orig_node; 
  char again=NO;
  
  do {
    again=NO;	
    list_for_each(orig_pos, &orig_list) {
      orig_node = list_entry(orig_pos, struct orig_node, list);
      addr_to_string(orig_node->addr, orig_str, sizeof (orig_str));
      dbg(4, "purgePacketsAOrigsARoutes(): considering orig_node->addr: %s \n", orig_str);

      purgePackNodes( orig_node );
    
      if( orig_node->this_device_node == NULL ) {
    	
	// check if orig_node is an outdated neighbor
	int dli = 0;
	char outdated = YES;
    	for( dli = 0; dli < device_list_size; dli++ ) {
	  get_time_internal( &now_tv );
	  time2tv( &then_tv, ( arg_purge_to_ms ) );
	  timeradd( &orig_node->lastSeenAsNb[dli], &then_tv, &then_tv);
	  if ( timercmp( &then_tv, &now_tv, > ) ) 
	    outdated = NO;
	}

	// remove stale routes to orig
    	if ( list_empty( &orig_node->pack_list ) ){
	  if( (*orig_node).configured_router != NULL ) {
	    addr_to_string(orig_node->addr, orig_str, sizeof (orig_str));
	    addr_to_string(orig_node->configured_router->addr, old_str, sizeof (old_str));
	    dbg(3, "deletin routing enty to %s via old:%s  \n",  orig_str, old_str);
	    add_del_route(orig_node, orig_node->configured_router, 1, NULL); /* del route */
	    orig_node->configured_router = NULL;
	  }
	}

	// remove orig_node form orig_list only if also outdated neighbour
    	if ( list_empty( &orig_node->pack_list ) &&  outdated ){
	  dbg(4, "purgePacketsAOrigsARoutes(): orig_node->pack_list empty and orig_node->lastSeenAsNb outdated, removing orig_node \n");
	  list_del( orig_pos );
	  free_memory( orig_node );
	  again=YES;
	  /* after list_del we cannot goon with the current list_for_each loop so start again from the beginning */
	  break;
    	}
      }
    }
  } while (again == YES);
  
  showRoutes( &orig_list );
  
}


int batman(void)
{
  int res;
  int event;
  int cycle=0;
  struct packet_orig in_stream[MAX_ORIG_BUNDLE + 1];
  struct packet_orig *orig_packet;
  struct timeval rcv_to;
  unsigned int neigh = 0;
  int rcvd_via_device_node_item = -1;
  struct pack_node *own_pack_node;
  struct device_node  *device_datap=NULL;
  int i = 0, more_data ;
  
  //  debug_event_list();


  int dnap=0;
  for( dnap=0; dnap < device_list_size; dnap++ ) {
    add_event_to( EVENT_ORIG_INTERVAL, &device_node_array[dnap], arg_orig_interval_ms + jitter( arg_orig_jitter_ms ) );
  }

  /*
    list_for_each( device_pos, &device_list){
    device_node = list_entry( device_pos, struct device_node, list );
    add_event_to( EVENT_ORIG_INTERVAL, device_node, arg_orig_interval_ms + jitter( arg_orig_jitter_ms ) );
    }
  */
  	
  add_event_to( EVENT_PURGE_INTERVAL, NULL, arg_purge_interval_ms );
  debug_event_list();

  while (!is_aborted()  /*&& cycle < 20*/ )
    {
      cycle++;
      dbg(4, "batman(): cycle: %d \n", cycle);
      get_next_to( &rcv_to );
      dbg(4, "next to at: %ld: %ld ... waiting for packet \n",rcv_to.tv_sec, rcv_to.tv_usec );
      //      int wfp_call = 0;
      do {
	//	wfp_call++;
      	i = 0;
      	memset( (unsigned char *)&in_stream, 0, sizeof (in_stream) );

	res = wait_for_packet((unsigned char *)&in_stream, sizeof (in_stream), &neigh, 
			      &rcvd_via_device_node_item, &rcv_to, &more_data );
	
	while( res > 0 && rcvd_via_device_node_item != -1 && neigh != 0 ) {
	  if( res % sizeof( struct packet_orig ) != 0 ) {
	    output(1, "packet received! Size: %d , Not matching !!! ... \n", res);
	    finishNow();	    exit(-1);
	  } 

	  dbg(3, "processing bundle: sub packet index %d . \n", i);
    	  orig_packet = &in_stream[i++];
	  updateOrigAPacketAForwARouteList( neigh, orig_packet, rcvd_via_device_node_item );
	  res = res - sizeof( struct packet_orig );
	}

	timerclear( &rcv_to );
	if( res != 0 ) {
	  output(1, " batman(): wait_for_packet should not leave res != 0 after processing !!!!!!\n");
	  finishNow();	  exit (-1);
	}
      } while( more_data );

      event = get_pend_event( &device_datap );
      dbg(5, "event %d ... \n", event);
      if( event > 0 ){

	if( event == EVENT_ORIG_INTERVAL ) {
	  if( device_datap == NULL ) {
	    output(1, "event %d, delivered without device_datap !!!!!!!!!!! \n", event);
	    finishNow();	    exit( -1 );
	  }
	  dbg(4, "event %d, preparing originator emission via IF device %s... \n",
		 event, device_datap->arg_device );
	  
	  own_pack_node = generateOwnPackNode( device_datap );

	  addToAllForwLists( own_pack_node, 
			     (arg_keep_forw_order? 1:(arg_fw_jitter_ms + jitter( arg_fw_jitter_ms ))) );

	  add_event_to( EVENT_ORIG_INTERVAL, device_datap,
			arg_orig_interval_ms + jitter( arg_orig_jitter_ms )  );
		
	} else if ( event == EVENT_PURGE_INTERVAL ) {
	  dbg(3, "event %d, updating and purging orig_list, pack_list, routes ... \n", event);
	  purgePacketsAOrigsARoutes();
	  add_event_to(	EVENT_PURGE_INTERVAL, NULL, arg_purge_interval_ms );
		
	} else if( event == EVENT_FW_JITTER ) {
	  if( device_datap == NULL ) {
	    output(1, "event %d, delivered without device_datap !!!!!!!!!!! \n", event);
	    finishNow();	    exit( -1 );
	  }
	  dbg(4, "event %d, consuming up to %d pending originator packets"
		 " generating and sending originator packet via ID device %s ... \n", 
		 event,  arg_max_orig_bundle, device_datap->arg_device );
	  broadcastFwList( device_datap );
	}
      }
    }

  return 0;
}

void delAllRoutes( void ) {
  struct list_head *orig_pos;
  struct orig_node *orig_node; 

  output(1, "delAllRoutes(): Deleting all BATMAN routes\n");
  
  list_for_each(orig_pos, &orig_list) {
    orig_node = list_entry(orig_pos, struct orig_node, list);
    
    if (orig_node->configured_router != NULL)
      add_del_route(orig_node, orig_node->configured_router, 1, NULL);
    orig_node->configured_router = NULL;
      
  }
  return;
}



void closeAllSockets( void ) {
  int dnap=0;
  for( dnap=0; dnap < device_list_size; dnap++ ) {
    close( device_node_array[dnap].snd_sock );
  }
  return;
}  

int main(int ac, char **av)
{
  int res;
  //       	struct ifreq rcv_int_req;
  //        struct sockaddr_in rcv_addr, rcv_null;
  //  	struct list_head *device_pos;
  //  	struct device_node *device_node=NULL;
  memset( &device_node_array[0], 0, sizeof( device_node_array ) );

  printf("B.A.T.M.A.N-III %s\n", VERSION);

  apply_init_args( ac, av );

  /********************************************/



  /********************************************/

  stop = 0;
  signal(SIGINT, handler);


  gettimeofday(&start_time_tv, NULL);
  srand(getpid());

  forward_old = get_forwarding();
  set_forwarding(1);

  res = batman();


  delAllRoutes();

  set_forwarding(forward_old);

  closeAllSockets();



  return res;
}
