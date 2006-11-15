 Copyright (C) 2006 B.A.T.M.A.N. contributors:
 This program is free software; you can redistribute it and/or
 modify it under the terms of version 2 of the GNU General Public
 License as published by the Free Software Foundation.
 
 This program is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 02110-1301, USA

 We would like to thank all people that donated their time and skills
 to this software!

Thomas Lopatic
Marek Lindner
Axel Neumann
Corinna 'Elektra' Aichele
Stefan Sperling
Felix Fietkau
Ludger Schmudde


*************************************************************************
The experimental version of batman. source files renamed to bmex.c.h
to avoid confusion.


Although the core routing concept is similar to the main batman
protocol this branch incorporates a number of experimental features
and a complete rewrite of the data structure maintained by each batman
node to keep track of received originator messages and identified
routes.

Also it offers a few additional information to a node (and its users) when trying to
find optimal metrics (and hazards) for selecting the best next hop towards the final
destination of a packet.

The current version aims to supports (this is very experimental or work in progress):

- Multi interface support
- Routing table showing selected and alternative routes and characteristics to each destination
- Accessible characteristics for each potential route include:
  - Next-hop ip
  - Timeout for bidirectional neighbor status of next hop
  - Interface
  - Number of total originator messages from destination received via this neighbor
  - Number of originator messages form destination received via this neighbor first
  - Average, minimm, and maximum TTL (Hops) of originator message
  - Minimum and maximum sequence number of received originator messages
  - Average, minimum, and maximum one-way trip time indicator which can be used to
    identify the fastest of possibly multiple routes to a destination.
- Originator packet bundling to reduce MAC overhead when (re-)broadcasting own and other
  nodes originator messages
- ...

*************************************************************************
some comments about the output:

showRoutes()  dev:ath0 ip:10.0.1.103 ttl:100 seq:167  dev:eth0.0 ip:10.0.5.103 ttl:1 seq:168 rmetric:1, cpolicy:3, fpolicy:2
to_orig         via_NB_orig      BDNB device all/1.  av/mi/ma-Ttl  mi/ma-SeqNo  av/mi/ma/la-ttpc
      10.0.1.76      10.0.5.102  2915 eth0.0  10  7  98.0  98  98    174   183     1.3    1    2    1
        alt. NB       10.0.1.76  2189   ath0   3  3  99.0  99  99    175   182     0.0    0    0    0
     10.0.1.102      10.0.5.102  2911 eth0.0  10  9  99.0  99  99    164   173     0.3    0    1    0
        alt. NB       10.0.1.76  2185   ath0   3  1  98.0  98  98    164   168     2.0    2    2    2
     10.0.5.102      10.0.5.102  2908 eth0.0  10 10   0.0   0   0    164   173     0.3    0    1    0





This batman (bmex) node has been started with two interface, namely
ath0 (ip 10.0.1.103) and eth0.0 (ip 10.0.5.103).  It is broadcasting
originator messages for 10.0.1.103 with a initial ttl of 100. It the
moment of the screenshot 167 Originator messages have been scheduled
for broadcasting on ath0 and eth0. Additionally this node is
broadcasting originator messages for 10.0.5.103 but only with a ttl of
one. This means the originator-device 10.0.5.103 is only viewable for
its direct neighbors. For this originator 168 originator messages have
been scheduled so fare. The node has been started with routing-metric
1, consider-policy 3 (specifies which originator messages should be
doroped or considered for further processing) and
forwarding/re-broadcasting-policy 2 (1-3-2 is currently the default
case but others could be implemented). 

The 1. line is followed by a list of potential routing entries to all
known nodes in the mesh. The first column shows the known destination
nodes. They are indicated by their ip address. If multiple routes to a
destination are known they are listed after the cuurent selected route
as alternative neighbor (alt. NB).

The 2. column shows the next-hop neighbor of the path to the
destination.

The 3. column shows the current timeout for the bidirectional link
status for this neighbor. -1 is shown if it is timed out.

The 4. column (BDNB) indicates the device in charge to reach that
neighbor.

The 5. column (all/1) shows the number of received
originator-sequence-number touples falling in the range of the 10
highest aware sequence numbers and the number of sequence numbers
first seen via this neighbor. As an example destination 10.0.1.76 is
reachable via two different neighbors (10.0.5.102 via eth0.0 and
directly via ath0). In this case the wireless link ath0 is less
reliable that the wired link (eth0.0) but it has one hop less than via
the wired link. Here all the last 10 sequencenumbers have been
received via eth0.0 but only 7 of them have been received via eth0.0
first. 3 of them have been received before and directly via link ath0.

  [ Note that the considered originator messages are not selected by a
  time frame but by the fact whether they belong to the highest 10
  sequence numbers aware of. Thus if a node successively received
  seqNo 1-20 (with 20 as the highes seqNo received so fare) it would
  show 10. If it received [1, 5, 11, 14, 20] it would show 3. If it
  successively received [1-14] and missed everything beyond it would
  also show 10. If no more originator messages are received after some
  time a garbage collector will come along and purge that destination
  from the list. This way route optimization can only be triggered by
  the reception of a new originator-sequencenumber touple and is never
  triggered by a timeout. I belive that unsynchronized timeouts on
  different nodes can be a reason for routing loops. ]

The 6. column (av/mi/ma-Ttl) shows the average, minimum, and maximum
ttl received with the last originator messages.

The 7. column (mi/ma-SeqNo) shows the minimum and maximum received
sequence numbers within the range of the last received originator
messages.

The 8. column (av/mi/ma/la-ttpc) aims to indicate the average,
minimum, maximum, and latest one-way trip time (plus an unknown
constant C per destination). Because the unknown constant C is equal
for all paths and originator messages received from a particular
destination, the indicated values can be used to estimate the fastest
path to a destination. 

  [ The acquirement of this value is a bit tricky. It is based on the
  idea that each node (re-)broadcasting its own and other node's
  originator messages keeps track of the INTENTIONAL delay (jitter)
  between reception and re-broadcasting of the message. Each node is
  doing so by adding this delay to a field (calles hold-bach-time) in
  the message itself. This way, every node receiving the same
  originator message from a distant node via two or more neighbors can
  combine the message's reception timestamp and hold-back-time field
  and use this information to evaluate which of the potential path to
  the destination suffers the least UNINTENTIONAL (processing, MAC, or
  PHY) delay. ]
