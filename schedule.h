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


void schedule_own_packet( struct batman_if *batman_if );

void schedule_forward_packet( struct bat_packet *in, uint8_t unidirectional, uint8_t directlink, uint8_t cloned, struct ext_packet *gw_array, int16_t gw_array_len, struct ext_packet *hna_array, int16_t hna_array_len, struct batman_if *if_outgoing, uint32_t curr_time, uint32_t neigh );

void send_outstanding_packets();
