/*! \file ip_port.h
 * Common API to store an IP address and port.
 */
/*
 * (C) 2019 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: neels@hofmeyr.de
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

/*! \defgroup ip_port  IP address/port utilities.
 * @{
 * \file ip_port.h
 */

int osmo_ip_str_type(const char *ip);

struct osmo_ip_port {
	/*! AF_INET for IPv4 address, or AF_INET6 for IPv6 address. */
	int af;
	/*! NUL terminated string of the IPv4 or IPv6 address. */
	char ip[INET6_ADDRSTRLEN];
	/*! Port number */
	uint16_t port;
};

/*! Format string to print an osmo_ip_port.
 *
 * For example:
 *
 *     struct osmo_ip_port *my_ip_port = ...;
 *     printf("got " OSMO_IP_PORT_FMT, OSMO_IP_PORT_ARGS(my_ip_port));
 */
#define OSMO_IP_PORT_FMT "%s:%u"
#define OSMO_IP_PORT_ARGS(R) ((R)->ip ? : ""), (R)->port

bool osmo_ip_port_is_set(const struct osmo_ip_port *ip_port);

int osmo_ip_port_from_str(struct osmo_ip_port *ip_port, const char *ip, uint16_t port);

int osmo_ip_port_from_in_addr(struct osmo_ip_port *ip_port, const struct in_addr *addr, uint16_t port);
int osmo_ip_port_from_in6_addr(struct osmo_ip_port *ip_port, const struct in6_addr *addr, uint16_t port);
int osmo_ip_port_from_32(struct osmo_ip_port *ip_port, uint32_t ip, uint16_t port);
int osmo_ip_port_from_32n(struct osmo_ip_port *ip_port, uint32_t ip, uint16_t port);
int osmo_ip_port_from_sockaddr_in(struct osmo_ip_port *ip_port, const struct sockaddr_in *src);
int osmo_ip_port_from_sockaddr_in6(struct osmo_ip_port *ip_port, const struct sockaddr_in6 *src);
int osmo_ip_port_from_sockaddr(struct osmo_ip_port *ip_port, const struct sockaddr_storage *dst);

int osmo_ip_port_to_in_addr(const struct osmo_ip_port *ip_port, struct in_addr *dst);
int osmo_ip_port_to_in6_addr(const struct osmo_ip_port *ip_port, struct in6_addr *dst);
int osmo_ip_port_to_32(const struct osmo_ip_port *ip_port, uint32_t *ip);
int osmo_ip_port_to_32n(const struct osmo_ip_port *ip_port, uint32_t *ip);
int osmo_ip_port_to_sockaddr_in(const struct osmo_ip_port *ip_port, struct sockaddr_in *dst);
int osmo_ip_port_to_sockaddr_in6(const struct osmo_ip_port *ip_port, struct sockaddr_in6 *dst);
int osmo_ip_port_to_sockaddr(const struct osmo_ip_port *ip_port, struct sockaddr_storage *dst);

/*! @} */
