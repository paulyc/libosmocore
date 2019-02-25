/*! \file ip_port.c
 * Common implementation to store an IP address and port.
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

#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocom/core/ip_port.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/byteswap.h>

/*! \addtogroup ip_port
 *
 * Common operations to store IP address as a char string along with a uint16_t port number.
 *
 * Convert IP address string to/from in_addr and in6_addr, with bounds checking and basic housekeeping.
 *
 * The initial purpose is to store and translate IP address info between GSM CC and MGCP protocols -- GSM mostly using
 * 32-bit IPv4 addresses, and MGCP forwarding addresses as ASCII character strings.
 *
 * (At the time of writing, there are no immediate IPv6 users that come to mind, but it seemed appropriate to
 * accommodate both address families from the start.)
 *
 * @{
 * \file ip_port.c
 */


/*! Return true if all elements of the osmo_ip_port instance are set.
 * \param[in] ip_port  The instance to examine.
 * \return True iff ip is nonempty, port is not 0 and af is set to either AF_INET or AF_INET6.
 */
bool osmo_ip_port_is_set(const struct osmo_ip_port *ip_port)
{
	return *ip_port->ip
		&& ip_port->port
		&& (ip_port->af == AF_INET || ip_port->af == AF_INET6);
}

/*! Distinguish between valid IPv4 and IPv6 strings.
 * This does not verify whether the string is a valid IP address; it assumes that the input is a valid IP address, and
 * on that premise returns whether it is an IPv4 or IPv6 string, by looking for '.' and ':' characters.  It is safe to
 * feed invalid address strings, but the return value is only guaranteed to be meaningful if the input was valid.
 * \param[in] ip  Valid IP address string.
 * \return AF_INET or AF_INET6, or AF_UNSPEC if neither '.' nor ':' are found in the string.
 */
int osmo_ip_str_type(const char *ip)
{
	if (!ip)
		return AF_UNSPEC;
	/* Could also be IPv4-mapped IPv6 format with both colons and dots: x:x:x:x:x:x:d.d.d.d */
	if (strchr(ip, ':'))
		return AF_INET6;
	if (strchr(ip, '.'))
		return AF_INET;
	return AF_UNSPEC;
}

/*! Safely copy the given ip string to ip_port, classify to AF_INET or AF_INET6, and set the port.
 * Data will be written to ip_port even if an error is returned.
 * \param[out] ip_port  The instance to copy to.
 * \param[in] ip  Valid IP address string.
 * \param[in] port  Port number.
 * \return 0 on success, negative if copying the address string failed (e.g. too long), if the address family could
 *         not be detected (i.e. if osmo_ip_str_type() returned AF_UNSPEC), or if ip_port is NULL.
 */
int osmo_ip_port_from_str(struct osmo_ip_port *ip_port, const char *ip, uint16_t port)
{
	int rc;
	if (!ip_port)
		return -ENOSPC;
	if (!ip)
		ip = "";
	*ip_port = (struct osmo_ip_port){
		.af = osmo_ip_str_type(ip),
		.port = port,
	};
	rc = osmo_strlcpy(ip_port->ip, ip, sizeof(ip_port->ip));
	if (rc <= 0)
		return -EIO;
	if (rc >= sizeof(ip_port->ip))
		return -ENOSPC;
	if (ip_port->af != AF_UNSPEC)
		return -EINVAL;
	return 0;
}

/*! Convert IPv4 address to osmo_ip_port, and set port.
 * \param[out] ip_port  The instance to copy to.
 * \param[in] addr  IPv4 address data.
 * \param[in] port  Port number.
 * \return 0 on success, negative on error.
 */
int osmo_ip_port_from_in_addr(struct osmo_ip_port *ip_port, const struct in_addr *addr, uint16_t port)
{
	if (!ip_port)
		return -ENOSPC;
	*ip_port = (struct osmo_ip_port){
		.af = AF_INET,
		.port = port,
	};
	if (!inet_ntop(AF_INET, addr, ip_port->ip, sizeof(ip_port->ip)))
		return -ENOSPC;
	return 0;
}

/*! Convert IPv6 address to osmo_ip_port, and set port.
 * \param[out] ip_port  The instance to copy to.
 * \param[in] addr  IPv6 address data.
 * \param[in] port  Port number.
 * \return 0 on success, negative on error.
 */
int osmo_ip_port_from_in6_addr(struct osmo_ip_port *ip_port, const struct in6_addr *addr, uint16_t port)
{
	if (!ip_port)
		return -ENOSPC;
	*ip_port = (struct osmo_ip_port){
		.af = AF_INET6,
		.port = port,
	};
	if (!inet_ntop(AF_INET6, addr, ip_port->ip, sizeof(ip_port->ip)))
		return -ENOSPC;
	return 0;
}

/*! Convert IPv4 address from 32bit host-byte-order to osmo_ip_port, and set port.
 * \param[out] ip_port  The instance to copy to.
 * \param[in] addr  32bit IPv4 address data.
 * \param[in] port  Port number.
 * \return 0 on success, negative on error.
 */
int osmo_ip_port_from_32(struct osmo_ip_port *ip_port, uint32_t ip, uint16_t port)
{
	struct in_addr addr;
	if (!ip_port)
		return -ENOSPC;
	addr.s_addr = ip;
	return osmo_ip_port_from_in_addr(ip_port, &addr, port);
}

/*! Convert IPv4 address from 32bit network-byte-order to osmo_ip_port, and set port.
 * \param[out] ip_port  The instance to copy to.
 * \param[in] addr  32bit IPv4 address data.
 * \param[in] port  Port number.
 * \return 0 on success, negative on error.
 */
int osmo_ip_port_from_32n(struct osmo_ip_port *ip_port, uint32_t ip, uint16_t port)
{
	if (!ip_port)
		return -ENOSPC;
	return osmo_ip_port_from_32(ip_port, osmo_ntohl(ip), port);
}

/*! Convert IPv4 address and port to osmo_ip_port.
 * \param[out] ip_port  The instance to copy to.
 * \param[in] src  IPv4 address and port data.
 * \return 0 on success, negative on error.
 */
int osmo_ip_port_from_sockaddr_in(struct osmo_ip_port *ip_port, const struct sockaddr_in *src)
{
	if (!ip_port)
		return -ENOSPC;
	if (!src)
		return -EINVAL;
	return osmo_ip_port_from_in_addr(ip_port, &src->sin_addr, src->sin_port);
}

/*! Convert IPv6 address and port to osmo_ip_port.
 * \param[out] ip_port  The instance to copy to.
 * \param[in] src  IPv6 address and port data.
 * \return 0 on success, negative on error.
 */
int osmo_ip_port_from_sockaddr_in6(struct osmo_ip_port *ip_port, const struct sockaddr_in6 *src)
{
	if (!ip_port)
		return -ENOSPC;
	if (!src)
		return -EINVAL;
	return osmo_ip_port_from_in6_addr(ip_port, &src->sin6_addr, src->sin6_port);
}

/*! Convert IPv4 or IPv6 address and port to osmo_ip_port.
 * \param[out] ip_port  The instance to copy to.
 * \param[in] src  IPv4 or IPv6 address and port data.
 * \return 0 on success, negative if src does not indicate AF_INET nor AF_INET6 (or if the conversion fails, which
 *         should not be possible in practice).
 */
int osmo_ip_port_from_sockaddr(struct osmo_ip_port *ip_port, const struct sockaddr_storage *src)
{
	const struct sockaddr_in *sin = (void*)src;
	const struct sockaddr_in6 *sin6 = (void*)src;
	if (!ip_port)
		return -ENOSPC;
	if (!src)
		return -EINVAL;
	if (sin->sin_family == AF_INET)
		return osmo_ip_port_from_sockaddr_in(ip_port, sin);
	if (sin6->sin6_family == AF_INET6)
		return osmo_ip_port_from_sockaddr_in6(ip_port, sin6);
	return -EINVAL;
}

/*! Convert osmo_ip_port address string to IPv4 address data.
 * \param[in] ip_port  The instance to convert the IP of.
 * \param[out] dst  IPv4 address data to write to.
 * \return 0 on success, negative on error (e.g. invalid IPv4 address string).
 */
int osmo_ip_port_to_in_addr(const struct osmo_ip_port *ip_port, struct in_addr *dst)
{
	int rc;
	if (!ip_port)
		return -EINVAL;
	if (!dst)
		return -ENOSPC;
	if (ip_port->af != AF_INET)
		return -EAFNOSUPPORT;
	rc = inet_pton(AF_INET, ip_port->ip, dst);
	if (rc != 1)
		return -EINVAL;
	return 0;
}

/*! Convert osmo_ip_port address string to IPv6 address data.
 * \param[in] ip_port  The instance to convert the IP of.
 * \param[out] dst  IPv6 address data to write to.
 * \return 0 on success, negative on error (e.g. invalid IPv6 address string).
 */
int osmo_ip_port_to_in6_addr(const struct osmo_ip_port *ip_port, struct in6_addr *dst)
{
	int rc;
	if (!ip_port)
		return -EINVAL;
	if (!dst)
		return -ENOSPC;
	if (ip_port->af != AF_INET6)
		return -EINVAL;
	rc = inet_pton(AF_INET6, ip_port->ip, dst);
	if (rc != 1)
		return -EINVAL;
	return 0;
}

/*! Convert osmo_ip_port address string to IPv4 address data in host-byte-order.
 * \param[in] ip_port  The instance to convert the IP of.
 * \param[out] dst  IPv4 address data in 32bit host-byte-order format to write to.
 * \return 0 on success, negative on error (e.g. invalid IPv4 address string).
 */
int osmo_ip_port_to_32(const struct osmo_ip_port *ip_port, uint32_t *ip)
{
	int rc;
	struct in_addr addr;
	if (!ip_port)
		return -EINVAL;
	if (!ip)
		return -ENOSPC;
	rc = osmo_ip_port_to_in_addr(ip_port, &addr);
	if (rc)
		return rc;
	*ip = addr.s_addr;
	return 0;
}

/*! Convert osmo_ip_port address string to IPv4 address data in network-byte-order.
 * \param[in] ip_port  The instance to convert the IP of.
 * \param[out] dst  IPv4 address data in 32bit network-byte-order format to write to.
 * \return 0 on success, negative on error (e.g. invalid IPv4 address string).
 */
int osmo_ip_port_to_32n(const struct osmo_ip_port *ip_port, uint32_t *ip)
{
	int rc;
	uint32_t ip_h;
	if (!ip_port)
		return -EINVAL;
	if (!ip)
		return -ENOSPC;
	rc = osmo_ip_port_to_32(ip_port, &ip_h);
	if (rc)
		return rc;
	*ip = osmo_htonl(ip_h);
	return 0;
}

/*! Convert osmo_ip_port address string and port to IPv4 address and port data.
 * \param[in] ip_port  The instance to convert the IP and port of.
 * \param[out] dst  IPv4 address and port data to write to.
 * \return 0 on success, negative on error (e.g. invalid IPv4 address string).
 */
int osmo_ip_port_to_sockaddr_in(const struct osmo_ip_port *ip_port, struct sockaddr_in *dst)
{
	if (!ip_port)
		return -EINVAL;
	if (!dst)
		return -ENOSPC;
	if (ip_port->af != AF_INET)
		return -EINVAL;
	*dst = (struct sockaddr_in){
		.sin_family = ip_port->af,
		.sin_port = ip_port->port,
	};
	return osmo_ip_port_to_in_addr(ip_port, &dst->sin_addr);
}

/*! Convert osmo_ip_port address string and port to IPv6 address and port data.
 * \param[in] ip_port  The instance to convert the IP and port of.
 * \param[out] dst  IPv6 address and port data to write to.
 * \return 0 on success, negative on error (e.g. invalid IPv6 address string).
 */
int osmo_ip_port_to_sockaddr_in6(const struct osmo_ip_port *ip_port, struct sockaddr_in6 *dst)
{
	if (!ip_port)
		return -EINVAL;
	if (!dst)
		return -ENOSPC;
	if (ip_port->af != AF_INET6)
		return -EINVAL;
	*dst = (struct sockaddr_in6){
		.sin6_family = ip_port->af,
		.sin6_port = ip_port->port,
	};
	return osmo_ip_port_to_in6_addr(ip_port, &dst->sin6_addr);
}

/*! Convert osmo_ip_port address string and port to IPv4 or IPv6 address and port data.
 * Depending on ip_port->af, dst will be handled as struct sockaddr_in or struct sockaddr_in6.
 * \param[in] ip_port  The instance to convert the IP and port of.
 * \param[out] dst  IPv4/IPv6 address and port data to write to.
 * \return 0 on success, negative on error (e.g. invalid IP address string for the family indicated by ip_port->af).
 */
int osmo_ip_port_to_sockaddr(const struct osmo_ip_port *ip_port, struct sockaddr_storage *dst)
{
	if (!ip_port)
		return -EINVAL;
	if (!dst)
		return -ENOSPC;
	switch (ip_port->af) {
	case AF_INET:
		return osmo_ip_port_to_sockaddr_in(ip_port, (void*)dst);
	case AF_INET6:
		return osmo_ip_port_to_sockaddr_in6(ip_port, (void*)dst);
	default:
		return -EINVAL;
	}
}

/*! @} */
