/* redsocks - transparent TCP-to-proxy redirector
 * Copyright (C) 2007-2018 Leonid Evdokimov <leon@darkk.net.ru>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "log.h"
#include "base.h"
#include "utils.h"
#include "redsocks.h" // for redsocks_close
#include "libc-compat.h"
#include "alan_debug.h"

#define SERVER_NAME_LEN 256
#define TLS_HEADER_LEN 5
#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

static int parse_tls_header(const uint8_t*, size_t, char **);
static int parse_extensions(const uint8_t*, size_t, char **);
static int parse_server_name_extension(const uint8_t*, size_t, char **);

char *get_TLS_SNI(unsigned char *bytes, int* len)
{
    unsigned char *curr;
    unsigned char sidlen = bytes[43];
    curr = bytes + 1 + 43 + sidlen;
    unsigned short cslen = ntohs(*(unsigned short*)curr);
    curr += 2 + cslen;
    unsigned char cmplen = *curr;
    curr += 1 + cmplen;
    unsigned char *maxchar = curr + 2 + ntohs(*(unsigned short*)curr);
    curr += 2;
    unsigned short ext_type = 1;
    unsigned short ext_len;
    while(curr < maxchar && ext_type != 0)
    {
        ext_type = ntohs(*(unsigned short*)curr);
        curr += 2;
        ext_len = ntohs(*(unsigned short*)curr);
        curr += 2;
        if(ext_type == 0)
        {
            curr += 3;
            unsigned short namelen = ntohs(*(unsigned short*)curr);
            curr += 2;
            return (char*)curr;
        }
        else curr += ext_len;
    }
    if (curr != maxchar) return NULL;
    return NULL; //SNI was not present
}


const unsigned char good_data_2[] = {
    // TLS record
    0x16, // Content Type: Handshake
    0x03, 0x01, // Version: TLS 1.0
    0x00, 0x6c, // Length (use for bounds checking)
        // Handshake
        0x01, // Handshake Type: Client Hello
        0x00, 0x00, 0x68, // Length (use for bounds checking)
        0x03, 0x03, // Version: TLS 1.2
        // Random (32 bytes fixed length)
        0xb6, 0xb2, 0x6a, 0xfb, 0x55, 0x5e, 0x03, 0xd5,
        0x65, 0xa3, 0x6a, 0xf0, 0x5e, 0xa5, 0x43, 0x02,
        0x93, 0xb9, 0x59, 0xa7, 0x54, 0xc3, 0xdd, 0x78,
        0x57, 0x58, 0x34, 0xc5, 0x82, 0xfd, 0x53, 0xd1,
        0x00, // Session ID Length (skip past this much)
        0x00, 0x04, // Cipher Suites Length (skip past this much)
            0x00, 0x01, // NULL-MD5
            0x00, 0xff, // RENEGOTIATION INFO SCSV
        0x01, // Compression Methods Length (skip past this much)
            0x00, // NULL
        0x00, 0x3b, // Extensions Length (use for bounds checking)
            // Extension
            0x00, 0x00, // Extension Type: Server Name (check extension type)
            0x00, 0x0e, // Length (use for bounds checking)
            0x00, 0x0c, // Server Name Indication Length
                0x00, // Server Name Type: host_name (check server name type)
                0x00, 0x09, // Length (length of your data)
                // "localhost" (data your after)
                0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74,
            // Extension
            0x00, 0x0d, // Extension Type: Signature Algorithms (check extension type)
            0x00, 0x20, // Length (skip past since this is the wrong extension)
            // Data
            0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03,
            0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01,
            0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02,
            0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
            // Extension
            0x00, 0x0f, // Extension Type: Heart Beat (check extension type)
            0x00, 0x01, // Length (skip past since this is the wrong extension)
            0x01 // Mode: Peer allows to send requests
};

/* Parse a TLS packet for the Server Name Indication extension in the client
 * hello handshake, returning the first servername found (pointer to static
 * array)
 *
 * Returns:
 *  >=0  - length of the hostname and updates *hostname
 *         caller is responsible for freeing *hostname
 *  -1   - Incomplete request
 *  -2   - No Host header included in this request
 *  -3   - Invalid hostname pointer
 *  -4   - malloc failure
 *  < -4 - Invalid TLS client hello
 */
static int
parse_tls_header(const uint8_t *data, size_t data_len, char **hostname) {
    uint8_t tls_content_type;
    uint8_t tls_version_major;
    uint8_t tls_version_minor;
    size_t pos = TLS_HEADER_LEN;
    size_t len;

    if (hostname == NULL)
        return -3;

    /* Check that our TCP payload is at least large enough for a TLS header */
    if (data_len < TLS_HEADER_LEN)
        return -1;

    /* SSL 2.0 compatible Client Hello
     *
     * High bit of first byte (length) and content type is Client Hello
     *
     * See RFC5246 Appendix E.2
     */
    if (data[0] & 0x80 && data[2] == 1) {
        return -2;
    }

    tls_content_type = data[0];
    if (tls_content_type != TLS_HANDSHAKE_CONTENT_TYPE) {
        return -5;
    }

    tls_version_major = data[1];
    tls_version_minor = data[2];
    if (tls_version_major < 3) {
        return -2;
    }

    /* TLS record length */
    len = ((size_t)data[3] << 8) +
        (size_t)data[4] + TLS_HEADER_LEN;
    data_len = MIN(data_len, len);

    /* Check we received entire TLS record length */
    if (data_len < len)
        return -1;

    /*
     * Handshake
     */
    if (pos + 1 > data_len) {
        return -5;
    }
    if (data[pos] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
        return -5;
    }

    /* Skip past fixed length records:
       1	Handshake Type
       3	Length
       2	Version (again)
       32	Random
       to	Session ID Length
     */
    pos += 38;

    /* Session ID */
    if (pos + 1 > data_len)
        return -5;
    len = (size_t)data[pos];
    pos += 1 + len;

    /* Cipher Suites */
    if (pos + 2 > data_len)
        return -5;
    len = ((size_t)data[pos] << 8) + (size_t)data[pos + 1];
    pos += 2 + len;

    /* Compression Methods */
    if (pos + 1 > data_len)
        return -5;
    len = (size_t)data[pos];
    pos += 1 + len;

    if (pos == data_len && tls_version_major == 3 && tls_version_minor == 0) {
        return -2;
    }

    /* Extensions */
    if (pos + 2 > data_len)
        return -5;
    len = ((size_t)data[pos] << 8) + (size_t)data[pos + 1];
    pos += 2;

    if (pos + len > data_len)
        return -5;
    return parse_extensions(data + pos, len, hostname);
}

static int
parse_extensions(const uint8_t *data, size_t data_len, char **hostname) {
    size_t pos = 0;
    size_t len;

    /* Parse each 4 bytes for the extension header */
    while (pos + 4 <= data_len) {
        /* Extension Length */
        len = ((size_t)data[pos + 2] << 8) +
            (size_t)data[pos + 3];

        /* Check if it's a server name extension */
        if (data[pos] == 0x00 && data[pos + 1] == 0x00) {
            /* There can be only one extension of each type, so we break
               our state and move p to beinnging of the extension here */
            if (pos + 4 + len > data_len)
                return -5;
            return parse_server_name_extension(data + pos + 4, len, hostname);
        }
        pos += 4 + len; /* Advance to the next extension header */
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return -5;

    return -2;
}

static int
parse_server_name_extension(const uint8_t *data, size_t data_len,
        char **hostname) {
    size_t pos = 2; /* skip server name list length */
    size_t len;

    while (pos + 3 < data_len) {
        len = ((size_t)data[pos + 1] << 8) +
            (size_t)data[pos + 2];

        if (pos + 3 + len > data_len)
            return -5;

        switch (data[pos]) { /* name type */
            case 0x00: /* host_name */
                *hostname = malloc(len + 1);
                if (*hostname == NULL) {
                    return -4;
                }

                strncpy(*hostname, (const char *)(data + pos + 3), len);

                (*hostname)[len] = '\0';

                return len;
        }
        pos += 3 + len;
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return -5;

    return -2;
}

int red_recv_udp_pkt(int fd, char *buf, size_t buflen, struct sockaddr_in *inaddr, struct sockaddr_in *toaddr)
{
	socklen_t addrlen = sizeof(*inaddr);
	ssize_t pktlen;
	struct msghdr msg;
	struct iovec io;
	char control[1024];

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = inaddr;
	msg.msg_namelen = sizeof(*inaddr);
	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	io.iov_base = buf;
	io.iov_len = buflen;

	pktlen = recvmsg(fd, &msg, 0);
	if (pktlen == -1) {
		log_errno(LOG_WARNING, "recvfrom");
		return -1;
	}

	if (toaddr) {
		memset(toaddr, 0, sizeof(*toaddr));
		for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (
				cmsg->cmsg_level == SOL_IP &&
				cmsg->cmsg_type == IP_ORIGDSTADDR &&
				cmsg->cmsg_len >= CMSG_LEN(sizeof(*toaddr))
			) {
				struct sockaddr_in* cmsgaddr = (struct sockaddr_in*)CMSG_DATA(cmsg);
				char buf[RED_INET_ADDRSTRLEN];
				log_error(LOG_DEBUG, "IP_ORIGDSTADDR: %s", red_inet_ntop(cmsgaddr, buf, sizeof(buf)));
				memcpy(toaddr, cmsgaddr, sizeof(*toaddr));
			}
			else {
				log_error(LOG_WARNING, "unexepcted cmsg (level,type) = (%d,%d)",
					cmsg->cmsg_level, cmsg->cmsg_type);
			}
		}
		if (toaddr->sin_family != AF_INET) {
			log_error(LOG_WARNING, "(SOL_IP, IP_ORIGDSTADDR) not found");
			return -1;
		}
	}

	if (addrlen != sizeof(*inaddr)) {
		log_error(LOG_WARNING, "unexpected address length %u instead of %zu", addrlen, sizeof(*inaddr));
		return -1;
	}

	if (pktlen >= buflen) {
		char buf[RED_INET_ADDRSTRLEN];
		log_error(LOG_WARNING, "wow! Truncated udp packet of size %zd from %s! impossible! dropping it...",
		          pktlen, red_inet_ntop(inaddr, buf, sizeof(buf)));
		return -1;
	}

	return pktlen;
}

uint32_t red_randui32()
{
	uint32_t ret;
	evutil_secure_rng_get_bytes(&ret, sizeof(ret));
	return ret;
}

time_t redsocks_time(time_t *t)
{
	time_t retval;
	retval = time(t);
	if (retval == ((time_t) -1))
		log_errno(LOG_WARNING, "time");
	return retval;
}

int redsocks_gettimeofday(struct timeval *tv)
{
	int retval = gettimeofday(tv, NULL);
	if (retval != 0)
		log_errno(LOG_WARNING, "gettimeofday");
	return retval;
}

char *redsocks_evbuffer_readline(struct evbuffer *buf)
{
#if _EVENT_NUMERIC_VERSION >= 0x02000000
	return evbuffer_readln(buf, NULL, EVBUFFER_EOL_CRLF);
#else
	return evbuffer_readline(buf);
#endif
}

int red_socket_client(int type)
{
	int fd = -1;
	int error;

    logdbgtofile("/tmp/debug.log","RED_SOCKET_CLIENT");

	fd = socket(AF_INET, type, 0);
	if (fd == -1) {
		log_errno(LOG_ERR, "socket");
		goto fail;
	}

	error = fcntl_nonblock(fd);
	if (error) {
		log_errno(LOG_ERR, "fcntl");
		goto fail;
	}

	if (type == SOCK_STREAM) {
		if (apply_tcp_keepalive(fd))
			goto fail;
	}

	return fd;

fail:
	if (fd != -1)
		redsocks_close(fd);
	return -1;
}

int red_socket_server(int type, struct sockaddr_in *bindaddr)
{
	int on = 1;
	int error;
	int fd = red_socket_client(type);
	if (fd == -1)
		goto fail;

    logdbgtofile("/tmp/debug.log","RED_SOCKET_SERVER");

	error = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (error) {
		log_errno(LOG_ERR, "setsockopt");
		goto fail;
	}

	error = bind(fd, (struct sockaddr*)bindaddr, sizeof(*bindaddr));
	if (error) {
		log_errno(LOG_ERR, "bind");
		goto fail;
	}

	return fd;
fail:
	if (fd != -1)
		redsocks_close(fd);
	return -1;

}


struct bufferevent* red_connect_relay(struct sockaddr_in *addr, evbuffercb writecb, everrorcb errorcb, void *cbarg)
{
	struct bufferevent *retval = NULL;
	int relay_fd = -1;
	int error;
	char debug_string[256];
	char DESTINATION[791];

    logdbgtofile("/tmp/debug.log","RED_CONNECT_RELAY");

	sprintf(debug_string,"RED_CONNECT_RELAY: addr %s.", (char *)addr);
	logdbgtofile("/tmp/debug.log",debug_string);

// not here; core dump
//	strcpy(DESTINATION, get_TLS_SNI((unsigned char *)addr,sizeof((unsigned char *)addr)));
//	sprintf(debug_string,"RED_CONNECT_RELAY: destination %s.", (char *)DESTINATION);
//	logdbgtofile("/tmp/debug.log",debug_string);

	relay_fd = red_socket_client(SOCK_STREAM);

	error = connect(relay_fd, (struct sockaddr*)addr, sizeof(*addr));
	if (error && errno != EINPROGRESS) {
		log_errno(LOG_NOTICE, "connect");
		goto fail;
	}

    logdbgtofile("/tmp/debug.log","RED_CONNECT_RELAY: connect finished.");
	sprintf(debug_string,"RED_CONNECT_RELAY: writecb %s.", (char *)writecb);
	logdbgtofile("/tmp/debug.log",debug_string);

	strcpy(DESTINATION, get_TLS_SNI(good_data_2,sizeof(good_data_2)));
	sprintf(debug_string,"RED_CONNECT_RELAY: TEST DESTINATION %s.", (char *)DESTINATION);
	logdbgtofile("/tmp/debug.log",debug_string);
	// parse_tls_header((uint8_t *)writecb,sizeof(writecb),DESTINATION);
// not here; core dump
//	strcpy(DESTINATION, get_TLS_SNI((unsigned char *)writecb,sizeof((unsigned char *)writecb)));
//	sprintf(debug_string,"RED_CONNECT_RELAY: destination %s.", (char *)DESTINATION);
//	logdbgtofile("/tmp/debug.log",debug_string);

	retval = bufferevent_new(relay_fd, NULL, writecb, errorcb, cbarg);
	if (!retval) {
		log_errno(LOG_ERR, "bufferevent_new");
		goto fail;
	}

	sprintf(debug_string,"RED_CONNECT_RELAY: addr %d.", addr->sin_addr.s_addr);
	logdbgtofile("/tmp/debug.log",debug_string);

    logdbgtofile("/tmp/debug.log","RED_CONNECT_RELAY: bufferevent_new finished.");

	relay_fd = -1;

	error = bufferevent_enable(retval, EV_WRITE); // we wait for connection...
	if (error) {
		log_errno(LOG_ERR, "bufferevent_enable");
		goto fail;
	}

    logdbgtofile("/tmp/debug.log","RED_CONNECT_RELAY: bufferevent_enable finished.");

	return retval;

fail:
	if (relay_fd != -1)
		redsocks_close(relay_fd);
	if (retval)
		redsocks_bufferevent_free(retval);
	return NULL;
}

int red_socket_geterrno(struct bufferevent *buffev)
{
	int error;
	int pseudo_errno;
	socklen_t optlen = sizeof(pseudo_errno);

	assert(event_get_fd(&buffev->ev_read) == event_get_fd(&buffev->ev_write));

	error = getsockopt(event_get_fd(&buffev->ev_read), SOL_SOCKET, SO_ERROR, &pseudo_errno, &optlen);
	if (error) {
		log_errno(LOG_ERR, "getsockopt");
		return -1;
	}
	return pseudo_errno;
}

/** simple fcntl(2) wrapper, provides errno and all logging to caller
 * I have to use it in event-driven code because of accept(2) (see NOTES)
 * and connect(2) (see ERRORS about EINPROGRESS)
 */
int fcntl_nonblock(int fd)
{
	int error;
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		return -1;

	error = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (error)
		return -1;

	return 0;
}

int red_is_socket_connected_ok(struct bufferevent *buffev)
{
	int pseudo_errno = red_socket_geterrno(buffev);

	if (pseudo_errno == -1) {
		return 0;
	}
	else if (pseudo_errno) {
		errno = pseudo_errno;
		log_errno(LOG_NOTICE, "connect");
		return 0;
	}
	else {
		return 1;
	}
}

char *red_inet_ntop(const struct sockaddr_in* sa, char* buffer, size_t buffer_size)
{
	const char *retval = 0;
	size_t len = 0;
	uint16_t port;
	const char placeholder[] = "???:???";
	char DESTINATION[791];
	char debug_string[512];

    logdbgtofile("/tmp/debug.log","RED_INET_NTOP: inet_ntop started.");

	assert(buffer_size >= RED_INET_ADDRSTRLEN);

// not here
//	strcpy(DESTINATION, get_TLS_SNI((unsigned char *)buffer,sizeof((unsigned char *)buffer)));
//	sprintf(debug_string,"RED_INET_NTOP: destination %s.", (char *)DESTINATION);
//	logdbgtofile("/tmp/debug.log",debug_string);
	sprintf(debug_string,"RED_INET_NTOP: buffer %s.", (char *)buffer);
	logdbgtofile("/tmp/debug.log",debug_string);

	memset(buffer, 0, buffer_size);
	if (sa->sin_family == AF_INET) {
		retval = inet_ntop(AF_INET, &sa->sin_addr, buffer, buffer_size);
		port = ((struct sockaddr_in*)sa)->sin_port;
	}
	else if (sa->sin_family == AF_INET6) {
		retval = inet_ntop(AF_INET6, &((const struct sockaddr_in6*)sa)->sin6_addr, buffer, buffer_size);
		port = ((struct sockaddr_in6*)sa)->sin6_port;
	}
	if (retval) {
		assert(retval == buffer);
		len = strlen(retval);
		snprintf(buffer + len, buffer_size - len, ":%d", ntohs(port));
	}
	else {
		strcpy(buffer, placeholder);
	}
	return buffer;
}

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
