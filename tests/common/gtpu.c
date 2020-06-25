/*
 * Copyright (C) 2019,2020 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "test-common.h"

ogs_socknode_t *test_gtpu_server(const char *ipstr, int port)
{
    int rv;
    ogs_sockaddr_t *addr = NULL;
    ogs_socknode_t *node = NULL;
    ogs_sock_t *sock = NULL;

    rv = ogs_getaddrinfo(&addr, AF_UNSPEC, ipstr, port, 0);
    ogs_assert(rv == OGS_OK);

    node = ogs_socknode_new(addr);
    ogs_assert(node);

    sock = ogs_udp_server(node);
    ogs_assert(sock);

    return node;
}

ogs_pkbuf_t *test_gtpu_read(ogs_socknode_t *node)
{
    int rc = 0;
    ogs_pkbuf_t *recvbuf = ogs_pkbuf_alloc(NULL, OGS_MAX_SDU_LEN);
    ogs_pkbuf_put(recvbuf, OGS_MAX_SDU_LEN);

    ogs_assert(node);
    ogs_assert(node->sock);

    while (1) {
        rc = ogs_recv(node->sock->fd, recvbuf->data, recvbuf->len, 0);
        if (rc <= 0) {
            if (errno == EAGAIN) {
                continue;
            }
            break;
        } else {
            break;
        }
    }
    recvbuf->len = rc;

    return recvbuf;
}

int testgnb_gtpu_send(ogs_socknode_t *node, ogs_pkbuf_t *sendbuf)
{
    int rv;

    ogs_sockaddr_t upf;
    ssize_t sent;

    ogs_assert(node);
    ogs_assert(node->sock);

    memset(&upf, 0, sizeof(ogs_sockaddr_t));
    upf.ogs_sin_port = htons(OGS_GTPV1_U_UDP_PORT);
    upf.ogs_sa_family = AF_INET;
    upf.sin.sin_addr.s_addr = inet_addr("127.0.0.4");

    sent = ogs_sendto(node->sock->fd, sendbuf->data, sendbuf->len, 0, &upf);
    ogs_pkbuf_free(sendbuf);
    if (sent < 0 || sent != sendbuf->len)
        return OGS_ERROR;

    return OGS_OK;
}

void test_gtpu_close(ogs_socknode_t *node)
{
    ogs_socknode_free(node);
}

#include "upf/upf-config.h"

#if HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#if HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif

#if HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif

#if HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif

int test_gtpu_build_ping(ogs_pkbuf_t **sendbuf,
        test_sess_t *sess, const char *dst_ip)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp_header_t *gtp_h = NULL;
    ogs_gtp_extension_header_t *ext_h = NULL;
    ogs_ipsubnet_t dst_ipsub;

    ogs_assert(sess);
    ogs_assert(dst_ip);
    rv = ogs_ipsubnet(&dst_ipsub, dst_ip, NULL);
    ogs_assert(rv == OGS_OK);

    pkbuf = ogs_pkbuf_alloc(NULL,
            200 /* enough for ICMP; use smaller buffer */);
    ogs_pkbuf_put(pkbuf, 200);
    memset(pkbuf->data, 0, pkbuf->len);

    gtp_h = (ogs_gtp_header_t *)pkbuf->data;
    gtp_h->flags = 0x34;
    gtp_h->type = OGS_GTPU_MSGTYPE_GPDU;
    gtp_h->teid = htobe32(sess->upf_n3_teid);

    ext_h = (ogs_gtp_extension_header_t *)(pkbuf->data + OGS_GTPV1U_HEADER_LEN);
    ext_h->type = OGS_GTP_EXTENSION_HEADER_TYPE_PDU_SESSION_CONTAINER;
    ext_h->len = 1;
    ext_h->pdu_type =
        OGS_GTP_EXTENSION_HEADER_PDU_TYPE_UL_PDU_SESSION_INFORMATION;
    ext_h->qos_flow_identifier = 1;
    ext_h->next_type = OGS_GTP_EXTENSION_HEADER_TYPE_NO_MORE_EXTENSION_HEADERS;

    if (dst_ipsub.family == AF_INET) {
        struct ip *ip_h = NULL;
        struct icmp *icmp_h = NULL;

#define GTP_EXTENSION_HEADER_SIZE 8
        gtp_h->length = htobe16(
                sizeof *ip_h + ICMP_MINLEN + GTP_EXTENSION_HEADER_SIZE);

        ip_h = (struct ip *)(pkbuf->data +
                OGS_GTPV1U_HEADER_LEN + GTP_EXTENSION_HEADER_SIZE);
        icmp_h = (struct icmp *)((uint8_t *)ip_h + sizeof *ip_h);

        ip_h->ip_v = 4;
        ip_h->ip_hl = 5;
        ip_h->ip_tos = 0;
        ip_h->ip_id = rand();
        ip_h->ip_off = 0;
        ip_h->ip_ttl = 255;
        ip_h->ip_p = IPPROTO_ICMP;
        ip_h->ip_len = htobe16(sizeof *ip_h + ICMP_MINLEN);
        ip_h->ip_src.s_addr = sess->ue_ip.addr;
        ip_h->ip_dst.s_addr = dst_ipsub.sub[0];
        ip_h->ip_sum = ogs_in_cksum((uint16_t *)ip_h, sizeof *ip_h);

        icmp_h->icmp_type = 8;
        icmp_h->icmp_seq = rand();
        icmp_h->icmp_id = rand();
        icmp_h->icmp_cksum = ogs_in_cksum((uint16_t *)icmp_h, ICMP_MINLEN);
    } else if (dst_ipsub.family == AF_INET6) {
#if 0
        struct ip6_hdr *ip6_h = NULL;
        struct icmp6_hdr *icmp6_h = NULL;
        uint16_t plen = 0;
        uint8_t nxt = 0;
        uint8_t *p = NULL;

        gtp_h->length = htons(sizeof *ip6_h + sizeof *icmp6_h);
        plen =  htons(sizeof *icmp6_h);
        nxt = IPPROTO_ICMPV6;

        p = (uint8_t *)pkbuf->data + OGS_5GS_GTP_HEADER_LEN;
        ip6_h = (struct ip6_hdr *)p;
        icmp6_h = (struct icmp6_hdr *)((uint8_t *)ip6_h + sizeof *ip6_h);

        memcpy(p, src_ipsub.sub, sizeof src_ipsub.sub);
        p += sizeof src_ipsub.sub;
        memcpy(p, dst_ipsub.sub, sizeof dst_ipsub.sub);
        p += sizeof dst_ipsub.sub;
        p += 2; memcpy(p, &plen, 2); p += 2;
        p += 3; *p = nxt; p += 1;

        icmp6_h->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6_h->icmp6_seq = rand();
        icmp6_h->icmp6_id = rand();

        icmp6_h->icmp6_cksum = ogs_in_cksum(
                (uint16_t *)ip6_h, sizeof *ip6_h + sizeof *icmp6_h);

        ip6_h->ip6_flow = htonl(0x60000001);
        ip6_h->ip6_plen = plen;
        ip6_h->ip6_nxt = nxt;;
        ip6_h->ip6_hlim = 0xff;
        memcpy(ip6_h->ip6_src.s6_addr, src_ipsub.sub, sizeof src_ipsub.sub);
        memcpy(ip6_h->ip6_dst.s6_addr, dst_ipsub.sub, sizeof dst_ipsub.sub);
#endif
    } else
        ogs_assert_if_reached();

    *sendbuf = pkbuf;

    return OGS_OK;
}
