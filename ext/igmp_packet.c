/*
 *  igmp_packet.c
 *
 *  $Id: igmp_packet.c,v 1.1.1.1 2010/02/15 01:54:38 ishigoemon Exp $
 *
 *  Copyright (C) 1999  Masaki Fukushima
 *  Modified from igmp_packet.c
 *
 *  FIXME: Add support for IGMPv3
 *
 */

#include "ruby_pcap.h"
#include <limits.h>

#define IGMP_HDR(pkt)    ((struct igmp *)LAYER4_HDR(pkt))
#define IGMP_LENGTH(pkt) (ntohs(IGMP_HDR(pkt)->uh_ulen))

VALUE cIGMPPacket;

#define CheckTruncateIgmp(pkt, need) \
    CheckTruncate(pkt, pkt->hdr.layer4_off, need, "truncated IGMP")

VALUE
setup_igmp_packet(pkt, tl_len)
     struct packet_object *pkt;
     int tl_len;
{
    VALUE class;

    DEBUG_PRINT("setup_igmp_packet");

    class = cIGMPPacket;
    if (tl_len == 8) {
      DEBUG_PRINT("got igmpv2 size");
    }
    return class;
}

#define IGMPP_METHOD(func, need, val) \
static VALUE\
(func)(self)\
     VALUE self;\
{\
    struct packet_object *pkt;\
    struct igmp *igmp;\
    DEBUG_PRINT(#func);\
    GetPacket(self, pkt);\
    CheckTruncateIgmp(pkt, (need));\
    igmp = IGMP_HDR(pkt);\
    return (val);\
}

IGMPP_METHOD(igmpp_type,   1, INT2FIX(igmp->igmp_type))
IGMPP_METHOD(igmpp_code,   2, INT2FIX(igmp->igmp_code))
IGMPP_METHOD(igmpp_cksum,  4, INT2FIX(ntohs(igmp->igmp_cksum)))
IGMPP_METHOD(igmpp_group,  8, new_ipaddr(&igmp->igmp_group))


void
Init_igmp_packet(void)
{
    DEBUG_PRINT("Init_igmp_packet");

    /* define class IgmpPacket */
    cIGMPPacket = rb_define_class_under(mPcap, "IGMPPacket", cIPPacket);

    rb_define_method(cIGMPPacket, "igmp_pkttype", igmpp_type, 0);
    rb_define_method(cIGMPPacket, "pkttype", igmpp_type, 0);
    rb_define_method(cIGMPPacket, "igmp_code", igmpp_code, 0);
    rb_define_method(cIGMPPacket, "code", igmpp_code, 0);
    rb_define_method(cIGMPPacket, "igmp_cksum", igmpp_cksum, 0);
    rb_define_method(cIGMPPacket, "igmp_group", igmpp_group, 0);
}
