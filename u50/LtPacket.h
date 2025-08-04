// SPDX-License-Identifier: GPL-2.0 AND MIT
// Copyright © 2021-2025 EnOcean
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in 
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is furnished to do
// so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef LTPACKET_H
#define LTPACKET_H

typedef struct {
#ifdef __BIG_ENDIAN_BITFIELD
    uint8_t sub : 8;
    uint8_t mbo : 1;
    uint8_t nod : 7;
#else
    uint8_t sub : 8;
    uint8_t nod : 7;
    uint8_t mbo : 1;
#endif
} DestSubnetNode;

typedef struct {
#ifdef __BIG_ENDIAN_BITFIELD
    uint8_t sub : 8;
    uint8_t mbo : 1;
    uint8_t nod : 7;
    uint8_t grp : 8;
    uint8_t mem : 8;
#else
    uint8_t sub : 8;
    uint8_t nod : 7;
    uint8_t mbo : 1;
    uint8_t grp : 8;
    uint8_t mem : 8;
#endif
} DestGroup;

typedef struct {
    uint8_t subnet;
    uint8_t neuron_id[6];
} DestNeuronId;


typedef struct {
#ifdef __BIG_ENDIAN_BITFIELD
    uint8_t priority : 1;
    uint8_t channel : 1;
    uint8_t backlog : 6;
    uint8_t version : 2;
    uint8_t packet_type : 2;
    uint8_t format : 2;
    uint8_t domain_length : 2;
#else
    uint8_t backlog : 6;
    uint8_t channel : 1;
    uint8_t priority : 1;
    uint8_t domain_length : 2;
    uint8_t format : 2;
    uint8_t packet_type : 2;
    uint8_t version : 2;
#endif
} L2HeaderV0;

typedef struct {
    uint8_t reserved;
#ifdef __BIG_ENDIAN_BITFIELD
    uint8_t version : 2;
    uint8_t packet_type : 6;
#else
    uint8_t packet_type : 6;
    uint8_t version : 2;
#endif
} L2HeaderV1;

#define PKT_TYPE_IPV4 0
#define PKT_TYPE_IPV6 1
//#if UIP_CONF_IPV6
//#define PKT_TYPE PKT_TYPE_IPV6
//#else
#define PKT_TYPE PKT_TYPE_IPV4
//#endif

typedef L2HeaderV0 L2Header;

typedef struct {
    uint8_t src_subnet : 8;
#ifdef __BIG_ENDIAN_BITFIELD
    uint8_t grp : 1; // 0 => group ack
    uint8_t src_node : 7;
#else
    uint8_t src_node : 7;
    uint8_t grp : 1; // 0 => group ack
#endif
    union {
        uint8_t group;
        DestSubnetNode sn;
        DestGroup ga;
        DestNeuronId nid;
    } dest_addr;
    uint8_t data[1];
} Npdu;

#define MAX_MSG_SIZE 1280
typedef struct {
    uint8_t cmd;
    uint8_t len;
    L2Header header;
    uint8_t data[MAX_MSG_SIZE];
} LtPacket;

typedef struct {
    uint8_t cmd;
    uint8_t len;
    uint16_t ext_len;
    L2Header header;
    uint8_t data[MAX_MSG_SIZE];
} LtExtPacket;


extern uint8_t pkt_buf[];
#endif
