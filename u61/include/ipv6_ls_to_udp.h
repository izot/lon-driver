// SPDX-License-Identifier: GPL-2.0 AND MIT
// Copyright © 2021-2022 Dialog Semiconductor
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

/****************************************************************************
 *
 *  FILE DESCRIPTION:  
 *      This header file contains the definitions and function prototypes
 *      used to translate between LonTalk V0 or V2 and LS/UDP
 *
 ***************************************************************************/
#ifndef _IPV6_LS_TO_UDP_H
#define _IPV6_LS_TO_UDP_H

#ifdef __cplusplus
extern "C" {            /* Assume C declarations for C++ */
#endif  /* __cplusplus */

#ifndef USE_UIP
//#include "LonTalk.h"
#define UIP_CONF_IPV6 0
#define IPV6_TRACE_ENABLED 0
#define IPV6_INCLUDE_LTVX_LSUDP_TRANSLATION 1  
#define IPV6_SUPPORT_ARBITRARY_ADDRESSES 1
#ifndef WIN32
#ifndef U50_KERNEL
#include <stdint.h>
#endif
#endif
#endif

// Time To Live for IPV4 Multicast. 
#define IPV6_MC_TTL_FOR_IPV4 32 // Restricted to the same site, organization or department


    // LonTalk Service multicast type.  This is found in offset 14 of an
    // LS MC address
#define IPV6_LS_MC_ADDR_TYPE_BROADCAST 0
#define IPV6_LS_MC_ADDR_TYPE_GROUP     1

    // UDP port used for LS/UDP
    // Note that this  port was originaly allocated for use by LNS remote lightweight clients.  However
    // LNS only uses this port for TCP, so LS/UDP can use this port for UDP.
#define IPV6_LS_UDP_PORT           2541

// The IPV6_LTVX_NPDU_IDX_ definitions represent the byte offset of the first several fields in a version 0 NPDU.
//
// The following definitions are used to access fields within a LTVx NPDU
//     
// | 1 |   1   |   6   | 2 | 2 | 2 |   2   |  2  |    8    |1|  7    |Variable|0/8/24/48|Variable|
// |===|=======|=======|===|===|===|=======|=====|=========|=|=======|========|=========|========|
// |Pri|AltPath|DeltaBl|Ver|PDU|Fmt|AddrFmt|DmLen|SrcSubnet|f|SrcNode|DestAddr| Domain  |EnclPDU |
// |==============================================================================================
//
// DestAddr has one of the following forms
//
//  Broadcast (f = 1):  Group (f = 1):   Subnet/Node (f = 1)   
//      |  8   |          |  8   |       |  8   |1| 7  |      
//      |======|          |======|       |======|=|====|      
//      |subnet|          |group |       |subnet|1|Node|      
//      ========          ========       ===============      
//
//  Subnet/Node (f = 0) - for group responses   NeuronID (f = 1)
//   |  8   |1| 7  |   8   |   8    |            |  8   |   48   |  
//   |======|=|====|=======|========|            |======|========|  
//   |subnet|1|Node|GroupID|GroupMbr|            |subnet|NeuronID|  
//   ================================            =================  


#define IPV6_LTVX_NPDU_IDX_PRIDELTA       0
#define IPV6_LTVX_NPDU_IDX_TYPE           1
#define IPV6_LTVX_NPDU_IDX_SOURCE_SUBNET  2
#define IPV6_LTVX_NPDU_IDX_SOURCE_NODE    3
#define IPV6_LTVX_NPDU_IDX_DEST_ADDR      4
#define IPV6_LTVX_NPDU_IDX_DEST_SUBNET    IPV6_LTVX_NPDU_IDX_DEST_ADDR
#define IPV6_LTVX_NPDU_IDX_DEST_NODE      (IPV6_LTVX_NPDU_IDX_DEST_ADDR+1)
#define IPV6_LTVX_NPDU_IDX_DEST_NEURON_ID (IPV6_LTVX_NPDU_IDX_DEST_ADDR+1)

#define IPV6_LTVX_NPDU_IDX_DEST_NODE_MASK 0x7f

#define IPV6_LTVX_NPDU_IDX_RESP_GROUPID  (IPV6_LTVX_NPDU_IDX_DEST_ADDR+2)       // The group ID contained in a response (subnet/node address)
#define IPV6_LTVX_NPDU_IDX_RESP_GROUPMBR (IPV6_LTVX_NPDU_IDX_RESP_GROUPID+1)    // The group member contained in a response

#define IPV6_LTVX_NPDU_DEST_NEURON_ID_LEN   6


// The following definitions are used to access fields within a LTVx NPDU.  
// Typically a bit position (BITPOS) and mask value are provided for each field
// Byte 0 - IPV6_LTVX_NPDU_IDX_PRIDELTA
// | 1 |   1   |   6   |
// |===|=======|=======|
// |Pri|AltPath|DeltaBl|
// |====================
#define IPV6_LTVX_NPDU_BITPOS_DELTA_BACKLOG 0
#define IPV6_LTVX_NPDU_MASK_DELTA_BACKLOG  (0x3f << IPV6_LTVX_NPDU_BITPOS_DELTA_BACKLOG)
#define IPV6_LTVX_NPDU_BITPOS_ALT_PATH     6
#define IPV6_LTVX_NPDU_MASK_ALT_PATH       (1 << IPV6_LTVX_NPDU_BITPOS_ALT_PATH)
#define IPV6_LTVX_NPDU_BITPOS_PRIORITY     7
#define IPV6_LTVX_NPDU_MASK_PRIORITY       (1 << IPV6_LTVX_NPDU_BITPOS_PRIORITY)
#define IPV6_GET_ALT_PATH_FROM_NPDU(npdu)  (((npdu)[IPV6_LTVX_NPDU_IDX_PRIDELTA] & IPV6_LTVX_NPDU_MASK_ALT_PATH) >> IPV6_LTVX_NPDU_BITPOS_ALT_PATH)

// Byte 1 - IPV6_LTVX_NPDU_IDX_TYPE

// | 2 |   2   |   2   |  2  | 
// |===|=======|=======|=====|
// |Ver|PDU Fmt|AddrFmt|DmLen|
// ===========================
#define IPV6_LTVX_NPDU_BITPOS_DOMAINLEN     0
#define IPV6_LTVX_NPDU_BITPOS_ADDRTYPE      2
#define IPV6_LTVX_NPDU_BITPOS_PDUFMT        4
#define IPV6_LTVX_NPDU_BITPOS_VER           6
#define IPV6_LTVX_NPDU_MASK_DOMAINLEN       (0x03 << IPV6_LTVX_NPDU_BITPOS_DOMAINLEN)
#define IPV6_LTVX_NPDU_MASK_ADDRTYPE        (0x03 << IPV6_LTVX_NPDU_BITPOS_ADDRTYPE)
#define IPV6_LTVX_NPDU_MASK_PDUFMT          (0x03 << IPV6_LTVX_NPDU_BITPOS_PDUFMT) 
#define IPV6_LTVX_NPDU_MASK_VER             (0x03 << IPV6_LTVX_NPDU_BITPOS_VER) 

#define IPV6_GET_ADDRESS_FORMAT_FROM_NPDU(npdu)  (((npdu)[IPV6_LTVX_NPDU_IDX_TYPE] & IPV6_LTVX_NPDU_MASK_ADDRTYPE) >> IPV6_LTVX_NPDU_BITPOS_ADDRTYPE)
#define IPV6_GET_PDU_FORMAT_FROM_NPDU(npdu)  (((npdu)[IPV6_LTVX_NPDU_IDX_TYPE] & IPV6_LTVX_NPDU_MASK_PDUFMT) >> IPV6_LTVX_NPDU_BITPOS_PDUFMT)

#define ENCLOSED_PDU_TYPE_TPDU 0
#define ENCLOSED_PDU_TYPE_SPDU 1
#define ENCLOSED_PDU_TYPE_AUTH 2
#define ENCLOSED_PDU_TYPE_APDU 3

// Supported LT versions
#define IPV6_LT_VER_LEGACY          0       // 4 bit transaction IDs
#define IPV6_LT_VER_ENCAPSULATED_IP 1       // Arbitrary IP traffic on a native LonTalk link
#define IPV6_LT_VER_ENHANCED        2       // 12 bit transaction IDs.

// Some LonTalk links compress arbitrary UDP packets usng LS enhanced mode
#define IPV6_LT_VER_ARB_UDP         IPV6_LT_VER_ENHANCED  

#define IPV6_LT_VER_MATCHES(value, ver) ((value & IPV6_LTVX_NPDU_MASK_VER) == ((ver) << IPV6_LTVX_NPDU_BITPOS_VER))
#define IPV6_LT_IS_VER_LS_LEGACY_MODE(value)        IPV6_LT_VER_MATCHES(value, IPV6_LT_VER_LEGACY)
#define IPV6_LT_IS_VER_LS_ENHANCED_MODE(value)      IPV6_LT_VER_MATCHES(value, IPV6_LT_VER_ENHANCED)
#define IPV6_LT_IS_VER_LS_ENCAPSULATED_IP(value)    IPV6_LT_VER_MATCHES(value, IPV6_LT_VER_ENCAPSULATED_IP)
#define IPV6_LT_IS_VER_ARB_UDP(value)               IPV6_LT_VER_MATCHES(value, IPV6_LT_VER_ARB_UDP)

#define IPV6_LTVX_NPDU_BITPOS_SERVICE_TYPE  4
#define IPV6_LTVX_NPDU_MASK_SERVICE_TYPE   (3 << IPV6_LTVX_NPDU_BITPOS_SERVICE_TYPE)

// TPDU types
#define IPV6_LTVX_NPDU_TPDU_TYPE_ACKD      00
#define IPV6_LTVX_NPDU_TPDU_TYPE_REPEATED (0x01 << IPV6_LTVX_NPDU_BITPOS_SERVICE_TYPE)
#define IPV6_LTVX_NPDU_TPDU_TYPE_ACK      (0x02 << IPV6_LTVX_NPDU_BITPOS_SERVICE_TYPE)
#define IPV6_LTVX_NPDU_TPDU_TYPE_REMINDER (0x04 << IPV6_LTVX_NPDU_BITPOS_SERVICE_TYPE)
#define IPV6_LTVX_NPDU_TPDU_TYPE_REMMSG   (0x05 << IPV6_LTVX_NPDU_BITPOS_SERVICE_TYPE)

// SPDU types
#define IPV6_LTVX_NPDU_SPDU_TYPE_REQUEST  00
#define IPV6_LTVX_NPDU_SPDU_TYPE_RESPONSE (0x02 << IPV6_LTVX_NPDU_BITPOS_SERVICE_TYPE)
#define IPV6_LTVX_NPDU_SPDU_TYPE_REMINDER (0x04 << IPV6_LTVX_NPDU_BITPOS_SERVICE_TYPE)
#define IPV6_LTVX_NPDU_SPDU_TYPE_REMMSG   (0x05 << IPV6_LTVX_NPDU_BITPOS_SERVICE_TYPE)


// The first two bytes of the LIFT link layer header have the following format for V1 packets
// | 8 | 2 |    6    |
// |===|===|=========|
// |00 | 1 | PktType |
// ===================

#define IPV6_LSUDP_LINKHDR_MASK_PKTTYPE 0x3f
#define IPV6_GET_LSUDP_LINKHDR_PKTTYPE(pHdr) (pHdr[1] & IPV6_LSUDP_LINKHDR_MASK_PKTTYPE)

#define IPV6_LSUDP_LINKHDR_PKTTYPE_IPV4 0
#define IPV6_LSUDP_LINKHDR_PKTTYPE_IPV6 1

#if UIP_CONF_IPV6
#define IPV6_LSUDP_LINKHDR_PKTTYPE_MYIP IPV6_LSUDP_LINKHDR_PKTTYPE_IPV6
#else
#define IPV6_LSUDP_LINKHDR_PKTTYPE_MYIP IPV6_LSUDP_LINKHDR_PKTTYPE_IPV4
#endif
#define IPV6_LSUDP_LINKHDR_PKT_HEADER_VALID(pHdr) (pHdr[0] == 0 && IPV6_GET_LSUDP_LINKHDR_PKTTYPE(pHdr) == IPV6_LSUDP_LINKHDR_PKTTYPE_MYIP)

// Byte 1 - IPV6_LTVX_NPDU_IDX_TYPE

// | 2 |   2  |   2   |  2  |
// |===|======|=======|=====|
// |Ver|PDUFmt|AddrFmt|DmLen|
// ==========================


// The following definitions are used to access fields within a LS/UDP NPDU
//     
// |  4   |  4  |   4   | 1 | 1 |   2   | 0 or 16 | 0 or 8 | 0 or 8  | 0 or 48|variable|
// |======|=====|=======|===|===|=======|=========|========|=========|========|========|
// |UdpVer|Flags|AddrFmt|MCR|Pri|PDU Fmt| BlInfo  | Group  | Grp Mbr |NeuronId|Encl.PDU|
// |===================================================================================|
//
 
// Byte 0 
// |  4   |  3  | 1| 
// |======|=====|==|
// |UdpVer|Flags|SF|
// |================
//
#define IPV6_LSUDP_UDP_VER_LS_LEGACY         0
#define IPV6_LSUDP_UDP_VER_LS_ENHANCED       1
#define IPV6_LSUDP_UDP_VER_CURRENT           IPV6_LSUDP_UDP_VER_LS_ENHANCED

#define IPV6_LSUDP_NPDU_BITPOS_ARB_SOURCE    0
#define IPV6_LSUDP_NPDU_BITPOS_UNMAPPED      1
#define IPV6_LSUDP_NPDU_BITPOS_FLAGS         2
#define IPV6_LSUDP_NPDU_BITPOS_UDPVER        4
#define IPV6_LSUDP_NPDU_MASK_ARB_SOURCE      (0x01 << IPV6_LSUDP_NPDU_BITPOS_ARB_SOURCE)
#define IPV6_LSUDP_NPDU_MASK_UNMAPPED        (0x01 << IPV6_LSUDP_NPDU_BITPOS_UNMAPPED)
#define IPV6_LSUDP_NPDU_MASK_FLAGS           (0x03 << IPV6_LSUDP_NPDU_BITPOS_FLAGS)
#define IPV6_LSUDP_NPDU_MASK_UDPVER          (0x0f << IPV6_LSUDP_NPDU_BITPOS_UDPVER)

// Byte 1 
// |   4   | 1 | 1 |   2   | 
// |=======|===|===|=======|
// |AddrFmt|MCR|Pri|PDU Fmt| 
// =========================
//
#define IPV6_LSUDP_NPDU_BITPOS_PDUFMT        0
#define IPV6_LSUDP_NPDU_BITPOS_PRIORITY      2
#define IPV6_LSUDP_NPDU_BITPOS_MCR           3
#define IPV6_LSUDP_NPDU_BITPOS_ADDRFMT       4
#define IPV6_LSUDP_NPDU_MASK_PDUFMT          (0x03 << IPV6_LSUDP_NPDU_BITPOS_PDUFMT)
#define IPV6_LSUDP_NPDU_MASK_PRIORITY        (0x01 << IPV6_LSUDP_NPDU_BITPOS_PRIORITY)
#define IPV6_LSUDP_NPDU_MASK_MCR             (0x01 << IPV6_LSUDP_NPDU_BITPOS_MCR)
#define IPV6_LSUDP_NPDU_MASK_ADDRFMT         (0x0f << IPV6_LSUDP_NPDU_BITPOS_ADDRFMT)

// The BlInfo field - Bytes 2 and 3 (optional)
// | 2  |   6   |   8   |
// |====|=======|=======|
// |Rsvd|DeltaBl|RspTime|
// ======================
#define IPV6_LSUDP_NPDU_IDX_BLINFO 2
#define IPV6_LSUDP_NPDU_MASK_DELTA_BACKLOG IPV6_LTVX_NPDU_MASK_DELTA_BACKLOG

// The arbitrary source adderess, appears after the BlInfo record.  Present if
// IPV6_LSUDP_NPDU_MASK_ARB_SOURCE is set.
//
// |   8    |1|   7  |
// |========|=|======|
// |SubnetId|0|NodeId|
// |==================
// 
// |   8    |1|   7  |  6 |  2  |variable|
// |========|=|======|====|=====|========|
// |SubnetId|1|NodeId|Rsvd|DmLen|DomainID|
// |======================================
// Offsets relative to begining of arbitrary source address
#define IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_SUBNET    0
#define IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_NODE      (IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_SUBNET + 1)
#define IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_DMFLAG    (IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_NODE + 0)
#define IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_DMLEN     (IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_NODE + 1)
#define IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_DM        (IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_DMLEN + 1)

#define IPV6_LSUDP_NPDU_MASK_ARB_SOURCE_NODE     0x7f    // At offset IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_NODE
#define IPV6_LSUDP_NPDU_MASK_ARB_SOURCE_DMFLG    0x80    // At offset IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_DMFLAG
#define IPV6_LSUDP_NPDU_MASK_ARB_SOURCE_DMLEN    3       // At offset IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_DMLEN

// LSUDP address formats
#define IPV6_LSUDP_NPDU_ADDR_FMT_NEURON_ID           (0 << IPV6_LSUDP_NPDU_BITPOS_ADDRFMT)
#define IPV6_LSUDP_NPDU_ADDR_FMT_SUBNET_NODE         (1 << IPV6_LSUDP_NPDU_BITPOS_ADDRFMT)
#define IPV6_LSUDP_NPDU_ADDR_FMT_DOMAIN_BROADCAST    (2 << IPV6_LSUDP_NPDU_BITPOS_ADDRFMT)
#define IPV6_LSUDP_NPDU_ADDR_FMT_SUBNET_BROADCAST    (3 << IPV6_LSUDP_NPDU_BITPOS_ADDRFMT)
#define IPV6_LSUDP_NPDU_ADDR_FMT_GROUP               (4 << IPV6_LSUDP_NPDU_BITPOS_ADDRFMT)
#define IPV6_LSUDP_NPDU_ADDR_FMT_GROUP_RESP          (5 << IPV6_LSUDP_NPDU_BITPOS_ADDRFMT)
#define IPV6_LSUDP_NPDU_ADDR_FMT_BROADCAST_NEURON_ID (6 << IPV6_LSUDP_NPDU_BITPOS_ADDRFMT)
#define IPV6_LSUDP_NPDU_ADDR_FMT_EXP_SUBNET_NODE     (7 << IPV6_LSUDP_NPDU_BITPOS_ADDRFMT)

#if UIP_CONF_IPV6
// Offsets within IPV6 unicast addresses

// Subnet/node address
// |<---- 48 ---->| 8  |<----  8 ---->|<----- 56 ----->|<---- 8 --->|
// ==================================================================
// |    DomainId  | 00 | LS subnet ID | 00000000000000 | LS Node ID |
// ==================================================================
#define IPV6_LSIP_UCADDR_OFF_SUBNET 7
#define IPV6_LSIP_UCADDR_OFF_NODE   15
#define IPV6_LSIP_UCADDR_OFF_DOMAIN 0
#define IPV6_LSIP_LTVx_DOMAIN_LEN         6  // The size of the domain in the LTVX packet
#define IPV6_LSIP_LTVx_DOMAIN_LEN_ENCODED 3  // The encoded size of the domain in the LTVx packet
#define IPV6_LSIP_IPADDR_DOMAIN_LEN       6  // The size of the domain in the IP address
#else
/*
// Offsets within IPV4 unicast addresses

// Unicast addressing in LS/IPV4 uses a 2 byte prefix based on the domain,
// followed by the LS subnet and LS node.
//
// |<------ 16 ------>|<----  8 ---->|<--- 56 --->|
// ================================================
// |   Domain Prefix  | LS subnet ID | LS Node ID |
// ================================================
//
// LS/IPV4 supports 3 domain lengths, 0, 1 and 3.  However, the third
// byte of 3 byte domain ID must always be 0 and is ommitted from the IP address.
// Let "d1" and "d2" represent the first and second bytes of the domain ID, 
// "s" the LS subnet ID and "n" the LS node ID.  The format of the IP address
// for each  supported domain length is:
//
//      Domain len      Format
//          0           192.168.s.n
//          1           10.d1.s.n
//          3           d1.d2.s.n
//
*/
#define IPV6_LSIP_UCADDR_OFF_SUBNET 2
#define IPV6_LSIP_UCADDR_OFF_NODE   3
#define IPV6_LSIP_UCADDR_OFF_DOMAIN 0
// Support domain lengths 0, 1 and 3.
#define IPV6_LSIP_LTVX_DOMAIN_LEN_0_ENCODED 0  // The encoded size of the zero len domain.  Translates to 192.168.x.x
#define IPV6_LSIP_LTVX_DOMAIN_LEN_1_ENCODED 1  // The encoded size of a 1 byte domain.  Translates to D1.D1.x.x  
#define IPV6_LSIP_LTVX_DOMAIN_LEN_3_ENCODED 2  // The encoded size of a 3 byte domain.  Last byte MBZ.  Translates to D1.D2.x.x

#define IPV6_LSIP_IPADDR_DOMAIN_LEN       2  // The size of the domain in the IP address - lsb is 0.
#endif

#if UIP_CONF_IPV6
/* 
// // Neuron ID address
// |<---- 48 ---->|  8  |      8    |<------------ 64 ------------>|
// ================================================================= 
// | LS Domain ID | 00  | LS Subnet | EUI-64 derived from NeuronId |
// =================================================================
//
//           |0      0|       1|1      2|2      3|3      3|4      4|
//           |0      7|       5|6      3|4      1|2      9|0      7|
//           +--------+--------+--------|--------+--------+--------+
//           |mmmmmmmm|ssssssss|ssssssss|ssssssss|ssssssss|bbbbbbbb| Neuron ID
//           +--------+--------+--------+--------+--------+--------+
//            || /        /        /          \         \       \
//            ||/        /        /            \         \       \
//            ||        /        /              \         \       \
//            ||       /        /                \         \       \
//           /||      /        /                  \         \       \
//          / ||     /        /                    \         \       \
//      |0 /  ||    /   1|1   |          3|3        \     4|4 \       \    6|
//      |0v   vv   v    5|6   v          1|2         v    7|8  v       v   3|
//      +----------------+----------------+----------------+----------------+
//      |mmmmmmugssssssss|ssssssss11111111|11111110ssssssss|ssssssssbbbbbbbb| IID
//      +----------------+----------------+----------------+----------------+
//             ^^
//         u---+|
//         g----+
*/
#define IPV6_LSIP_UCADDR_OFF_NIDHI  8
#define IPV6_LSIP_UCADDR_OFF_NIDLO  13
#define IPV6_LSIP_UCADDR_NID_HILEN  3
#define IPV6_LSIP_UCADDR_NID_LOLEN  3

/* Offsets within IPV6 unicast addresses
//
//  |  16  |<-- 48  -->|<---- 48 ---->|<---- 8 ---->|<-------- 8 ------->|
//  ======================================================================
//  | FF18 | Domain ID | 4C5349505636 | AddressType | LS Subnet or Group |
//  ======================================================================
*/
#define IPV6_LSIP_MCADDR_OFF_ADDR_TYPE 14
#define IPV6_LSIP_MCADDR_OFF_SUBNET 15
#define IPV6_LSIP_MCADDR_OFF_GROUP  15
#define IPV6_LSIP_MCADDR_OFF_DOMAIN 2
#else
#define IPV6_LSIP_MCADDR_OFF_ADDR_TYPE 2
#define IPV6_LSIP_MCADDR_OFF_SUBNET 3
#define IPV6_LSIP_MCADDR_OFF_GROUP  3
#endif

// These are used on neuron to turn off certain warnings...
#ifndef NEURON_IPV6_WARNOFF_NO_EFFECT
#define NEURON_IPV6_WARNOFF_NO_EFFECT
#define NEURON_IPV6_WARNON_NO_EFFECT
#endif

#define IPV4_ADDRESS_LEN 4
#define IPV6_ADDRESS_LEN 16
#if UIP_CONF_IPV6
#define IPV6_MAX_IP_ADDRESS_LEN IPV6_ADDRESS_LEN
#else
#define IPV6_MAX_IP_ADDRESS_LEN IPV4_ADDRESS_LEN
#endif

#define IPV6_MAX_ARBITRARY_SOURCE_ADDR_LEN 9

// Allow room for subent/node address, 6 byte domain and 2 byte msg code.
#define IPV6_MAX_LTVX_UNICAST_ARB_ANNOUNCE_LEN (IPV6_LTVX_NPDU_IDX_DEST_NODE+1+6+2)

// Allow room for 6 byte domain broadcast address and 2 byte msg code.
#define IPV6_MAX_LTVX_BROADCAST_ARB_ANNOUNCE_LEN (IPV6_LTVX_NPDU_IDX_DEST_SUBNET+1+6+2)


// Announcment message.  The first byte is IPV6_EXP_MSG_CODE.
#define IPV6_EXP_MSG_CODE                             0x60
// The sub-command code.
#define IPV6_EXP_DEVICE_LS_ADDR_MAPPING_ANNOUNCEMENT  0x15        // Announce LS address. Content doesn't matter, source addr format does.
#define IPV6_EXP_SUBNETS_LS_ADDR_MAPPING_ANNOUNCEMENT 0x16        // Announce subnets using LS derived IP addresses


///////////////////////////////////////////////////////////////////////////////
// 
// V0/V2 Arbitrary UDP packet Compresssion 
//
/////////////////////////////////////////////////////////////////////////////////

// The following definitions are used to access fields within the APDU of a 
// compressed arbitrary UPD packet
//     
// | 8 | 1 | 3 | 3 | 1 | 0-128 | 0-128 | 0/16  |   16  | Variable    |
// |===|===|===|===|===|=======|=======|=======|=======|=============|
// | 4F|MBZ|SAC|DAC|SPE|SrcAddr|DstAddr|SrcPort|DstPort| UDP Payload |
// ===================================================================
//

    // This message code is used by the LonTalk applicaion to send and receive 
    // UDP messages.  They are presented as LonTalk application messages using
    // the Ipv6UdpAppMsgHdr, followed by the UDP payload.
#define IPV6_UDP_APP_MSG_CODE           0x4f    

// The following define the commpression bits
#define IPV6_ARB_UDP_SAC_BITPOS         4       // The bit position of the Source Address Compression value
#define IPV6_ARB_UDP_DAC_BITPOS         1       // The bit position of the Desitination Address Compression value
#define IPV6_ARB_UDP_SPE_BITPOS         0       // The bit position of the Source Port Elided Flag

#define IPV6_ARB_UDP_SAC_MASK           (0x7 << IPV6_ARB_UDP_SAC_BITPOS)
#define IPV6_ARB_UDP_DAC_MASK           (0x7 << IPV6_ARB_UDP_DAC_BITPOS)
#define IPV6_ARB_UDP_SPE_MASK           (0x1 << IPV6_ARB_UDP_SPE_BITPOS)

typedef struct Ipv6UdpAppMsgHdr
{
    uint8_t   sourceIpAddress[IPV4_ADDRESS_LEN];   // The source IP address in *NETWORK ORDER* 
    uint16_t  sourcePort;                          // The source UDP port in *NETWORK ORDER*
    uint8_t   destIpAddress[IPV4_ADDRESS_LEN];     // The desgination IP address in *NETWORK ORDER*
    uint16_t  destPort;                            // The destination UDP port in *NETWORK ORDER*.
} Ipv6UdpAppMsgHdr;

// The maximum sized NPDU header for a compressed arbitrary UPD packet. Addr mode is subnet/node (2 byte dest)
// or broadcast (1 byte dest).
#define IPV6_MAX_COMPRESSED_ARB_UDP_NPDU_HDR (2 + /* Priority/Delta + Ver/pduFm/addrFmt/dmLen */\
                                              4 + /* Source subnet/node, dest subnet/node */ \
                                              6   /* 6 byte domain ID */)

// The maximum for the UDP header in a compressed packet, assuming nothing is elided */
#define IPV6_MAX_COMPRESSED_ARB_UDP_HDR_LEN (2 + /* msg code + compression flags*/ \
                                             2*IPV6_MAX_IP_ADDRESS_LEN + \
                                             4  /* 2 ports */)

// The maximum size of the NPDU header + the UDP header 
#define IPV6_MAX_COMPRESSED_ARB_UDP_OVERHEAD (IPV6_MAX_COMPRESSED_ARB_UDP_NPDU_HDR + IPV6_MAX_COMPRESSED_ARB_UDP_HDR_LEN)

///////////////////////////////////////////////////////////////////////////////
// 
// External data 
//
///////////////////////////////////////////////////////////////////////////////
#if UIP_CONF_IPV6
// The Lontalk services multicast prefix which appears at offsets 8-13 of
// an LS MC adderess
extern const uint8_t ipv6_ls_multicast_prefix[6];
// Pointer to my IP prefix
uip_ds6_prefix_t *pIpv6LsDomainUipPrefix;

#else
extern const uint8_t ipv6_ls_multicast_prefix[2];
// The 2 byte IP prefix used to represent the 0 length domain
extern const uint8_t ipv6_zero_len_domain_prefix[2];
extern volatile uint8_t ipv6_one_len_domain_prefix;
#define IPV6_DOMAIN_LEN_1_PREFIX ipv6_one_len_domain_prefix
#define IPV6_DOMAIN_LEN_0_PREFIX_0 192
#define IPV6_DOMAIN_LEN_0_PREFIX_1 168
#endif 
///////////////////////////////////////////////////////////////////////////////
// 
// Function prototypes 
//
///////////////////////////////////////////////////////////////////////////////

/******************************************************************************
  Function:  ipv6_gen_ls_prefix
   
  Summary:
    Generate a LS prefix from a LS domain and subnet

  Parameters:
    pDomainId:  Pointer to the domain ID
    domainLen:  Length of the domain (0 to 6)
    subnet:     LS subnet ID
    pAddr:      Pointer to a buffer to store the prefix (must be IPV6_IP_ADDR_LEN)

*****************************************************************************/
extern  void ipv6_gen_ls_prefix(const uint8_t *pDomainId, uint8_t domainLen, 
                               uint8_t subnet, uint8_t *pAddr);

/******************************************************************************
  Function:  ipv6_gen_ls_mc_addr
   
  Summary:
    Generate a multicast address for a LS broadcast or group address

  Parameters:
    type:           The multicast group type: IPV6_LS_MC_ADDR_TYPE_BROADCAST or
                    IPV6_LS_MC_ADDR_TYPE_GROUP
    pDomainId:      Pointer to the domain ID        (IPV6 only)
    domainLen:      Length of the domain (0 to 6)   (IPV6 only)
    subnetOrGroup:  LS subnet ID or group ID
    pAddr:          Pointer to a buffer to store the IPV6 address

*****************************************************************************/
extern void ipv6_gen_ls_mc_addr(uint8_t type, 
#if UIP_CONF_IPV6
                                const uint8_t *pDomainId, uint8_t domainLen, 
#endif
                                uint8_t subnetOrGroup, uint8_t *pAddr);

/******************************************************************************
  Function:  ipv6_gen_ls_subnet_node_addr
   
  Summary:
    Generate a unicast address for a LS subent/node address

  Parameters:
    pDomainId:      Pointer to the domain ID
    domainLen:      Length of the domain (0 to 6)
    subnetId:       LS subnet ID 
    nodeId:         LS node ID
    pAddr:          Pointer to a buffer to store the IPV6 address

*****************************************************************************/
extern void ipv6_gen_ls_subnet_node_addr(const uint8_t *pDomainId, uint8_t domainLen, 
                                         uint8_t subnetId, uint8_t nodeId, uint8_t *pAddr);

/******************************************************************************
  Function:  ipv6_gen_ls_neuronid_addr
   
  Summary:
    Generate a unicast address for a LS neuron ID 

  Parameters:
    pDomainId:      Pointer to the domain ID
    domainLen:      Length of the domain (0 to 6)
    subnetId:       LS subnet ID 
    pNeuronId:      Pointer to the LS neuron ID
    pAddr:          Pointer to a buffer to store the IPV6 address

*****************************************************************************/
extern void ipv6_gen_ls_neuronid_addr(const uint8_t *pDomainId, uint8_t domainLen, 
                                      uint8_t subnetId, const uint8_t *pNeuronId, 
                                      uint8_t *pAddr);

#if IPV6_INCLUDE_LTVX_LSUDP_TRANSLATION

/******************************************************************************
  Function:  ipv6_convert_ltvx_to_ls_udp
   
  Summary:
    Convert the LonTalk V0 or V2 NPDU to LS/UDP format.   

  Parameters:
    pNpdu:              On input, pointer to the LTVX NPDU.  This gets overwriten
                        by the V1 UDP payload.
    pduLen:             The size, in bytes of the LTVX NPDU
    pSourceAddr:        Pointer to recieve the IP source addresss, 
                        calculated from the address in the LTVX NPDU.
    pSourcePort:        Pointer to recieve the source port in *HOST* order
    pDestAddr:          Pointer to recieve the IP destination addresss, 
                        calculated from the address in the LTVX NPDU.
    pDestPort:          Pointer to recieve the dest port in *HOST* order
    lsMappingHandle:    A handle used for LS mapping 
*****************************************************************************/
uint16_t ipv6_convert_ltvx_to_ls_udp(uint8_t *pNpdu, uint16_t pduLen, 
                                     uint8_t *pSourceAddr, uint16_t *pSourcePort, 
                                     uint8_t *pDestAddr, uint16_t *pDestPort
#if IPV6_SUPPORT_ARBITRARY_ADDRESSES
                                   , void *lsMappingHandle
#endif
                                  );

/******************************************************************************
  Function:  ipv6_convert_ls_udp_to_ltvx
   
  Summary:
    Convert the LS/UDP packet found in the Contiki global uip_buf to an LTV0
    or LTV2 NPDU and return it in the buffer provided.

  Parameters:
    ipv6:               True if this is IPV6, false if IPV4
    pUdpPayload:        Pointer to the UDP data
    udpLen:             The length of the UDP data
    pSourceAddr:        Pointer to source address, in *network* order
    sourcePort:         Source port in *host* order
    pDestAddr:          Pointer to destination address, in *network* order
    destPort:           Destination port in *host* order
    pNpdu:              A pointer to a buffer to write the LTVX npdu.
    pLtVxLen:           A pointer to the size in bytes of the resulting NPDU.
    lsMappingHandle:    A handle used for LS mapping 
*****************************************************************************/
void ipv6_convert_ls_udp_to_ltvx(uint8_t ipv6, uint8_t *pUdpPayload, uint16_t udpLen,
                                 const uint8_t *pSourceAddr, uint16_t sourcPort,
                                 const uint8_t *pDestAddr, uint16_t destPort,
                                 uint8_t *pNpdu, uint16_t *pLtVxLen
#if IPV6_SUPPORT_ARBITRARY_ADDRESSES
                                 , void *lsMappingHandle
#endif
                              );

#if IPV6_SUPPORT_ARBITRARY_ADDRESSES


/******************************************************************************
  Function:  ipv6_send_multicast_announcement
   
  Summary:
    Send a multicast announcement that this device is using an arbitrary
    IP address.  This function contructs an LTV0 or LTV2 message and then calls the 
    utility function ipv6_send_announcement to do the actual send.

  Parameters:
    lsSenderHandle:     A handle to the callback object that implements
                        the send function.
    pDesiredIpAddress:  Pointer LS derived IP address that this device should
                        ideally use.
*****************************************************************************/
void ipv6_send_multicast_announcement(void *lsSenderHandle,
                                      const uint8_t *pDesiredIpAddress);


///////////////////////////////////////////////////////////////////////////////
//
// The following callback functions need to be provided by the upper layers 
// and called by the LS to UDP mapping layer.
//
///////////////////////////////////////////////////////////////////////////////

/******************************************************************************
  Function:  ipv6_send_announcement
   
  Summary:
    This callback is used to send an announcement message.  

  Parameters:
    lsSenderHandle: A handle to the callback object that implements the send 
                    function.
    ltVxMsg:        The announcement message, in LTV0 or LTV2 format.
    msgLen:         The message length.

*****************************************************************************/
void ipv6_send_announcement(void *lsSenderHandle, const uint8_t *ltVxMsg, uint8_t msgLen);

/******************************************************************************
  Function:  ipv6_get_arbitrary_source_address
   
  Summary:
    This callback is used to retrieve arbitrary IP address information 
    for a given source address.  

  Parameters:
    lsMappingHandle:        A handle used for LS mapping 
    pSourceIpAddress:       On input, a pointer the desired (LS derived) source 
                            IP address.  If this IP address cannot be used, 
                            pSourceIpAddress will be updated with the arbitrary
                            IP address to be used instead.
    pDomainId:              The LS domain ID.
    domainIdLen:            The length (in bytes) of the LS domain ID
    pEnclosedSource:        Pointer to a buffer to receive the necessary LS
                            source addressing information (in V1 format) to be 
                            added to the UDP payload, if any
  Return: 
    The length of the additional enclosed source address information

*****************************************************************************/
uint8_t ipv6_get_arbitrary_source_address(void *lsMappingHandle,
                                          uint8_t *pSourceIpAddress, 
                                          const uint8_t *pDomainId, int domainIdLen,
                                          uint8_t *pEnclosedSource);

/******************************************************************************
  Function:  ipv6_get_arbitrary_dest_address
   
  Summary:
    This callback is used to used by the ls to udp translation layers to retrieve 
    arbitrary IP address information for a given destination address.  

  Parameters:
    lsMappingHandle:        A handle used for LS mapping 
    pDomainId:              The LS domain ID.
    domainIdLen:            The length (in bytes) of the LS domain ID
    subnetId:               The LS destination subnet ID
    nodeId:                 The LS destination node ID
    ipv1AddrFmt:            The LS/IP address format
    pDestIpAddress:         Pointer to a buffer to receive the destination IP
                            address to be used.
    pEnclosedDest:          Pointer to a buffer to receive additional LS
                            destination address information enclosed in the
                            PDU, if any.
  Return: 
    The length of the additional enclosed destination address information
*****************************************************************************/
uint8_t ipv6_get_arbitrary_dest_address(void *lsMappingHandle,
                                        const uint8_t *pDomainId, uint8_t domainLen, 
                                        uint8_t subnetId, uint8_t nodeId, uint8_t ipv1AddrFmt,
                                        uint8_t *pDestIpAddress, uint8_t *pEnclosedDest);

/******************************************************************************
  Function:  ipv6_set_arbitrary_address_mapping
   
  Summary:
    This callback is used by the ls to udp translation layers to 
    inform the LS/IP mapping layers that a given LS address uses an
    arbitrary IP address.  

  Parameters:
    lsMappingHandle:        A handle used for LS mapping 
    pArbitraryIpAddr:       The arbitrary IP address to use when addressing
                            the LS device.
    pDomainId:              The LS domain ID.
    domainIdLen:            The length (in bytes) of the LS domain ID
    subnetId:               The LS subnet ID
    nodeId:                 The LS node ID

*****************************************************************************/
void ipv6_set_arbitrary_address_mapping(void *lsMappingHandle, const uint8_t *pArbitraryIpAddr, 
                                         const uint8_t *pDomainId, uint8_t domainLen, 
                                         uint8_t subnetId, uint8_t nodeId);

/******************************************************************************
  Function:  ipv6_set_derived_address_mapping
   
  Summary:
    This callback is used by the ls to udp translation layers to 
    inform the LS/IP mapping layers that a given LS address uses an
    LS derived IP address.  

  Parameters:
    lsMappingHandle:        A handle used for LS mapping 
    pDomainId:              The LS domain ID.
    domainIdLen:            The length (in bytes) of the LS domain ID
    subnetId:               The LS subnet ID
    nodeId:                 The LS node ID

*****************************************************************************/
void ipv6_set_derived_address_mapping(void *lsMappingHandle, 
                                      const uint8_t *pDomainId, uint8_t domainLen, 
                                      uint8_t subnetId, uint8_t nodeId);


/******************************************************************************
  Function:  ipv6_set_derived_subnets_mapping
   
  Summary:
    This callback is used by the ls to udp translation layers when an 
    SubnetsAddrMapping message is received.

  Parameters:
    lsMappingHandle:        A handle used for LS mapping 
    pDomainId:              The LS domain ID.
    domainIdLen:            The length (in bytes) of the LS domain ID
    set:                    True to set the derived mapping entries, clear to
                            clear the dervived mapping entries.
    pSubneteMap:            Pointer to a bit map of subnets to set or clear.

*****************************************************************************/
void ipv6_set_derived_subnets_mapping(void *lsMappingHandle, 
                                      const uint8_t *pDomainId, uint8_t domainLen, 
                                      uint8_t set, const uint8_t *pSubnets);

/******************************************************************************
  Function:  ipv6_is_unicast_address_supported
   
  Summary:
    This callback is used by the ls to udp translation layers to 
    determmine whether or not the specified IP address can be used by this
    device as a source address.

  Parameters:
    lsMappingHandle:        A handle used for LS mapping 
    ipAddress:              The LS domain ID.

*****************************************************************************/
uint8_t ipv6_is_unicast_address_supported(void *lsMappingHandle, const uint8_t *ipAddress);


#endif // IPV6_SUPPORT_ARBITRARY_ADDRESSES
#endif

/******************************************************************************
  Function:  ipv6_gen_compressed_arbitrary_udp_header
   
  Summary:
    Compress the arbitrary UDP packet to an LTV2 NPDU and return it in the buffer 
    provided.

  Parameters:
    pSourceAddr:        Pointer to source address, in *network* order
    sourcePort:         Source port in *host* order
    pDestAddr:          Pointer to destination address, in *network* order
    destPort:           Destination port in *host* order
    pMyDomain           Pointer to the domain to use
    myDomainLen         The length of the domain to use
    pNpduHeader:        A pointer to a buffer to write the LTV2 npdu header

  Return:
    The length of the NPDU header.  
*****************************************************************************/
uint8_t ipv6_gen_compressed_arbitrary_udp_header(const uint8_t *pSourceAddr, uint16_t sourcePort,
                                                 const uint8_t *pDestAddr, uint16_t destPort,
                                                 const uint8_t *pMyDomain, uint8_t myDomainLen,
                                                 uint8_t *pNpduHeader);

/******************************************************************************
  Function:  ipv6_find_arb_udp_header_offset
   
  Summary:
    Get the offset of an arbitrary udp header.

  Parameters:
    ltVersion:          Expected version.  
    pNpdu:              A pointer to a buffer containing the npdu
    fillSource:         If true, fill in the source address
    ppMyDomain          On return *ppMyDomain points to the domain ID
    pDomainLen          On return *pDomainLen is the domain ID length

  Return:
    The length of the NPDU header.  
*****************************************************************************/
uint8_t ipv6_find_arb_udp_header_offset(uint8_t ltVersion, 
                                        uint8_t *pNpdu, uint8_t fillSource,
                                        uint8_t **ppDomain, uint8_t *pDomainLen);

/******************************************************************************
  Function:  ipv6_inflate_arbitrary_udp_header
   
  Summary:
    Compress the arbitrary UDP packet to an LTV0 or LTV2 NPDU and return it in the buffer 
    provided.

  Parameters:
    pNpduHeader:        A pointer to a buffer containing the LTV2 npdu header
    pNpduHeaderLen:     On return, set the length of the ndpu header
    pArbUdpHeader:      A pointer to a buffer to return the inflated arbitrary
                        UDP header.

  Return:
    The offset of the UDP payload
*****************************************************************************/
uint8_t ipv6_inflate_arbitrary_udp_header(const uint8_t *pNpduHeader,
                                          uint8_t *pNpduHeaderLen, 
                                          Ipv6UdpAppMsgHdr *pArbUdpHeader);

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif
