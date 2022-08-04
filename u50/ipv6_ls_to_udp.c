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
 *    This file implements the translation between LonTalk V0 or V2 and LS/UDP
 *
 ***************************************************************************/

#if !defined USE_UIP && !defined U50_KERNEL
#include "LtaDefine.h"
#else
#define FEATURE_INCLUDED(x) 1
#endif

#if FEATURE_INCLUDED(IZOT)

#ifdef U50_KERNEL
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>
#include <asm/byteorder.h>
// Address Formats are based on those found in the LonTalk packet.
// These are used for incoming addresses.  The first 4 match
// the address formats used in the LonTalk packet.
typedef enum
{
    LT_AF_BROADCAST			= 0,
    LT_AF_GROUP				= 1,
    LT_AF_SUBNET_NODE		= 2,
    LT_AF_UNIQUE_ID			= 3,
    LT_AF_GROUP_ACK			= 4,
    LT_AF_TURNAROUND		= 5,
    LT_AF_NONE				= 6,	// indicates no address available
} LtAddressFormat;

#else
#include <stdio.h>
#include <string.h>
#ifdef USE_UIP
#include "net/uip.h"
#define htons(x) UIP_HTONS(x)

// Address Formats are based on those found in the LonTalk packet.
// These are used for incoming addresses.  The first 4 match
// the address formats used in the LonTalk packet.
typedef enum
{
    LT_AF_BROADCAST			= 0,
    LT_AF_GROUP				= 1,
    LT_AF_SUBNET_NODE		= 2,
    LT_AF_UNIQUE_ID			= 3,
    LT_AF_GROUP_ACK			= 4,
    LT_AF_TURNAROUND		= 5,
    LT_AF_NONE				= 6,	// indicates no address available
} LtAddressFormat;


#elif WIN32
#include <winsock.h>
#else
#include <netinet/ip.h>
#include <netinet/udp.h>
#endif

#ifndef USE_UIP
#include "types/vxTypesBase.h"		/* must come between vxArch/vxTypes */
#include "types/vxTypes.h"
#endif 
#endif
#include "ipv6_ls_to_udp.h"
#include "ipv6_console_support.h"

#ifdef USE_UIP
#include "net/uip-debug.h"
#endif

#ifndef IPV6_BACLON_MSG_CODE
// The message code used to send and receive BAKNET UDP messages
#define IPV6_BACLON_MSG_CODE       0x0E  // REMINDER:  Need to find out what the real value is!
#endif

#ifdef USE_UIP
// Access to Contiki global buffer.
#define UIP_IP_BUF                          ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF                        ((struct uip_udp_hdr *)&uip_buf[UIP_LLH_LEN + UIP_IPH_LEN])
#endif

// Encoded domain length
const uint8_t domainLengthTable[4] = { 0, 1, 3, 6 };

#if UIP_CONF_IPV6

// The Lontalk services multicast prefix which appears at offsets 8-13 of
// an LS MC adderess
const uint8_t ipv6_ls_multicast_prefix[] = 
{ 0x4C, 0x53, 0x49, 0x50, 0x56, 0x36 };

// Pointer to my IP prefix
uip_ds6_prefix_t *pIpv6LsDomainUipPrefix;

#else
const uint8_t ipv6_ls_multicast_prefix[] = { 0xEF, 0xC0 };
// The 2 byte IP prefix used to represent the 0 length domain
const uint8_t ipv6_zero_len_domain_prefix[] = { IPV6_DOMAIN_LEN_0_PREFIX_0, IPV6_DOMAIN_LEN_0_PREFIX_1};
#endif

///////////////////////////////////////////////////////////////////////////////
// 
// Functions
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
    pAddr:      Pointer to IPV6 address to store the prefix

*****************************************************************************/
void ipv6_gen_ls_prefix(const uint8_t *pDomainId, uint8_t domainLen, uint8_t subnet, uint8_t *pAddr)
{
#if UIP_CONF_IPV6
    memset(pAddr, 0, sizeof(uip_ipaddr_t));
    if (domainLen <= 6)
    {
        memcpy(pAddr, pDomainId, domainLen);
        pAddr += 7;
        *pAddr++ = subnet;
    }
#else
    memset(pAddr, 0, IPV4_ADDRESS_LEN);

    if (domainLen > 6)
    {
        // An invalid domain. Set node and subnet to 0.  Will use the zero length domain below.
        domainLen = 0;  
    }
    if (domainLen == 0)
    {
        memcpy(pAddr, ipv6_zero_len_domain_prefix, sizeof(ipv6_zero_len_domain_prefix));
    }
    else
    {
        if (domainLen == 1)
        {
            pAddr[0] = IPV6_DOMAIN_LEN_1_PREFIX;
            pAddr[1] = pDomainId[0];
        }
        else
        {
			// Mapping works with 3 byte domains where last byte is 0
            if ((domainLen == 3) && (pDomainId[2] == 0))
            {
                pAddr[0] = pDomainId[0];
                pAddr[1] = pDomainId[1];
            }
            else // AP-2655 'illegal domain mapping' to support 6 and 3 byte (were 3rd byte isn't 0)
            {    // We're re-using the 0 byte domain prefix for this.
                memcpy(pAddr, ipv6_zero_len_domain_prefix, sizeof(ipv6_zero_len_domain_prefix));
            }
        }
    }
    pAddr[IPV6_LSIP_UCADDR_OFF_SUBNET] = subnet;
#endif
}

/******************************************************************************
  Function:  ipv6_gen_ls_mc_addr
   
  Summary:
    Generate a multicast address for a LS broadcast or group address

  Parameters:
    type:           The multicast group type: IPV6_LS_MC_ADDR_TYPE_BROADCAST or
                    IPV6_LS_MC_ADDR_TYPE_GROUP
    pDomainId:      Pointer to the domain ID (IPV6 only)
    domainLen:      Length of the domain (0 to 6) (IPV6 only)
    subnetOrGroup:  LS subnet ID or group ID
    pAddr:      Pointer to IPV6 address to store the prefix

*****************************************************************************/
void ipv6_gen_ls_mc_addr(uint8_t type, 
#if UIP_CONF_IPV6
                         const uint8_t *pDomainId, uint8_t domainLen, 
#endif
                         uint8_t subnetOrGroup, uint8_t *pAddr)
{
#if UIP_CONF_IPV6
    memset(pAddr, 0, sizeof(uip_ipaddr_t));
    if (domainLen > IPV6_LSIP_IPADDR_DOMAIN_LEN)
    {
        domainLen = 0;  // No domain...
    }
    *pAddr++ = 0xff;
    *pAddr++ = 0x18;
    memcpy(pAddr, pDomainId, domainLen);
    pAddr += 6;
#endif
    memcpy(pAddr, ipv6_ls_multicast_prefix, sizeof(ipv6_ls_multicast_prefix));
    pAddr += sizeof(ipv6_ls_multicast_prefix);
    *pAddr++ = type;
    *pAddr++ = subnetOrGroup;
}

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
void ipv6_gen_ls_subnet_node_addr(const uint8_t *pDomainId, uint8_t domainLen, 
                                  uint8_t subnetId, uint8_t nodeId, uint8_t *pAddr)
{                                     
#if UIP_CONF_IPV6
    ipv6_gen_ls_prefix(pDomainId, domainLen, subnetId, pAddr);
    pAddr[15] = nodeId & 0x7f;
#else
    nodeId &= 0x7f ;
    if (domainLen > 6)
    {
        // An invalid domain. Set node  to 0.  Will use the zero length domain below.
        domainLen = 0;  
        nodeId = 0;
    }
    if (subnetId == 0 || nodeId == 0)
    {
        domainLen = 0;
    }
    ipv6_gen_ls_prefix(pDomainId, domainLen, subnetId, pAddr);

    pAddr[IPV6_LSIP_UCADDR_OFF_NODE] = nodeId;
#endif
}

uint8_t getDomainLenEncoding(int domainLen)
{
    uint8_t encodedLen;
    for (encodedLen = 0; encodedLen < sizeof(domainLengthTable)/sizeof(domainLengthTable[0]); encodedLen++)
    {
        if (domainLen == domainLengthTable[encodedLen])
        {
            return encodedLen;
        }
    }
    return 0;  // Whoops.
}

#if IPV6_INCLUDE_LTVX_LSUDP_TRANSLATION

/******************************************************************************
  Function:  ipv6_convert_ltvx_to_ls_udp
   
  Summary:
    Convert the LonTalk V0 or V2 NPDU to LS/UDP format.   

  Parameters:
    pNpdu:              On input, pointer to the LTV0 or LTV2 NPDU.  This gets overwriten
                        by the LS/UDP payload.
    pduLen:             The size, in bytes of the LTVX NPDU
    pSourceAddr:        Pointer to recieve the IP source addresss, 
                        calculated from the address in the LTVX NPDU.
    pSourcePort:        Pointer to recieve the source port.
    pDestAddr:          Pointer to recieve the IP destination addresss, 
                        calculated from the address in the LTVX NPDU.
    pDestPort:          Pointer to recieve the dest port.
    lsMappingHandle:    A handle used for LS mapping 
*****************************************************************************/
uint16_t ipv6_convert_ltvx_to_ls_udp(uint8_t *pNpdu, uint16_t pduLen, 
                                  uint8_t *pSourceAddr, uint16_t *pSourcePort, 
                                  uint8_t *pDestAddr, uint16_t *pDestPort
#if IPV6_SUPPORT_ARBITRARY_ADDRESSES
                                  , void *lsMappingHandle
#endif
                                  )
{
    uint8_t domainOffset = 0;
    LtAddressFormat lsVxAddrFmt = IPV6_GET_ADDRESS_FORMAT_FROM_NPDU(pNpdu);
    uint8_t domainLen = domainLengthTable[pNpdu[IPV6_LTVX_NPDU_IDX_TYPE] & IPV6_LTVX_NPDU_MASK_DOMAINLEN];
    uint8_t lsUdpHdrLen = 2; // Size of the LS/UDP HDR
    uint8_t lsUdpHdrByte1 = IPV6_GET_PDU_FORMAT_FROM_NPDU(pNpdu);  // Second byte of LS/UDP header
    uint8_t lsUdpEnclosedAddr[7];
    uint8_t lsUdpEnclosedAddrLen = 0;
    uint8_t failed = 0;
    uint8_t altPath = IPV6_GET_ALT_PATH_FROM_NPDU(pNpdu);  // AltPath bit from first byte of LTV NPDU (Byte 0)
    uint8_t pduHdrByte0 = pNpdu[0];
    
    // AP-2879
    // AltPath is added into Backlog info (BlInfo) field. 
    // This field is presesnt if and only if the MCR flag is 1
    if (altPath)
    {    
        lsUdpHdrByte1 |= IPV6_LSUDP_NPDU_MASK_MCR;
        lsUdpHdrLen += 1;  // Add room for backlog info.
    }
    
    if (!IPV6_LT_IS_VER_LS_LEGACY_MODE(pNpdu[IPV6_LTVX_NPDU_IDX_TYPE]) &&
        !IPV6_LT_IS_VER_LS_ENHANCED_MODE(pNpdu[IPV6_LTVX_NPDU_IDX_TYPE]))
    {
        failed = 1; // Version is not supported;
    }
    else
    {
        switch (lsVxAddrFmt)
        {
        case LT_AF_BROADCAST:
        case LT_AF_GROUP:
            {
                domainOffset = IPV6_LTVX_NPDU_IDX_DEST_ADDR+1;
                ipv6_gen_ls_mc_addr(lsVxAddrFmt == LT_AF_BROADCAST ?  IPV6_LS_MC_ADDR_TYPE_BROADCAST : IPV6_LS_MC_ADDR_TYPE_GROUP,
    #if UIP_CONF_IPV6
                                   &pNpdu[IPV6_LTVX_NPDU_IDX_DEST_ADDR+1], domainLen,
    #endif
                                   pNpdu[IPV6_LTVX_NPDU_IDX_DEST_ADDR],  pDestAddr);
                 // AP-2879
                if ((((lsUdpHdrByte1 & IPV6_LSUDP_NPDU_MASK_PDUFMT) == ENCLOSED_PDU_TYPE_TPDU) || 
                        ((lsUdpHdrByte1 & IPV6_LSUDP_NPDU_MASK_PDUFMT) == ENCLOSED_PDU_TYPE_SPDU)) &&
                        ((pNpdu[4 + domainLen] & IPV6_LTVX_NPDU_MASK_SERVICE_TYPE) == 0) &&
                        !altPath)
                {
                    // AP-2879 Either an ackd, request service or any alt path message.  Include 
                    lsUdpHdrByte1 |= IPV6_LSUDP_NPDU_MASK_MCR;
                    lsUdpHdrLen += 1;  // Add room for backlog  info.
                }

                if (lsVxAddrFmt == LT_AF_BROADCAST)
                {
                    if (pNpdu[IPV6_LTVX_NPDU_IDX_DEST_SUBNET] == 0)
                    {
                        lsUdpHdrByte1 |= IPV6_LSUDP_NPDU_ADDR_FMT_DOMAIN_BROADCAST;
                    }
                    else
                    {
                        lsUdpHdrByte1 |= IPV6_LSUDP_NPDU_ADDR_FMT_SUBNET_BROADCAST;
                        lsUdpEnclosedAddrLen = 1;    // add room for subnetId
                        lsUdpEnclosedAddr[0] = pNpdu[IPV6_LTVX_NPDU_IDX_DEST_ADDR];
                    }
                }
                else
                {
                    lsUdpEnclosedAddrLen = 1;    // add room for groupID
                    lsUdpHdrByte1 |= IPV6_LSUDP_NPDU_ADDR_FMT_GROUP;
                    lsUdpEnclosedAddr[0] = pNpdu[IPV6_LTVX_NPDU_IDX_DEST_ADDR];
                }
            }
            break;
        case LT_AF_SUBNET_NODE:

            {
                uint8_t lsUdpAddrFmt;
                if (pNpdu[IPV6_LTVX_NPDU_IDX_SOURCE_NODE] & 0x80)
                {
                    lsUdpAddrFmt = IPV6_LSUDP_NPDU_ADDR_FMT_SUBNET_NODE;
                    domainOffset = IPV6_LTVX_NPDU_IDX_DEST_NODE+1;
                }
                else
                {
                    lsUdpAddrFmt = IPV6_LSUDP_NPDU_ADDR_FMT_GROUP_RESP;
                    domainOffset = IPV6_LTVX_NPDU_IDX_DEST_NODE+3;
                }

                ipv6_gen_ls_subnet_node_addr(&pNpdu[domainOffset], domainLen, 
                                             pNpdu[IPV6_LTVX_NPDU_IDX_DEST_SUBNET], pNpdu[IPV6_LTVX_NPDU_IDX_DEST_NODE],
                                             pDestAddr);
    #if IPV6_SUPPORT_ARBITRARY_ADDRESSES
                if (ipv6_get_arbitrary_dest_address(lsMappingHandle, &pNpdu[domainOffset], domainLen, 
                                             pNpdu[IPV6_LTVX_NPDU_IDX_DEST_SUBNET], pNpdu[IPV6_LTVX_NPDU_IDX_DEST_NODE],
                                             lsUdpAddrFmt, pDestAddr, lsUdpEnclosedAddr))
                {
                    lsUdpEnclosedAddrLen += 2;
                    lsUdpAddrFmt = IPV6_LSUDP_NPDU_ADDR_FMT_EXP_SUBNET_NODE;
                }
    #endif
                if ((pNpdu[IPV6_LTVX_NPDU_IDX_SOURCE_NODE] & 0x80) == 0)
                {
                    // Group response.  Add in the grop and member.
                    lsUdpEnclosedAddr[lsUdpEnclosedAddrLen++] = pNpdu[IPV6_LTVX_NPDU_IDX_RESP_GROUPID];
                    lsUdpEnclosedAddr[lsUdpEnclosedAddrLen++] = pNpdu[IPV6_LTVX_NPDU_IDX_RESP_GROUPMBR];
                }
                lsUdpHdrByte1 |= lsUdpAddrFmt; 
            }

            break;
        case LT_AF_UNIQUE_ID:
            domainOffset = IPV6_LTVX_NPDU_IDX_DEST_NEURON_ID + IPV6_LTVX_NPDU_DEST_NEURON_ID_LEN;
    #if UIP_CONF_IPV6
            if (pNpdu[IPV6_LTVX_NPDU_IDX_DEST_SUBNET])
            {
                // Unicast neuron ID addressing
    NEURON_IPV6_WARNOFF_NO_EFFECT
                lsUdpHdrByte1 |= IPV6_LSUDP_NPDU_ADDR_FMT_NEURON_ID;
    NEURON_IPV6_WARNON_NO_EFFECT
    #if UIP_CONF_IPV6
                ipv6_gen_ls_neuronid_addr(&pNpdu[domainOffset], domainLen, 
                                          pNpdu[IPV6_LTVX_NPDU_IDX_DEST_SUBNET], &pNpdu[IPV6_LTVX_NPDU_IDX_DEST_NEURON_ID],
                                           pDestAddr);
    #endif
            }
            else
    #endif
            {
                // Subnet is 0. This is a neuron ID addressed message that floods the network.
                // Use the broadcast address and include the NEURON ID in the payload
                lsUdpHdrByte1 |= IPV6_LSUDP_NPDU_ADDR_FMT_BROADCAST_NEURON_ID;
                ipv6_gen_ls_mc_addr(IPV6_LS_MC_ADDR_TYPE_BROADCAST, 
    #if UIP_CONF_IPV6
                                   &pNpdu[domainOffset], domainLen,
    #endif
                                   0,  pDestAddr);
                lsUdpEnclosedAddrLen = IPV6_LTVX_NPDU_DEST_NEURON_ID_LEN + 1;  // add room for subnetID and neuronID
                lsUdpEnclosedAddr[0] = pNpdu[IPV6_LTVX_NPDU_IDX_DEST_SUBNET];
                memcpy(&lsUdpEnclosedAddr[1], &pNpdu[IPV6_LTVX_NPDU_IDX_DEST_NEURON_ID], IPV6_LTVX_NPDU_DEST_NEURON_ID_LEN);
            }
            break;
        default:
            // Unsupported adress type
            failed = 1;
        };
    }

    if (!failed)
    {
        uint8_t arbitrarySourceAddressLen = 0;
        uint8_t arbitrarySourceAddress[IPV6_MAX_ARBITRARY_SOURCE_ADDR_LEN];
        // Copy the enclosed PDU following the LS/UDP header
        pduLen -= domainOffset+domainLen;
        if (pSourceAddr != NULL)
        {
            ipv6_gen_ls_prefix(&pNpdu[domainOffset], domainLen,  pNpdu[IPV6_LTVX_NPDU_IDX_SOURCE_SUBNET], pSourceAddr);
			pSourceAddr[IPV6_LSIP_UCADDR_OFF_NODE] = pNpdu[IPV6_LTVX_NPDU_IDX_SOURCE_NODE] & 0x7f;
        }

        if (pNpdu[0] & IPV6_LTVX_NPDU_MASK_PRIORITY)
        {
            lsUdpHdrByte1 |= (1 << IPV6_LSUDP_NPDU_BITPOS_PRIORITY);
        }
        // Set the version to use LS legacy or enhanced mode based on the LT version.
        if (IPV6_LT_IS_VER_LS_LEGACY_MODE(pNpdu[IPV6_LTVX_NPDU_IDX_TYPE]))
        {
            pNpdu[0] = IPV6_LSUDP_UDP_VER_LS_LEGACY << IPV6_LSUDP_NPDU_BITPOS_UDPVER;
        }
        else
        {
            pNpdu[0] = IPV6_LSUDP_UDP_VER_LS_ENHANCED << IPV6_LSUDP_NPDU_BITPOS_UDPVER;
        }
        // AP-2655 Handle 'illegal domains' by re-using the SRC field, and including the
        // full domain.  Set the 'unmapped' bit, to indicate it's present, but not really an
        // arbitrary address.
        if ((domainLen == 3) || (domainLen == 6))
        {
            uint8_t *pDomainId = &pNpdu[domainOffset];
            if ((domainLen != 3) || (pDomainId[2] != 0))
            {
                // Populate the SRC field with the info from the NPDU
                int encodedDomainLen = 0;
                arbitrarySourceAddressLen = IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_DM + domainLen;
                switch (domainLen)
                {
                    case 1: encodedDomainLen = 1; break;
                    case 3: encodedDomainLen = 2; break;
                    case 6: encodedDomainLen = 3; break;
                }
                arbitrarySourceAddress[IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_DMLEN] = encodedDomainLen;
                memcpy(&arbitrarySourceAddress[IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_DM], pDomainId, domainLen);
                
                // Using an arbitrary address. Include the source subnet/node
                arbitrarySourceAddress[IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_SUBNET] = pSourceAddr[IPV6_LSIP_UCADDR_OFF_SUBNET];
                arbitrarySourceAddress[IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_NODE] = pSourceAddr[IPV6_LSIP_UCADDR_OFF_NODE] & 0x7f;
                // Domain is included, so set the flag
                arbitrarySourceAddress[IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_DMFLAG] |= IPV6_LSUDP_NPDU_MASK_ARB_SOURCE_DMFLG;

                pNpdu[0] |= IPV6_LSUDP_NPDU_MASK_UNMAPPED;
            }
        }
        else
        {
#if IPV6_SUPPORT_ARBITRARY_ADDRESSES
            {
                arbitrarySourceAddressLen = 
                    ipv6_get_arbitrary_source_address(lsMappingHandle, pSourceAddr, 
                                                      &pNpdu[domainOffset], domainLen, 
                                                      arbitrarySourceAddress);
            }
            if (arbitrarySourceAddressLen)
            {
                pNpdu[0] |= IPV6_LSUDP_NPDU_MASK_ARB_SOURCE;
            }
#endif
        }
        memmove(&pNpdu[lsUdpHdrLen+lsUdpEnclosedAddrLen+arbitrarySourceAddressLen], &pNpdu[domainOffset+domainLen], pduLen);
        if (arbitrarySourceAddressLen)
        {
            memcpy(&pNpdu[lsUdpHdrLen], arbitrarySourceAddress, arbitrarySourceAddressLen);
            lsUdpHdrLen += arbitrarySourceAddressLen;
        }
        if (lsUdpHdrByte1 & IPV6_LSUDP_NPDU_MASK_MCR)
        {
            // AP-2879
            // Copy delta backlog and Alt-path
            // Alt-path is added as part of BlInfo (Backlog info field).  The BlInfo field is present
            // if and only if the MCRflag is 1
            pNpdu[IPV6_LSUDP_NPDU_IDX_BLINFO] = (pduHdrByte0 & IPV6_LTVX_NPDU_MASK_DELTA_BACKLOG) |
                                            (pduHdrByte0 & IPV6_LTVX_NPDU_MASK_ALT_PATH);
        }

        pNpdu[1] = lsUdpHdrByte1;
        memcpy(&pNpdu[lsUdpHdrLen], lsUdpEnclosedAddr, lsUdpEnclosedAddrLen);
        lsUdpHdrLen += lsUdpEnclosedAddrLen;
        *pSourcePort = *pDestPort = IPV6_LS_UDP_PORT;
    }
    else
    {
        pduLen = 0;
        lsUdpHdrLen = 0;
    }

    return pduLen+lsUdpHdrLen;

}

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
                              )
{
    uint8_t *pLsUdpPayload = pUdpPayload;
    uint8_t *p = pNpdu;
    uint8_t npduHdr;
    uint8_t lsUdpHdr0 = 0; // First byte of LS/UDP header.
    uint8_t lsUdpHdr1;   // Second byte of LS/UDP header
    uint8_t domainLen;
    const uint8_t *pDomain;
    uint8_t failed = 0;

    if (ipv6)
    {
        failed = 1;
        //printf("ipv6 is not supported yet\n");
    }
    else
    {
        if (memcmp(pDestAddr, ipv6_ls_multicast_prefix, sizeof(ipv6_ls_multicast_prefix)) == 0)
        {
            // Destination is group or broadcast - use source for domain.
            // REMINDER:  For IPV6, multicast should have domain in prefix - so we can still use it,
            // Only use source if dest is a unique ID.
           pDomain = pSourceAddr;
           //printf("Source = %x %x\n", *pSourceAddr, *(pSourceAddr+1));
        }
        else
        {
            pDomain = pDestAddr;
            //printf("Dest = %c %c\n", *pDestAddr, *(pDestAddr+1));
        }

        if ((*pLsUdpPayload & IPV6_LSUDP_NPDU_MASK_UDPVER) > 
            (IPV6_LSUDP_UDP_VER_CURRENT << IPV6_LSUDP_NPDU_BITPOS_UDPVER))
        {
            // Unsupported version.  Drop it.
            failed = 1;
        }
#if !IPV6_SUPPORT_ARBITRARY_ADDRESSES
        else if (*pLsUdpPayload & IPV6_LSUDP_NPDU_MASK_ARB_SOURCE)
        {
            // Unsupported version.  Drop it.
            failed = 1;
        }
#endif
        else
        {
            lsUdpHdr0 = *pLsUdpPayload;
            pLsUdpPayload++;
            lsUdpHdr1 = *pLsUdpPayload++;
            *p = (lsUdpHdr1 & IPV6_LSUDP_NPDU_MASK_PRIORITY) ? IPV6_LTVX_NPDU_MASK_PRIORITY : 0;
            if (lsUdpHdr1 & IPV6_LSUDP_NPDU_MASK_MCR)
            {
                // AP-2879
                *p |= (*pLsUdpPayload & IPV6_LSUDP_NPDU_MASK_DELTA_BACKLOG) |
                      (*pLsUdpPayload & IPV6_LTVX_NPDU_MASK_ALT_PATH);
                pLsUdpPayload++;                      
            }
        }
    }


    if (!failed)
    {
        // Set version (0), pdu format and domain length
        npduHdr = ((lsUdpHdr1 & IPV6_LSUDP_NPDU_MASK_PDUFMT) << IPV6_LTVX_NPDU_BITPOS_PDUFMT);
        if ((lsUdpHdr0 & IPV6_LSUDP_NPDU_MASK_UDPVER) == 
            (IPV6_LSUDP_UDP_VER_LS_ENHANCED << IPV6_LSUDP_NPDU_BITPOS_UDPVER))
        {
            // Whoops, need to set the LT version to enhanced mode.
            npduHdr |= (IPV6_LT_VER_ENHANCED << IPV6_LTVX_NPDU_BITPOS_VER);
        }
        domainLen = 0xff;
        // We use the SRC field for either arbitrary addressing, or 6 byte domain on IPV4 support.
        // If arbitrary addressing is compiled out, we still need most of the code for the 
        // AP-2655 unmapped domains case.
        if (lsUdpHdr0 & IPV6_LSUDP_NPDU_MASK_ARB_SOURCE) 
        {
#if IPV6_SUPPORT_ARBITRARY_ADDRESSES
            if (pLsUdpPayload[IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_DMFLAG] & IPV6_LSUDP_NPDU_MASK_ARB_SOURCE_DMFLG)
            {
                domainLen = domainLengthTable[pLsUdpPayload[IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_DMLEN] & IPV6_LSUDP_NPDU_MASK_ARB_SOURCE_DMLEN];
                pDomain = &pLsUdpPayload[IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_DM];
            }
            else
            {
                pDomain = pSourceAddr;
            }
#else
            failed = 1;
#endif
        } 
        else if ((lsUdpHdr1 & IPV6_LSUDP_NPDU_MASK_ADDRFMT) == IPV6_LSUDP_NPDU_ADDR_FMT_EXP_SUBNET_NODE)
        {
            pDomain = pSourceAddr;
        }

        if (domainLen == 0xff)
        {
            // The domain is not included in arbitrary source address.  Need to extract it from source or dest addr.
            if (memcmp(pDomain, ipv6_zero_len_domain_prefix, sizeof(ipv6_zero_len_domain_prefix)) == 0)
            {
                domainLen = 0;
            }
            else if (pDomain[0] == IPV6_DOMAIN_LEN_1_PREFIX)
            {
                domainLen = 1;
                pDomain++;  // Skip first byte...
            }
            else 
            {
                domainLen = 3;
            }
        }
        npduHdr |= getDomainLenEncoding(domainLen);
        p += 2;  // Skip over delta backlog and npuHdr;

        if ((lsUdpHdr0 & IPV6_LSUDP_NPDU_MASK_ARB_SOURCE) || (lsUdpHdr0 & IPV6_LSUDP_NPDU_MASK_UNMAPPED))
        {
            // Update arbitrary address info
#if IPV6_SUPPORT_ARBITRARY_ADDRESSES
            if (lsUdpHdr0 & IPV6_LSUDP_NPDU_MASK_ARB_SOURCE)
            {
                ipv6_set_arbitrary_address_mapping(lsMappingHandle, pSourceAddr, 
                                                   pDomain, domainLen, pLsUdpPayload[0], pLsUdpPayload[1]&0x7f);
            }
#endif
            *p++ = pLsUdpPayload[IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_SUBNET];
            *p++ = 0x80 | pLsUdpPayload[IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_NODE];
            // Skip source address.
            if (pLsUdpPayload[IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_DMFLAG] & IPV6_LSUDP_NPDU_MASK_ARB_SOURCE_DMFLG)
            {
                pLsUdpPayload += domainLen + IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_DM;
            }
            else
            {
                pLsUdpPayload += IPV6_LSUDP_NPDU_OFF_ARB_SOURCE_DMLEN;
            }
        }
        else
        {
#if IPV6_SUPPORT_ARBITRARY_ADDRESSES
            ipv6_set_derived_address_mapping(lsMappingHandle, pDomain, domainLen, 
                                             pSourceAddr[IPV6_LSIP_UCADDR_OFF_SUBNET], pSourceAddr[IPV6_LSIP_UCADDR_OFF_NODE]&0x7f);
#endif
            *p++ = pSourceAddr[IPV6_LSIP_UCADDR_OFF_SUBNET];
            *p++ = 0x80 | pSourceAddr[IPV6_LSIP_UCADDR_OFF_NODE];
        }

        switch(lsUdpHdr1 & IPV6_LSUDP_NPDU_MASK_ADDRFMT)
        {
#if UIP_CONF_IPV6
        case IPV6_LSUDP_NPDU_ADDR_FMT_NEURON_ID:
            npduHdr |= (ADDR_FORMAT_NEURONID << IPV6_LTVX_NPDU_BITPOS_ADDRTYPE);
            *p++ = UIP_IP_BUF->destipaddr.u8[IPV6_LSIP_UCADDR_OFF_SUBNET];
            memcpy(p, &UIP_IP_BUF->destipaddr.u8[IPV6_LSIP_UCADDR_OFF_NIDHI], IPV6_LSIP_UCADDR_NID_HILEN);
            *p = (*p << 2) | (*p >> 6);  // Move "local/group" bits to high byte of neuron ID.
            p += IPV6_LSIP_UCADDR_NID_HILEN;
            memcpy(p, &UIP_IP_BUF->destipaddr.u8[IPV6_LSIP_UCADDR_OFF_NIDLO], IPV6_LSIP_UCADDR_NID_LOLEN);
            p += IPV6_LSIP_UCADDR_NID_LOLEN;
            break;
#endif
        case IPV6_LSUDP_NPDU_ADDR_FMT_BROADCAST_NEURON_ID:

            npduHdr |= (LT_AF_UNIQUE_ID << IPV6_LTVX_NPDU_BITPOS_ADDRTYPE);
            *p++ = *pLsUdpPayload++;
            memcpy(p, pLsUdpPayload, IPV6_LTVX_NPDU_DEST_NEURON_ID_LEN);
            p += IPV6_LTVX_NPDU_DEST_NEURON_ID_LEN;
            pLsUdpPayload += IPV6_LTVX_NPDU_DEST_NEURON_ID_LEN;
            break;

        case IPV6_LSUDP_NPDU_ADDR_FMT_SUBNET_NODE:
        case IPV6_LSUDP_NPDU_ADDR_FMT_GROUP_RESP:
            
            npduHdr |= (LT_AF_SUBNET_NODE << IPV6_LTVX_NPDU_BITPOS_ADDRTYPE);
            *p++ = pDestAddr[IPV6_LSIP_UCADDR_OFF_SUBNET];
            *p++ = 0x80 | pDestAddr[IPV6_LSIP_UCADDR_OFF_NODE];
            if ((lsUdpHdr1 & IPV6_LSUDP_NPDU_MASK_ADDRFMT) == IPV6_LSUDP_NPDU_ADDR_FMT_SUBNET_NODE)
            {
                break; 
            }
            pNpdu[IPV6_LTVX_NPDU_IDX_SOURCE_NODE] = pNpdu[IPV6_LTVX_NPDU_IDX_SOURCE_NODE] & 0x7f;  // Strip hi bit to indicate group response
            *p++ = *pLsUdpPayload++;
            *p++ = *pLsUdpPayload++;
            break; 

        case IPV6_LSUDP_NPDU_ADDR_FMT_DOMAIN_BROADCAST:
NEURON_IPV6_WARNOFF_NO_EFFECT
            npduHdr |= (LT_AF_BROADCAST << IPV6_LTVX_NPDU_BITPOS_ADDRTYPE);
NEURON_IPV6_WARNON_NO_EFFECT
            *p++ = 0;
           break;

        case IPV6_LSUDP_NPDU_ADDR_FMT_SUBNET_BROADCAST:
NEURON_IPV6_WARNOFF_NO_EFFECT
            npduHdr |= (LT_AF_BROADCAST << IPV6_LTVX_NPDU_BITPOS_ADDRTYPE);
NEURON_IPV6_WARNON_NO_EFFECT
            *p++ = *pLsUdpPayload++;
            break;

        case IPV6_LSUDP_NPDU_ADDR_FMT_GROUP:
            npduHdr |= (LT_AF_GROUP << IPV6_LTVX_NPDU_BITPOS_ADDRTYPE);
            *p++ = *pLsUdpPayload++; // Note that this should be the same as UIP_IP_BUF->destipaddr.u8[IPV6_LSIP_MCADDR_OFF_GROUP]
            break;
        case IPV6_LSUDP_NPDU_ADDR_FMT_EXP_SUBNET_NODE:
            npduHdr |= (LT_AF_SUBNET_NODE << IPV6_LTVX_NPDU_BITPOS_ADDRTYPE);
            *p++ = *pLsUdpPayload++;           // Subnet ID
            *p++ = 0x80 | *pLsUdpPayload;      // Node ID
            if (*pLsUdpPayload++ & 0x80)
            {
                pNpdu[IPV6_LTVX_NPDU_IDX_SOURCE_NODE] &= 0x7f;  // Strip hi bit to indicate group response
                *p++ = *pLsUdpPayload++;   // Group ID
                *p++ = *pLsUdpPayload++;   // Group member
            }
            break;
        default:
            // Unknown address type
             failed = 1;
             break;
        }
    }

    if (failed)
    {
        *pLtVxLen = 0;
    }
    else
    {
        uint16_t pduLen;
        // Calculate the pduLen by subtracting the UDP payload and LS/UDP headers from udplen.
        pduLen = udpLen - (pLsUdpPayload - pUdpPayload);

        pNpdu[IPV6_LTVX_NPDU_IDX_TYPE] = npduHdr;
        memcpy(p, pDomain, domainLen);
#if !UIP_CONF_IPV6
        // IPV4 address doesn not include the LSB of the domain, which MBZ
        if (!(lsUdpHdr0 & IPV6_LSUDP_NPDU_MASK_UNMAPPED))
        {
            if (domainLen > IPV6_LSIP_IPADDR_DOMAIN_LEN)
            {
                memset(p+IPV6_LSIP_IPADDR_DOMAIN_LEN, 0, domainLen-IPV6_LSIP_IPADDR_DOMAIN_LEN);
            }
        }
#endif
        p += domainLen;
#if IPV6_SUPPORT_ARBITRARY_ADDRESSES
        if (
        		(lsUdpHdr1 & IPV6_LSUDP_NPDU_MASK_ADDRFMT) == IPV6_LSUDP_NPDU_ADDR_FMT_EXP_SUBNET_NODE &&
            (((lsUdpHdr1 & IPV6_LSUDP_NPDU_MASK_PDUFMT) == ENCLOSED_PDU_TYPE_APDU) ||
             (((lsUdpHdr1 & IPV6_LSUDP_NPDU_MASK_PDUFMT) == ENCLOSED_PDU_TYPE_TPDU) &&
              (*pLsUdpPayload & IPV6_LTVX_NPDU_MASK_SERVICE_TYPE) == IPV6_LTVX_NPDU_TPDU_TYPE_REPEATED))
			  )
        {
            // An unacked or repeated message that uses LS subnet node addressing, but includes the
            // subnet/node address expliicitly. We won't be sending an ack or response, so even if there
            // is a better address to use the sending device won't learn it. 

            // Note that it should be sufficient to determine whether a unicast or multicast address 
            // was used.  However, sockets doesn't really provide that information, so we can't always tell.
            // So generate the ls derived IP address, and see if it is supported, and send the announcement
            // in that case as well.

#if UIP_CONF_IPV6
            uint8_t lsDerivedAddr[16];
#else
            uint8_t lsDerivedAddr[4];
#endif
            // we know that the Vx message uses subnet node address, so we know where the domain ID is.
            ipv6_gen_ls_subnet_node_addr(&pNpdu[IPV6_LTVX_NPDU_IDX_DEST_NODE+1], domainLen, 
                                         pNpdu[IPV6_LTVX_NPDU_IDX_DEST_SUBNET], pNpdu[IPV6_LTVX_NPDU_IDX_DEST_NODE],
                                         lsDerivedAddr);

            if (memcmp(pDestAddr, ipv6_ls_multicast_prefix, sizeof(ipv6_ls_multicast_prefix)) == 0 ||
                ipv6_is_unicast_address_supported(lsMappingHandle, lsDerivedAddr))
            {
                uint8_t msg[IPV6_MAX_LTVX_UNICAST_ARB_ANNOUNCE_LEN];
                uint8_t len = 0;
                msg[len++] = 0;     // Pri, altpath backlog

                // version, pdu fmt, addfmt, domain len
                msg[len++] = (ENCLOSED_PDU_TYPE_APDU << IPV6_LTVX_NPDU_BITPOS_PDUFMT) |
                             (LT_AF_SUBNET_NODE << IPV6_LTVX_NPDU_BITPOS_ADDRTYPE) |
                              (pNpdu[IPV6_LTVX_NPDU_IDX_TYPE] & IPV6_LTVX_NPDU_MASK_DOMAINLEN);

                // souce address
                msg[len++] = pNpdu[IPV6_LTVX_NPDU_IDX_DEST_SUBNET];
                msg[len++] = pNpdu[IPV6_LTVX_NPDU_IDX_DEST_NODE] | 0x80;
                // dest address
                msg[len++] = pNpdu[IPV6_LTVX_NPDU_IDX_SOURCE_SUBNET];
                msg[len++] = pNpdu[IPV6_LTVX_NPDU_IDX_SOURCE_NODE];
                // domain ID
                memcpy(&msg[len], &pNpdu[IPV6_LTVX_NPDU_IDX_DEST_NODE+1], domainLen);
                len += domainLen;
                msg[len++] = IPV6_EXP_MSG_CODE;  
                msg[len++] = IPV6_EXP_DEVICE_LS_ADDR_MAPPING_ANNOUNCEMENT;
                ipv6_send_announcement(lsMappingHandle, msg, len);                
            }
        }

        // Check for IPV6_EXP_SUBNETS_LS_ADDR_MAPPING_ANNOUNCEMENT
        if ((lsUdpHdr1 & IPV6_LSUDP_NPDU_MASK_PDUFMT) == ENCLOSED_PDU_TYPE_APDU &&
            pLsUdpPayload[0] == IPV6_EXP_MSG_CODE && pduLen >= (3+32) &&
            pLsUdpPayload[1] == IPV6_EXP_SUBNETS_LS_ADDR_MAPPING_ANNOUNCEMENT)
        {
            // This is IPV6_EXP_SUBNETS_LS_ADDR_MAPPING_ANNOUNCEMENT announcement;
            ipv6_set_derived_subnets_mapping(lsMappingHandle, p - domainLen, domainLen, pLsUdpPayload[2], &pLsUdpPayload[3]);
        }
#endif
        memcpy(p, pLsUdpPayload, pduLen);

        // LTVX len is pduLen + NPDU header len.
        *pLtVxLen = pduLen + (p-pNpdu);
    }
}

#if IPV6_SUPPORT_ARBITRARY_ADDRESSES
/******************************************************************************
  Function:  ipv6_send_multicast_announcement
   
  Summary:
    Send a multicast announcement that this device is using an arbitrary
    IP address.  This function contructs the message and then calls the 
    utility function ipv6_send_announcement to do the actual send.

  Parameters:
    lsSenderHandle:     A handle used for sending messages 
    pDesiredIpAddress:  Pointer LS derived IP address that this device should
                        ideally use.
*****************************************************************************/
void ipv6_send_multicast_announcement(void *lsSenderHandle,
                                      const uint8_t *pDesiredIpAddress)
{
    uint8_t msg[IPV6_MAX_LTVX_BROADCAST_ARB_ANNOUNCE_LEN];
    uint8_t len = 0;
    uint8_t encodedDomainLen;
    const uint8_t *pDomainId = pDesiredIpAddress;
    msg[len++] = 0;     // Pri, altpath backlog

    // The domain is not included in arbitrary source address.  Need to extract it from source or dest addr.
#if UIP_CONF_IPV6
    encodedDomainLen = 3;
#else
    if (memcmp(pDesiredIpAddress, ipv6_zero_len_domain_prefix, sizeof(ipv6_zero_len_domain_prefix)) == 0)
    {
        encodedDomainLen = 0;
    }
    else if (pDesiredIpAddress[0] == IPV6_DOMAIN_LEN_1_PREFIX)
    {
        encodedDomainLen = 1;   // 1 byte domain
        pDomainId++;  // Skip the first byte.
    }
    else 
    {
        encodedDomainLen = 2;   // 6 byte domain
    }
#endif
    // version, pdu fmt, addfmt, domain len
    msg[len++] = (ENCLOSED_PDU_TYPE_APDU << IPV6_LTVX_NPDU_BITPOS_PDUFMT) |
                 (LT_AF_BROADCAST << IPV6_LTVX_NPDU_BITPOS_ADDRTYPE) |
                  encodedDomainLen;

    // source address
    msg[len++] = pDesiredIpAddress[IPV6_LSIP_UCADDR_OFF_SUBNET];
    msg[len++] = pDesiredIpAddress[IPV6_LSIP_UCADDR_OFF_NODE] | 0x80;
    // dest subnet - domain wide broadcast uses 0.
    msg[len++] = 0;
    // domain ID
#if UIP_CONF_IPV6
    memcpy(&msg[len], pDesiredIpAddress, IPV6_LSIP_IPADDR_DOMAIN_LEN);
    len += IPV6_LSIP_IPADDR_DOMAIN_LEN;
#else
    // it just so happens that for IPV4 the encoded domain LEN is also equal to the number of
    // bytes to copy.
    memcpy(&msg[len], pDomainId, encodedDomainLen);
    len += encodedDomainLen;
    if (encodedDomainLen == 2)
    {
        msg[len++] = 0; // Last byte is 0.
    }
#endif
    msg[len++] = IPV6_EXP_MSG_CODE;
    msg[len++] = IPV6_EXP_DEVICE_LS_ADDR_MAPPING_ANNOUNCEMENT; 
    ipv6_send_announcement(lsSenderHandle, msg, len);    
}
#endif

#endif

uint8_t ipv6_is_valid_ls_derived_ip_address(const uint8_t *pAddr)
{
    uint8_t valid = 1;
    if (memcmp(pAddr, ipv6_ls_multicast_prefix, sizeof(ipv6_ls_multicast_prefix)) != 0)
    {
        if (pAddr[IPV6_LSIP_UCADDR_OFF_SUBNET] == 0 || 
            pAddr[IPV6_LSIP_UCADDR_OFF_NODE] == 0 || 
            pAddr[IPV6_LSIP_UCADDR_OFF_NODE] > 127)
        {
            valid = 0;
        }
        else
        {
#if UIP_CONF_IPV6
            if (pAddr[0] == 0xff && pAddr[1] == 0x02)
            {
                // a multicast address that doesn't corresponde to an LS address
                valid = 0;
            }
#else
            if ((pAddr[0] & 224) == 224)
            {
                // a multicast or broadcast address that doesn't corresponde to an LS address
                valid = 0;
            }
#endif
        }
    }

    return valid;
}

uint8_t ipv6_ip_domain_differences(const uint8_t *pIpAddr, const uint8_t *pDomain, int domainLen)
{
    uint8_t domainDifferences = IPV6_LSIP_IPADDR_DOMAIN_LEN;
    int i;
    uint8_t prefix[IPV6_LSIP_IPADDR_DOMAIN_LEN];
    memset(prefix, 0, sizeof(prefix));
#if !UIP_CONF_IPV6
    // REMINDER:  IPV6
    if (domainLen == 0)
    {
        memcpy(prefix, ipv6_zero_len_domain_prefix, sizeof(ipv6_zero_len_domain_prefix));
    }
    else if (domainLen == 1)
    {
        prefix[0] = IPV6_DOMAIN_LEN_1_PREFIX;
        prefix[1] = pDomain[0];
    }
    else if (domainLen == 3 && pDomain[2] == 0)
    {
        memcpy(prefix, pDomain, sizeof(prefix));
    }
#endif
    for (i = 0; i < IPV6_LSIP_IPADDR_DOMAIN_LEN && pIpAddr[i] == prefix[i]; i++)
    {
        domainDifferences--;
    }

    return domainDifferences;
}

uint8_t ipv6_ip_address_matches_domain(const uint8_t *pIpAddr, const uint8_t *pDomain, int domainLen)
{
    return ipv6_ip_domain_differences(pIpAddr, pDomain, domainLen) == 0;
}

uint8_t ipv6_add_arbitrary_udp_addr(const uint8_t *pIpAddr, const uint8_t *pDomain, int domainLen, uint8_t *payLoad)
{
    uint8_t len = ipv6_ip_domain_differences(pIpAddr, pDomain, domainLen);

    if (len == 0)
    {
        // Domain matches!
        if (pIpAddr[IPV6_LSIP_UCADDR_OFF_SUBNET] == 0)
        {
            len = 1;
        }
        else if (pIpAddr[IPV6_LSIP_UCADDR_OFF_NODE] == 0 ||
                 pIpAddr[IPV6_LSIP_UCADDR_OFF_NODE] > 127)
        {
            len = 1;
        }
    }
    else
    {
        // Need to include the domain as well as the subnet node
        len += 2;
    }
    if (len != 0)
    {
        memcpy(payLoad, &pIpAddr[IPV4_ADDRESS_LEN-len], len);
    }
    return len;
}

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
                                                 uint8_t *pNpduHeader)
{
    uint8_t *p = pNpduHeader;
    uint8_t addressFormat;
    uint8_t sourceAddrLen = 0;
    uint8_t destAddrLen = 0;
    *p++ = 0; // IPV6_LTVX_NPDU_IDX_PRIDELTA - no priority, no alt path, no delta backlog.
    p += 1;   // addressing format for now...

    if (myDomainLen > 6)
    {
        myDomainLen = 0;
    }

    if (ipv6_is_valid_ls_derived_ip_address(pSourceAddr) && 
        ipv6_ip_address_matches_domain(pSourceAddr, pMyDomain, myDomainLen))
    {
        *p++ = pSourceAddr[IPV6_LSIP_UCADDR_OFF_SUBNET];
        *p++ = 0x80 | pSourceAddr[IPV6_LSIP_UCADDR_OFF_NODE];
    }
    else
    {
        *p++ = 0;
        *p++ = 0x80;
    }

    if (memcmp(ipv6_ls_multicast_prefix, pDestAddr, sizeof(ipv6_ls_multicast_prefix)) == 0)
    {
        *p++ = pDestAddr[IPV6_LSIP_MCADDR_OFF_SUBNET];  // The subnet or group
        if (pDestAddr[IPV6_LSIP_MCADDR_OFF_ADDR_TYPE] == IPV6_LS_MC_ADDR_TYPE_GROUP)
        {
            addressFormat = LT_AF_GROUP;
        }
        else 
        {
            addressFormat = LT_AF_BROADCAST;
        }
    }
#if UIP_CONF_IPV6
    // REMINDER: IPV6
#else
    else if (pDestAddr[IPV6_LSIP_UCADDR_OFF_NODE] == 0xff)
    {
        // A broadcast.
        addressFormat = LT_AF_BROADCAST;
        if (pDestAddr[IPV6_LSIP_UCADDR_OFF_SUBNET] == 0xff)
        {
            *p++ = 0;
        }
        else
        {
            *p++ = pDestAddr[IPV6_LSIP_UCADDR_OFF_SUBNET];
        }
    }
#endif
    else if (ipv6_ip_address_matches_domain(pDestAddr, pMyDomain, myDomainLen))   
    {
        addressFormat = LT_AF_SUBNET_NODE;
        *p++ = pDestAddr[IPV6_LSIP_UCADDR_OFF_SUBNET];
        if (pDestAddr[IPV6_LSIP_UCADDR_OFF_NODE] <= 127)
        {
            *p++ = 0x80 | pDestAddr[IPV6_LSIP_UCADDR_OFF_NODE];
        }
        else
        {
            *p++ = 0x80;
        }
    }
    else
    {
        addressFormat = LT_AF_SUBNET_NODE;
        *p++ = 0x00;
        *p++ = 0x80;
    }

    // Now that we have the address format we can fill in the pdu fmt, address type and domain len byte.
    pNpduHeader[IPV6_LTVX_NPDU_IDX_TYPE] = (2 << IPV6_LTVX_NPDU_BITPOS_VER) |
                                           (ENCLOSED_PDU_TYPE_APDU << IPV6_LTVX_NPDU_BITPOS_PDUFMT) | 
                                           (addressFormat<<IPV6_LTVX_NPDU_BITPOS_ADDRTYPE) | 
                                           getDomainLenEncoding(myDomainLen);

    memcpy(p, pMyDomain, myDomainLen);
    p+= myDomainLen;

    // Now start on the payload
    *p++ = IPV6_UDP_APP_MSG_CODE;

    sourceAddrLen = ipv6_add_arbitrary_udp_addr(pSourceAddr, pMyDomain, myDomainLen, p+1);
    *p = ((sourceAddrLen < 7) ? sourceAddrLen : 7) << IPV6_ARB_UDP_SAC_BITPOS;

    destAddrLen = ipv6_add_arbitrary_udp_addr(pDestAddr, pMyDomain, myDomainLen, &p[sourceAddrLen+1]);
    *p |= ((destAddrLen < 7) ? destAddrLen : 7) << IPV6_ARB_UDP_DAC_BITPOS;
    if (sourcePort == destPort)
    {
        *p |= IPV6_ARB_UDP_SPE_MASK;
    }
    p += (1 + sourceAddrLen + destAddrLen);
    if (sourcePort != destPort)
    {
        *((uint16_t *)p) = htons(sourcePort);
        p += sizeof(sourcePort);
    }
    *((uint16_t *)p) = htons(destPort);
    p += sizeof(destPort);
    return (uint8_t)(p - pNpduHeader);
}


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
                                        uint8_t **ppDomain, uint8_t *pDomainLen)
{
    uint8_t offset = 0;
    uint8_t destLen = 0;
    if (IPV6_LT_VER_MATCHES(pNpdu[IPV6_LTVX_NPDU_IDX_TYPE], ltVersion) &&
        (pNpdu[IPV6_LTVX_NPDU_IDX_TYPE] & IPV6_LTVX_NPDU_MASK_PDUFMT) == (ENCLOSED_PDU_TYPE_APDU << IPV6_LTVX_NPDU_BITPOS_PDUFMT))
    {
        int addrFormat = IPV6_GET_ADDRESS_FORMAT_FROM_NPDU(pNpdu);

        switch (addrFormat)
        {
        case LT_AF_BROADCAST:
        case LT_AF_GROUP:
            destLen = 1;
            break;
        case LT_AF_SUBNET_NODE:
            if (pNpdu[IPV6_LTVX_NPDU_IDX_SOURCE_NODE] & 0x80)
            {
                destLen = 2;
            }
            break;
        }

        if (destLen)
        {
            uint8_t *p;
            
            *pDomainLen = domainLengthTable[pNpdu[IPV6_LTVX_NPDU_IDX_TYPE] & IPV6_LTVX_NPDU_MASK_DOMAINLEN];
            *ppDomain = &pNpdu[IPV6_LTVX_NPDU_IDX_DEST_ADDR + destLen];
            p = *ppDomain + *pDomainLen;
            if (*p == IPV6_UDP_APP_MSG_CODE)
            {
                if (ltVersion == 0 && fillSource)
                {
                    ipv6_gen_ls_subnet_node_addr(*ppDomain, *pDomainLen, 
                                                 pNpdu[IPV6_LTVX_NPDU_IDX_SOURCE_SUBNET], 
                                                 pNpdu[IPV6_LTVX_NPDU_IDX_SOURCE_NODE], 
                                                 ((Ipv6UdpAppMsgHdr *)(p+1))->sourceIpAddress);
                }
                offset = (uint8_t)(p - pNpdu);
            }
        }
    }
    return offset;
}

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
                                          Ipv6UdpAppMsgHdr *pArbUdpHeader)
{
    uint8_t len = 0;
    uint8_t destLen = 0;
    if (IPV6_LT_IS_VER_ARB_UDP(pNpduHeader[IPV6_LTVX_NPDU_IDX_TYPE]) &&
        (pNpduHeader[IPV6_LTVX_NPDU_IDX_TYPE] & IPV6_LTVX_NPDU_MASK_PDUFMT) == (ENCLOSED_PDU_TYPE_APDU << IPV6_LTVX_NPDU_BITPOS_PDUFMT))
    {
        int addrFormat = IPV6_GET_ADDRESS_FORMAT_FROM_NPDU(pNpduHeader);

        switch (addrFormat)
        {
        case LT_AF_BROADCAST:
        case LT_AF_GROUP:
            destLen = 1;
            break;
        case LT_AF_SUBNET_NODE:
            if (pNpduHeader[IPV6_LTVX_NPDU_IDX_SOURCE_NODE] & 0x80)
            {
                destLen = 2;
            }
            break;
        }

        if (destLen)
        {
            uint8_t domainLen = domainLengthTable[pNpduHeader[IPV6_LTVX_NPDU_IDX_TYPE] & IPV6_LTVX_NPDU_MASK_DOMAINLEN];
            const uint8_t *pDomain = &pNpduHeader[IPV6_LTVX_NPDU_IDX_DEST_ADDR + destLen];
            const uint8_t *p = pDomain + domainLen;
            if (*p == IPV6_UDP_APP_MSG_CODE)
            {
                // Ok, it is is an arbitrary UDP 
                uint8_t compression;
                uint8_t enclosedAddrLen;
                *pNpduHeaderLen = (uint8_t)(p++ - pNpduHeader);
                compression = *p++;
                enclosedAddrLen = (compression & IPV6_ARB_UDP_SAC_MASK) >> IPV6_ARB_UDP_SAC_BITPOS;

                // First generate the prefix.
                ipv6_gen_ls_prefix(pDomain, domainLen, pNpduHeader[IPV6_LTVX_NPDU_IDX_SOURCE_SUBNET], pArbUdpHeader->sourceIpAddress);
                // Fill in the node
                pArbUdpHeader->sourceIpAddress[IPV6_LSIP_UCADDR_OFF_NODE] = pNpduHeader[IPV6_LTVX_NPDU_IDX_SOURCE_NODE] & 0x7f;

                // Now get any address info from the payload.
                memcpy(&pArbUdpHeader->sourceIpAddress[IPV4_ADDRESS_LEN-enclosedAddrLen], p, enclosedAddrLen);
                
                p += enclosedAddrLen;
                enclosedAddrLen = (compression & IPV6_ARB_UDP_DAC_MASK) >> IPV6_ARB_UDP_DAC_BITPOS;

                if (addrFormat == LT_AF_SUBNET_NODE || enclosedAddrLen)
                {
                    // First generate the prefix.
                    ipv6_gen_ls_prefix(pDomain, domainLen, pNpduHeader[IPV6_LTVX_NPDU_IDX_DEST_SUBNET], pArbUdpHeader->destIpAddress);
                    // Fill in the node
                    pArbUdpHeader->destIpAddress[IPV6_LSIP_UCADDR_OFF_NODE] = pNpduHeader[IPV6_LTVX_NPDU_IDX_DEST_NODE] & 0x7f;
                }
                else
                {
                    ipv6_gen_ls_mc_addr(IPV6_LS_MC_ADDR_TYPE_BROADCAST, pNpduHeader[IPV6_LTVX_NPDU_IDX_DEST_SUBNET], pArbUdpHeader->destIpAddress);
                }
                // Now get any address info from the payload.
                memcpy(&pArbUdpHeader->destIpAddress[IPV4_ADDRESS_LEN-enclosedAddrLen], p, enclosedAddrLen);
                p += enclosedAddrLen;

                memcpy(&pArbUdpHeader->sourcePort, p, sizeof(pArbUdpHeader->sourcePort));
                p += sizeof(pArbUdpHeader->sourcePort);

                if (compression & IPV6_ARB_UDP_SPE_MASK)
                {
                    // Source and dest are the same.
                    pArbUdpHeader->destPort = pArbUdpHeader->sourcePort;
                }
                else
                {
                    memcpy(&pArbUdpHeader->destPort, p, sizeof(pArbUdpHeader->destPort));
                    p += sizeof(pArbUdpHeader->destPort);
                }
                len = (uint8_t)(p - pNpduHeader);
            }
        }
    }
    return len;
}


#endif
