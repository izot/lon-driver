// SPDX-License-Identifier: GPL-2.0 AND MIT
// Copyright © 2022-2025 EnOcean
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

#include <linux/types.h>
/******************************************************************************
  Function:  ipv6_send_announcement
   
  Summary:
    This callback is used to send an announcement message.  

  Parameters:
    lsSenderHandle: A handle to the callback object that implements the send 
                    function.
    ltV0msg:        The announcement message, in LON V0 format.
    msgLen:         The message length.
*****************************************************************************/
void ipv6_send_announcement(void *lsMappingHandle, const uint8_t *ltV0msg, uint8_t msgLen)
{
}

/******************************************************************************
  Function:  ipv6_get_arbitrary_source_address
   
  Summary:
    This callback is used to retrieve arbitrary IP address information 
    for a given source address.  

  Parameters:
    lsMappingHandle:        A handle used for LON/IP mapping 
    pSourceIpAddress:       On input, a pointer the desired (LON/IP derived) source 
                            IP address.  If this IP address cannot be used, 
                            pSourceIpAddress will be updated with the arbitrary
                            IP address to be used instead.
    pDomainId:              The LON/IP domain ID.
    domainIdLen:            The length (in bytes) of the LON/IP domain ID
    pEnclosedSource:        Pointer to a buffer to receive the necessary LON/IP
                            source addressing information (in V1 format) to be 
                            added to the UDP payload, if any
  Return: 
    The length of the additional enclosed source address information
*****************************************************************************/
uint8_t ipv6_get_arbitrary_source_address(void *lsMappingHandle,
                                          uint8_t *pSourceIpAddress, 
                                          const uint8_t *pDomainId, int domainIdLen,
                                          uint8_t *pEnclosedSource)
{
	return 0;
}

/******************************************************************************
  Function:  ipv6_get_arbitrary_dest_address
   
  Summary:
    This callback is used to used by the LON/IP to UDP translation layers to  
    retrieve arbitrary IP address information for a given destination address.  

  Parameters:
    lsMappingHandle:        A handle used for LON/IP mapping 
    pDomainId:              The LON/IP domain ID.
    domainIdLen:            The length (in bytes) of the LON/IP domain ID
    subnetId:               The LON/IP destination subnet ID
    nodeId:                 The LON/IP destination node ID
    ipv1AddrFmt:            The LON/IP address format
    pDestIpAddress:         Pointer to a buffer to receive the destination IP
                            address to be used.
    pEnclosedDest:          Pointer to a buffer to receive additional LON/IP
                            destination address information enclosed in the
                            PDU, if any.
  Return: 
    The length of the additional enclosed destination address information
*****************************************************************************/
uint8_t ipv6_get_arbitrary_dest_address(void *lsMappingHandle,
                                        const uint8_t *pDomainId, uint8_t domainLen, 
                                        uint8_t subnetId, uint8_t nodeId, uint8_t ipv1AddrFmt,
                                        uint8_t *pDestIpAddress, uint8_t *pEnclosedDest)
{
	return 0;
}

/******************************************************************************
  Function:  ipv6_set_arbitrary_address_mapping
   
  Summary:
    This callback is used by the LON/IP to UDP translation layers to 
    inform the LON/IP mapping layers that a given LON/IP address uses an
    arbitrary IP address.  

  Parameters:
    lsMappingHandle:        A handle used for LON/IP mapping 
    pArbitraryIpAddr:       The arbitrary IP address to use when addressing
                            the LON/IP device.
    pDomainId:              The LON/IP domain ID.
    domainIdLen:            The length (in bytes) of the LON/IP domain ID
    subnetId:               The LON/IP subnet ID
    nodeId:                 The LON/IP node ID
*****************************************************************************/
void ipv6_set_arbitrary_address_mapping(void *lsMappingHandle, const uint8_t *pArbitraryIpAddr, 
                                         const uint8_t *pDomainId, uint8_t domainLen, 
                                         uint8_t subnetId, uint8_t nodeId)
{
}

/******************************************************************************
  Function:  ipv6_set_derived_address_mapping
   
  Summary:
    This callback is used by the LON/IP to UDP translation layers to 
    inform the LON/IP mapping layers that a given LON/IP address uses a
    LON/IP derived IP address.  

  Parameters:
    lsMappingHandle:        A handle used for LON/IP mapping 
    pDomainId:              The LON/IP domain ID.
    domainIdLen:            The length (in bytes) of the LON/IP domain ID
    subnetId:               The LON/IP subnet ID
    nodeId:                 The LON/IP node ID
*****************************************************************************/
void ipv6_set_derived_address_mapping(void *lsMappingHandle, 
                                      const uint8_t *pDomainId, uint8_t domainLen, 
                                      uint8_t subnetId, uint8_t nodeId)
{
}

/******************************************************************************
  Function:  ipv6_set_derived_subnets_mapping
   
  Summary:
    This callback is used by the LON/IP to UDP translation layers when an 
    SubnetsAddrMapping message is received.

  Parameters:
    lsMappingHandle:        A handle used for LON/IP mapping 
    pDomainId:              The LON/IP domain ID.
    domainIdLen:            The length (in bytes) of the LON/IP domain ID
    set:                    True to set the derived mapping entries, clear to
                            clear the dervived mapping entries.
    pSubneteMap:            Pointer to a bit map of subnets to set or clear.
*****************************************************************************/
void ipv6_set_derived_subnets_mapping(void *lsMappingHandle, 
                                      const uint8_t *pDomainId, uint8_t domainLen, 
                                      uint8_t set, const uint8_t *pSubnets)
{
}

/******************************************************************************
  Function:  ipv6_is_unicast_address_supported
   
  Summary:
    This callback is used by the LON/IP to UDP translation layers to 
    determmine whether or not the specified IP address can be used by this
    device as a source address.

  Parameters:
    lsMappingHandle:        A handle used for LON/IP mapping 
    ipAddress:              The LON/IP domain ID.

*****************************************************************************/
uint8_t ipv6_is_unicast_address_supported(void *lsMappingHandle, const uint8_t *ipAddress)
{
	return 0;
}

