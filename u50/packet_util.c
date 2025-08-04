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

#include <linux/string.h>
#include "LtPacket.h"
#include "packet_util.h"

void GenerateNeuronId(uint8_t *neuronId, uint8_t *macId) { 
    neuronId[0] = (~(macId[0] << 6)) & 0x80; // Flip u/l bit and move to MSB of Neuron MFG
    neuronId[0] |= (macId[0] << 6) & 0x40;   // Or in g bit as the second most significant
                                             // bit in the MFG byte
    neuronId[0] |= (macId[0] >> 2);          // Or in rest of the first byte of the MAC ID
                                             // in the least significant bits
    memcpy(&neuronId[1], &macId[1], 5);      // Copy the rest of the macId 
}

void generate_mac_address(uint8_t *macId, uint8_t *neuronId) {
    macId[0] = (~(neuronId[0] >> 6)) & 0x2;
    macId[0] |= (neuronId[0] >> 6) & 0x1;
    macId[0] |= (neuronId[0] << 2);
    memcpy(&macId[1], &neuronId[1], 5);
}

void generate_lt_header(uint8_t* buf) {//, uint8_t* mac_header) {
    L2HeaderV1 *header_buf = (L2HeaderV1*)buf;
    header_buf->reserved = 0;
    header_buf->version = 1;
    header_buf->packet_type = PKT_TYPE;
}

#if 0
extern ethaddr_t eth_mac_addr;
static void generate_mac_header(uint8_t* buf, uint8_t* lt_header, uint8_t* dst) {
    struct uip_eth_hdr* mac_buf = (struct uip_eth_hdr*) buf;
    memcpy(&mac_buf->src, &eth_mac_addr, sizeof(ethaddr_t));
    generate_mac_address((uint8_t*)&mac_buf->dest, dst);
    mac_buf->type=ETH_IP_TYPE;
}
#endif
