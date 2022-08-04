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

/*
 * U61Link.h
 *
 *  Created on: Aug 23, 2017
 *      Author: dwf
 */

#pragma once

#include "Ldv32.h"
#include "platform.h"
#include "U61Driver.h"
#include "U61Defs.h"

struct U61LinkState {
	OsalThreadId		m_hThisThread;
	OsalHandle			m_hClientEvent;
	OsalHandle			m_hReadThreadNotifier;
	OsalHandle			m_hReadMACNotifier;
	ThreadState			m_RTState;
	// LLP states:
	BOOL		    	m_bWaitForMAC;
	BOOL		    	m_bHaveMAC;
	BOOL		    	m_bUplinkHoldoff;
	DWORD		    	m_RxTimer;
	USBLTA_Params   	m_uparams;
	// Uplink packet state machine.
	UlState		    	m_Ulstate;
	BOOL				m_bUplinkFrameError;		// in frame error state
	BYTE				m_ThisMessage[SIZE_ULB];	// Uplink packets build here. 1st byte would reflect the length.
	int			    	m_MsgIndex;					// points to spot in <m_ThisMessage>
	int					m_UplinkLength;				// length / extended length
//	void StateReset() { m_Ulstate = UL_IDLE1; m_MsgIndex = 0; m_UplinkLength = 0; }
	// Downlink packet state machine.
	BYTE				m_DlPacket[SIZE_DLB];		// Downlink packets here, with escaped data expanded.
	int			    	m_DlPacketSize;				// Reflects expanded packet size.
	int			    	m_DlQueueSize;				// as fetched from the FT driver.
	int					m_DlIndex;					// into m_DlPacket[]
	// Downlink transaction tracking
	BYTE		    	m_PigXtn;
	int			    	m_PigCount;
	int			    	m_PigQueCount;
	DWORD		    	m_PigTimer;
	U61_Stats			m_Stats;		// last copy of stats.
	//int				m_iOpenReferences;
    BYTE                m_mac_id[MAX_ADDR_LEN];

	// Various LLP counts:
	U61OpenMode		m_OpenMode;
	BYTE			m_neuronMipVersion;
	BYTE			m_supportsExBuffers;
	WORD			m_ExtUplinkLength;	// extended length
	BYTE			m_UplinkCsBase;		// 0, or extended length fields
	// Queues:
	t_UDlist		Ulist;				// Uplink list (unused)
	t_UDlist		Dlist;				// Downlink list (unused)
	DcmpOptions		m_Options;
    DWORD           m_DevIndex;     	// [0] based device instance
    volatile BOOL	m_bCroak;
	void* priv; // pointer to private driver memory - link struct belongs to this chunk
};

// Access methods
void U61LinkInit(struct U61LinkState *state);
short U61LinkStart(struct U61LinkState *state, U61OpenMode mode);
short U61LinkRead(struct U61LinkState *state, pLDV_Message pMsg, int iSize);
short U61LinkWrite(struct U61LinkState *state, const LDV_Message* pMsg);
short U61LinkRegisterEvent(struct U61LinkState *state, OsalHandle hClientEvent);
int	U61LinkGetStats(struct U61LinkState *state, pU61_Stats ps);
void U61LinkShutdown(struct U61LinkState *state);

DWORD CalLowerRead(struct U61LinkState *state, PVOID pDest, WORD Count, PWORD pActual);
int CalLowerWrite(struct U61LinkState *state, PVOID OutputBuffer, ULONG OutputBufferLength);


// IPV4 ICMP "poll" (ping) definitions - 
//    ============================================================================
//    | 8                | 8                | 16                                 |
//    ============================================================================
//  0 | Version/IHL      | Type of service  | Length                             |
//  4 | Identification                      | Flags & offset                     |
//  8 | TTL              | Protocol         | Header Checksum                    |
// 12 | Source IP address                                                        |
// 16 | Destination IP address                                                   |
//    ==ICMP Header===============================================================
// 20 | Type of message  | Code             | Checksum                           |
//    ============================================================================
#define IPV4_START				2					// inc. BL & LTV2 bytes
#define IPV4_TOS				(IPV4_START+1)		// 0
#define IPV4_PROTO				(IPV4_START+9)		// 1:ICMP
#define IPV4_DEST_ADDR			(IPV4_START+16)
#define IPV4_ICMP_TYPE			(IPV4_START+20)		// 8:ping
#define IPV4_ICMP_CODE			(IPV4_START+21)		// 0


