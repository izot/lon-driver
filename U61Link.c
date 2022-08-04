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
 * U61Link.c
 *
 *  Created on: Aug 30, 2017
 *      Author: dwf
 *  We've disabled the "pig" for now, it's not clear that this level
 *  of downlink flow control is necessary.
 */

#define AP2549			1

#include <linux/delay.h>
#include <linux/list.h>
#include "u61_priv.h"

#include "Ldv32.h"
#include "U61Link.h"
#include "U61Osal.h"

// #define FLUSH_TRACING

static const USBLTA_Params def_uparams = {
	DEF_INTRANSFERSIZE,
	DEF_READTIMEOUT,
	DEF_WRITETIMEOUT,
	DEF_UPLINKLIMIT,
	DEF_LLPTIMEOUT,
	DEF_LATENCYTIMER,
	DEF_PIG_XTN_COUNT
};

static void U61LinkStateReset(struct U61LinkState *state)
{
	state->m_Ulstate = UL_IDLE1;
	state->m_MsgIndex = 0;
	state->m_UplinkLength = 0;
	state->m_bUplinkFrameError = FALSE;
}

//////////////////////////////////////////////////////////////////////
static WORD endianSwap16(WORD in)
{
	return (in >> 8) | (in << 8);
}
//////////////////////////////////////////////////////////////////////
#if 0
static WORD lonvxdMsgLength(pUSBLTA_Message pvxdb)
{
	if(pvxdb->Length != EXT_LENGTH)
		return pvxdb->Length;
	else
	{
		pLONVXD_ExtBuffer pexb = (pLONVXD_ExtBuffer)pvxdb;
		return endianSwap16(pexb->ExtLength);
	}
}
#endif
//////////////////////////////////////////////////////////////////////
// Include length fields
static WORD lonvxdTotalLength(pUSBLTA_Message pvxdb)
{
	if(pvxdb->Length != EXT_LENGTH)
		return pvxdb->Length + 1;
	else {
		pLDV_ExtMessage pexb = (pLDV_ExtMessage)pvxdb;
		return endianSwap16(pexb->ExtLength) + 1 + 2;
	}
}

// We are going to try and preserve the regular LDV_Message format..
static void U61UplinkQueue(struct U61LinkState *state, pUSBLTA_Message mp)
{
    int iCpyLength = lonvxdTotalLength(mp) + 1;
    if (state->m_bWaitForMAC) {
        BYTE *buf = (BYTE *)mp;
		if (iCpyLength >= 23 && buf[0] == 0x16 && buf[16] == 0x2d) { 
			// read memory response is 23 bytes, this could be parsed
			// with a lot more headers brought in
			int i;
			for (i=0; i < 6; i++) 
				state->m_mac_id[i] = buf[i+17];
            state->m_bWaitForMAC = FALSE;
            state->m_bHaveMAC = TRUE;
            OsalSetEvent(state->m_hReadMACNotifier);
		}
        // else continue waiting...
    } else {
        // This section used to allocate a buffer, copy the msg,
        // call u61_bump and then free the memory.  I don't see
        // where that is necessary, and indeed just passing
        // the message up (u61_bump() copies it into a skb)
        // seems to work just fine. -- mlb 2018
        u61_bump(get_priv(state), (uint8_t*)mp, iCpyLength);
    }
}

static const BYTE MsgIdentify[] = {niIDENTIFY, 0};
static const BYTE MsgModeL2[]	= {niLMODE, 1, 1};
static const BYTE MsgModeL5[]	= {niLMODE, 1, 0};
static const BYTE MsgNeuronID[] = { 0x22, 0x13, 0x70, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6d, 0x01, 0x00, 0x00, 0x06 };
void IdentifyLta(struct U61LinkState *state)
{
//	PutDownlink((const USBLTA_Message *)MsgIdentify);
}

//////////////////////////////////////////////////////////////////////
// Check for completed uplink packets
// Use the length at [0]
// Update: Expanded packets may appear as:
//          0   1    2    3
// [7E][00][FF][LHI][LLO][CMD][...]
// instead of
//          0    1
// [7E][00][LEN][CMD][...]
//////////////////////////////////////////////////////////////////////
static BOOL CheckUplinkCompleted(struct U61LinkState *state)
{
	if (state->m_MsgIndex == 1)		// length
		state->m_UplinkLength = state->m_ThisMessage[0];
	else if (state->m_UplinkLength == EXT_LENGTH && state->m_MsgIndex == 3)
	{
		// get the extended length. state->m_ThisMessage[0] is still EXT_LENGTH
		state->m_UplinkLength = ((state->m_ThisMessage[1] << 8) | state->m_ThisMessage[2]);
	}
	else if (state->m_MsgIndex && (state->m_MsgIndex > state->m_UplinkLength))
	{
		BYTE NiCmd;
		pUSBLTA_Message mp = (pUSBLTA_Message)state->m_ThisMessage;
		if (state->m_ThisMessage[0] == EXT_LENGTH)
		{
			// Re-arrange the 1st 4 bytes. endian swap the length
			// Output: [CMD][FF][LHI][LLO][...]
			NiCmd = state->m_ThisMessage[3];
			state->m_ThisMessage[1] = EXT_LENGTH;
			state->m_UplinkLength--;		// dec for NiCmd
			state->m_ThisMessage[2] = (BYTE)(state->m_UplinkLength & 0xFF);
			state->m_ThisMessage[3] = (BYTE)(state->m_UplinkLength >> 8);
			state->m_ThisMessage[0] = NiCmd;
		}
		else
		{
			// Re-arrange the 1st two bytes (Length & NiCmd)
			NiCmd = state->m_ThisMessage[1];
			state->m_UplinkLength--;		// dec for NiCmd
			state->m_ThisMessage[1] = (BYTE)state->m_UplinkLength;
			state->m_ThisMessage[0] = NiCmd;
		}
		// Filter any niDRIVER commands:
		if ((NiCmd & niCMD_MASK) == niDRIVER || NiCmd == niLMODE) {
			// LDDebugInform("Processed one uplink niDRIVER cmd 0x%02X", NiCmd);
			if (NiCmd == niPIG) {
				if (state->m_PigQueCount)
					state->m_PigQueCount--;
			} else if (NiCmd == niLMODE) {
				LDDebugInform("NI Mode received: %d", mp->Message[0]);
			}
		} else {
			// LDDebugUplinkMessage(TRUE, mp);
			// Process & Shrink any niRESET data.
			if (NiCmd == niRESET) {
				if (mp->Length) {
					state->m_Stats.Txid = mp->Message[1];
					state->m_Stats.L2L5Mode = mp->Message[0];
					LDDebugInform("NI Reset received, TXID: %d, MODE: %d", state->m_Stats.Txid, state->m_Stats.L2L5Mode);
				} else {
					LDDebugInform("NI Reset received, no data.");
				}
				mp->Length = 0;
			} else if (NiCmd == niCRCERR) {
                DWORD_PEG((get_priv(state)->dev->stats.rx_crc_errors));
            } else if (NiCmd == niINCOMING && (mp->Length > (3+11)) && (mp->Message[OFFS_MCODE] == NM_WINK)) {
                // Process any uplink network WINK messages
				IdentifyLta(state);
			}
			#ifdef FLUSH_TRACING
			if (NiCmd == niFLUSH_COMPLETE) {
				LDDebugInform("NI Flush Complete received.");
			}
			#endif
            // Note: trashed uplink data can result in 0xFF in the Length field, a bad value.
            if (((unsigned int)state->m_UplinkLength + 2) > (sizeof(USBLTA_Message) + 2)) {
                LDDebugNotice("Uplink message had invalid length: %d", state->m_UplinkLength);
            } else {
                // Queue it.
                U61UplinkQueue(state, mp);
                // This version doesn't have a way to employ m_uparams.UplinkContainerLimit
                // or m_bUplinkHoldoff

            }
		}
		U61LinkStateReset(state);
		return TRUE;
	}
	return FALSE;
}


static void U61DumpRawUplink(BYTE *bp, WORD nCount)
{
#if 0
	char *pBuf = allocateMemory(1024);
	char hcBuf[16];
	int pbCount;
	if (!pBuf)
		return;
	strcpy(pBuf, KERN_INFO "U61 Read: ");
	pbCount = strlen(pBuf);
	while(nCount--) {
		sprintf(hcBuf, "%02X ", *bp++);
		strcat(pBuf, hcBuf);
		pbCount += strlen(hcBuf);
		if (pbCount > (1024 - 16))
			break;
	}
	strcat(pBuf, "\n");
	printk(pBuf);
	freeMemory(pBuf);
#endif
}


//////////////////////////////////////////////////////////////////////
// The reader thread uplink processor
//////////////////////////////////////////////////////////////////////
static void ProcessUplink(struct U61LinkState *state)
{
	BYTE buffRead[256];
	WORD dwRCount = 0;
	BYTE *bp;
	DWORD RdStatus;

	RdStatus = CalLowerRead(state, buffRead, sizeof(buffRead), &dwRCount);

	if (dwRCount == 0) {
		// this would be a timeout
		// LDDebugInform("Read of 0");
	} else if (dwRCount == -1) {	// never will happen..
		// this would be an error
		// LDDebugNotice("Error on device read: %s", strerror(errno));
		state->m_bCroak = TRUE;
	} else {
		bp = buffRead;
		U61DumpRawUplink(bp, dwRCount);
		while (dwRCount) {
			if (state->m_bCroak)
				break;
			switch(state->m_Ulstate) {
			case UL_IDLE1:
				if (*bp == UMIP_ESC) {
					state->m_Ulstate = UL_IDLE2;
					state->m_bUplinkFrameError = FALSE;
				} else if (!state->m_bUplinkFrameError) {
					DWORD_PEG(state->m_Stats.FrameErrors);
                    DWORD_PEG((get_priv(state)->dev->stats.rx_frame_errors));
					LDDebugNotice("Uplink frame error (1) - %02X", *bp);
					state->m_bUplinkFrameError = TRUE;
				}
				bp++;
				dwRCount--;
				break;
			case UL_IDLE2:
				if (*bp == 0) {
					state->m_Ulstate = UL_PACKET;
					bp++;
					dwRCount--;
					// Start the timer.
					state->m_RxTimer = OsalGetTickCount();
				} else {
					// Not 2nd frame byte, just go back to IDLE1 w/ same data.
					DWORD_PEG(state->m_Stats.FrameErrors);
                    DWORD_PEG((get_priv(state)->dev->stats.rx_frame_errors));
					LDDebugNotice("Uplink frame error (2) - %02X", *bp);
					state->m_Ulstate = UL_IDLE1;
				}
				break;
			case UL_PACKET:
				// Process as much of the packet that we have, inc. ESC data.
				while (dwRCount) {
					BYTE cc;
					cc = state->m_ThisMessage[state->m_MsgIndex++] = *bp++;
					dwRCount--;
					if (cc == UMIP_ESC) {
						state->m_Ulstate = UL_ESCD1;
						break;
					}
					if (CheckUplinkCompleted(state))
						break;
				}
				if (state->m_Ulstate != UL_IDLE1 && OsalGetTickCount() - state->m_RxTimer > state->m_uparams.LLPTimeout) {
					DWORD_PEG(state->m_Stats.TmoErrors);
                    DWORD_PEG((get_priv(state)->dev->stats.rx_errors));
					LDDebugNotice("Uplink frame timeout");
					U61LinkStateReset(state);
				}
				break;
			case UL_ESCD1:		// only gets here from UL_PACKET.
				// by default:
				state->m_Ulstate = UL_PACKET;
				// look at next byte following UMIP_ESC
				if (*bp != UMIP_ESC)	{
					DWORD_PEG(state->m_Stats.FrameErrors);
                    DWORD_PEG((get_priv(state)->dev->stats.rx_frame_errors));
					LDDebugNotice("Uplink frame error (data)");
					if (*bp == 0) {
						state->m_MsgIndex = 0;		// re-framed! re-start!
					} else {
						// unknown 2nd byte. must re-frame.
						U61LinkStateReset(state);
					}
				} // else normal escaped data. drop 2nd UMIP_ESC.
				bp++;
				dwRCount--;
				CheckUplinkCompleted(state);
				break;
			}	// end of switch
		}
	}
}


//////////////////////////////////////////////////////////////////////
// The reader thread:
//////////////////////////////////////////////////////////////////////
#define U61_THREAD_WAIT		1000		// MS
#define U61_MAC_WAIT		500		// MS
static DWORD TheReaderThread(struct U61LinkState *state)
{
	LDDebugInform("Thread launched %u", state->m_hThisThread);
	while (!state->m_bCroak) {
		if (!state->m_bUplinkHoldoff) {
			OsalWaitForEvent(state->m_hReadThreadNotifier, U61_THREAD_WAIT);
			ProcessUplink(state);	// does not block.
		} else {
			udelay(100);
		}
	}
	state->m_bCroak = FALSE;	// indicate done.
	return 0;
}

static BOOL WaitThreadStart(struct U61LinkState *state)		// returns TRUE if success
{
	DWORD dwTaskTime;
	OsalThreadId tid;
	// Start thread, then wait...
    tid = OsalCreateThread((OsalEntryPoint)TheReaderThread, state);
    state->m_hThisThread = tid;
	if (!state->m_hThisThread) {
		LDDebugError("[%d] Failed to create reader thread", state->m_DevIndex);
		return FALSE;
	}

	// Wait for thread creation to complete.
	dwTaskTime = OsalGetTickCount();
/*	while (state->m_RTState != TSTATE_IDLE) {
		Sleep(25);
		if (OsalGetTickCount() - dwTaskTime > 3000)
			return FALSE;
	}*/
	return TRUE;
}

void U61LinkInit(struct U61LinkState *state)
{
	INIT_LIST_HEAD(&state->Dlist.list);
	INIT_LIST_HEAD(&state->Ulist.list);
}

short U61LinkStart(struct U61LinkState *state, U61OpenMode mode)
{
    int macRetries = 2;
	LDDebugInform("Link Start, open mode %d", mode);
	state->m_Options = (DCMP_BLIND|DCMP_DEFAULT);
	state->m_OpenMode = mode;
	OsalCreateEvent(&state->m_hReadThreadNotifier);
	OsalCreateEvent(&state->m_hReadMACNotifier);
	//state->m_StartupIndex = 0;
	memset(&state->m_Stats, 0, sizeof(state->m_Stats));
	state->m_Stats.Size = sizeof(state->m_Stats);
	//state->m_iOpenReferences = 0;
	state->m_bCroak = FALSE;
	state->m_uparams = def_uparams;
	U61LinkStateReset(state);
	state->m_PigXtn = state->m_PigCount = state->m_PigQueCount = 0;
	state->m_bUplinkHoldoff = FALSE;
    state->m_bWaitForMAC = TRUE;
    state->m_bHaveMAC = FALSE;
	if (!WaitThreadStart(state)) {
		return LDVX_INITIALIZATION_FAILED;
	}
    // Get perm MAC addr, do before launching TheReaderThread!
    LDDebugInform("Link Start, acquire embedded MAC");
    while (macRetries--) {
        U61LinkWrite(state, (const LDV_Message*) MsgNeuronID);
        OsalWaitForEvent(state->m_hReadMACNotifier, U61_MAC_WAIT);
        if (state->m_bHaveMAC )
            break;
    }
    state->m_bWaitForMAC = FALSE;
    if (state->m_bHaveMAC) {
        
        LDDebugInform("Link Start, embedded MAC %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
                      state->m_mac_id[0], state->m_mac_id[1], state->m_mac_id[2],
                      state->m_mac_id[3], state->m_mac_id[4], state->m_mac_id[5]);
    } else {
        LDDebugInform("Link Start, failed to acquire embedded MAC");
    }
	// Open mode:
	if (state->m_OpenMode == U61_OPEN_LAYER5) {
		U61LinkWrite(state, (const LDV_Message*) MsgModeL5);
	} else {
		U61LinkWrite(state, (const LDV_Message*) MsgModeL2);
	}
	return LDV_OK;
}


// escaped data stuffing
static void ByteDownlink(struct U61LinkState *state, BYTE cc)
{
	state->m_DlPacket[state->m_DlIndex++] = cc;
	if (cc == UMIP_ESC)
		state->m_DlPacket[state->m_DlIndex++] = UMIP_ESC;
}


short U61LinkWrite(struct U61LinkState *state, const LDV_Message* mp)
{
	unsigned sIndex;
	unsigned dwLength;
	int nWritten;
	const BYTE *pExpAppMessage;
	BYTE lNiCmd = mp->NiCmd;
	// Critical section rqd?

	// First snag any niDRVR commands:
	if (lNiCmd == niDRV_RST) {
		// not much I can do if it fails..
        LDDebugInform("Resetting FT port (niDRV_RST)...");
        // until we have a way to reset/cycle this USB device this is deprecated.
		return TRUE;
	}
	if (lNiCmd == niDRV_CYC) {
		// not much I can do if it fails..
        LDDebugInform("Cycling FT port (niDRV_CYC)...");
        // until we have a way to reset/cycle this USB device this is deprecated.
		return TRUE;
	}
	// Hook niLMODE commands from the client.
	// Set the OpenMode so that if the NI resets we'll do the right thing.
	if (lNiCmd == niLMODE && mp->Length) {
		state->m_OpenMode = (mp->ExpAppMessage[0] == 0) ? U61_OPEN_LAYER5 : U61_OPEN_LAYER2;
	}
	#ifdef FLUSH_TRACING
	if (lNiCmd == niFLUSH) {
		LDDebugInform("NI Flush command written.");
	}
	#endif
#ifdef U61_PIG
	// Next check for downlink packet throttling
	if (state->m_PigQueCount >= 2) {
		// May time out..
		if ((OsalGetTickCount() - state->m_PigTimer) > DEF_PIGTIMER) {
			state->m_PigQueCount--;
			state->m_PigTimer = OsalGetTickCount();
			LDDebugNotice("Pig timed out");
		}
		return FALSE;	// note that the caller ignores this return value :)
	}
#endif
	// Finally restrict downlink packet forms since out-of-range ones can break the MIP:
	if (((lNiCmd & niCMD_MASK) == niCOMM) && ((lNiCmd & niQUE_MASK) > niNTQ_P)) {
		LDDebugNotice("Out of range packet command 0x%02X is being transformed", lNiCmd);
		lNiCmd = (niCOMM|niTQ) | (lNiCmd & 0x01);
	}
	// AP-3995 - drop LTV1 packets for now.
	#if AP2549
	if (state->m_OpenMode != U61_OPEN_LAYER5 &&
		(lNiCmd == (niCOMM|niTQ) || lNiCmd == (niCOMM|niTQ_P)) &&
		(mp->ExpAppMessage[1] & 0xC0) == 0x40) {	// LTV1 message
		const BYTE *pExpM = mp->ExpAppMessage;
		if (pExpM[IPV4_TOS] == 0 && pExpM[IPV4_PROTO] == 1) {		// ICMP
			if (pExpM[IPV4_ICMP_TYPE] == 8 && pExpM[IPV4_ICMP_CODE] == 0) {		// ICMP ping
				// keep it
			} else {
		return TRUE;
	}
		}
	}
	#endif
	// Build the expanded downlink message.
	state->m_DlPacket[0] = UMIP_ESC;
	state->m_DlPacket[1] = 0;

	state->m_DlIndex = 2;			// start here

	if (mp->Length == EXT_LENGTH) {
		// this is an extended message
		const LDV_ExtMessage *pexm = (LDV_ExtMessage *)mp;	// source
		if (pexm->ExtLength > MAXLONMSG) {
			LDDebugNotice("Oversized extended message: %d", pexm->ExtLength);
			return FALSE;
		}
		state->m_DlPacket[state->m_DlIndex++] = EXT_LENGTH;		// is never UMIP_ESC
		dwLength = pexm->ExtLength + 1;			// bump to include NiCmd
		ByteDownlink(state, (BYTE)(dwLength >> 8));
		ByteDownlink(state, (BYTE)(dwLength & 0xFF));
		pExpAppMessage = pexm->ExpAppMessage;
	} else {
// EPR 69432 - U10/U20 firmware does not expect escaped length, NICmd.
		dwLength =  mp->Length + 1;				// bump to include NiCmd.
		state->m_DlPacket[state->m_DlIndex++] = (BYTE)dwLength;
		pExpAppMessage = mp->ExpAppMessage;
	}
	ByteDownlink(state, lNiCmd);		// is never UMIP_ESC
	// lose the bump to length.
	dwLength--;

	sIndex = 0;
	while (sIndex < dwLength) {
		ByteDownlink(state, *pExpAppMessage++);
		sIndex++;
	}

	state->m_DlPacketSize = state->m_DlIndex;
	nWritten = CalLowerWrite(state, state->m_DlPacket, state->m_DlPacketSize);

	if (nWritten != state->m_DlPacketSize) {
        // LDDebugNotice("Data write failed (%d).  Wrote %d/%d.", errno, nWritten, state->m_DlPacketSize);
		LDDebugInform("Data write - wrote %d of %d bytes", nWritten, state->m_DlPacketSize);
		DWORD_PEG(state->m_Stats.WriteErrors);
        DWORD_PEG((get_priv(state)->dev->stats.tx_errors));
		// return false;
	}
	// LDDebugUplinkMessage(FALSE, mp);
#ifdef U61_PIG
	// Before exiting, see if we need to send down a XTN "pig".
	if (++state->m_PigCount >= state->m_uparams.PigCount) {
		// build another expanded message. [0] & [1] are already in place.
		// Assumption: the XTN value is the only possible escaped data.
		state->m_DlPacket[2] = 2;		    // length
		state->m_DlPacket[3] = niPIG;
		state->m_DlIndex = 4;				// start here
		ByteDownlink(state, state->m_PigXtn);
		state->m_DlPacketSize = state->m_DlIndex;

		(void)CalLowerWrite(state, state->m_DlPacket, state->m_DlPacketSize);
		nWritten = state->m_DlPacketSize;

		if (nWritten != state->m_DlPacketSize) {
            // LDDebugNotice("Pig write failed (%d).  Wrote %d/%d.", errno, nWritten, state->m_DlPacketSize);
			DWORD_PEG(state->m_Stats.WriteErrors);
            // NOTE: Although the pig write failed, the user's write succeeded
            //       (above), so we return TRUE anyway.  If there is really an
            //       underlying buffer problem, then the next user write will
            //       also fail, and this will result in an error that the user
            //       can handle as normal, by delaying and reissuing the write.
            --state->m_PigCount;           // try again
		} else {
            // This just cycles around:
            state->m_PigXtn++;
            state->m_PigQueCount++;
            state->m_PigCount = 0;         // reset this
            state->m_PigTimer = OsalGetTickCount();
        }
	}
#endif
	return TRUE;
}

void U61LinkShutdown(struct U61LinkState *state)
{
	OsalTickCount tickStart;
	LDDebugInform("Link Shutdown");
	state->m_bCroak = TRUE;		// will clear to FALSE when complete.
	SIG_NOTIFIER(state->m_hReadThreadNotifier);
	tickStart = OsalGetTickCount();
	while (state->m_bCroak) {
		if (OsalGetTickCount() - tickStart > 5000)
			break;
	}
	CloseThreadHandle(state->m_hThisThread);
	CLOSE_NOTIFIER(state->m_hReadThreadNotifier);
    CLOSE_NOTIFIER(state->m_hReadMACNotifier);
	state->m_hThisThread = 0;
}

