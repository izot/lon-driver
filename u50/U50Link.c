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

///////////////////////////////////////////////////////////////////////////////
//
// U50Link.cpp : Defines the U50Link class.
//
#define U50_LINK_TRACE	0
#define AP2549			1
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/kmod.h>
#include <linux/time.h>
#include "u50_priv.h"
#include "Ldv32.h"
#include "U50Link.h"
#include "U50Osal.h"

BOOL WaitThreadStart(struct U50LinkState *state);
void smpReaderStateZap(struct U50LinkState *state);
void smpClearAckTimerIdle(struct U50LinkState *state);
void smpResetReader(struct U50LinkState *state);
void smpKickWriter(struct U50LinkState *state);
BYTE smpGetResponse(BYTE request);
void smpDlQueueCheck(struct U50LinkState *state);
void smpDlCpNow(struct U50LinkState *state, BYTE CpCode, BYTE CpParam);
void smpDlMsgNow(struct U50LinkState *state);
void smpDlNiCmdLocal(struct U50LinkState *state);
void smpBumpTxSequence(struct U50LinkState *state);
void smpUplinkAckd(struct U50LinkState *state);
void smpMessageComplete(struct U50LinkState *state);
void smpReadProcess(struct U50LinkState *state);
void smpWriteService(struct U50LinkState *state);
void smpCodePacketRxd(struct U50LinkState *state, BOOL bRxReset);
BOOL smpChecksumValid(struct U50LinkState *state, BYTE* pPkt, int len);
void smpUplinkQueue(struct U50LinkState *state, LONVXD_Buffer *lvdp);
void smpTxCompleteModal(struct U50LinkState *state);
void smpTxComplete(struct U50LinkState *state);
void smpUplinkCopy(struct U50LinkState *state);
void smpInitiateCps(struct U50LinkState *state);
void smpInitiateCp(struct U50LinkState *state, BYTE cmd);
void smpResetAckTimer(struct U50LinkState *state, DCMPTXSTATE NewState);

static const BYTE StartupCommandsL2[] =
{
	nicbMODE_L2,		// This may cause a reset so do it first.
	nicbSSTATUS,		// This gets the MIP version.
	0					// This means the end!
};

static const BYTE StartupCommandsL5[] =
{
	nicbMODE_L5,		// This may cause a reset so do it first.
	nicbSSTATUS,		// This gets the MIP version.
	0					// This means the end!
};

static const BYTE StartupCommandsDef[] =
{
	nicbSSTATUS,		// This gets the MIP version.
	0					// This means the end!
};

static const BYTE MsgNeuronID[] = { 0x22, 0x13, 0x70, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6d, 0x01, 0x00, 0x00, 0x06 };


//////////////////////////////////////////////////////////////////////
// Locks are used to protect the UP and DOWN lists.
void smpEnterCriticalSection(struct U50LinkState *state)
{
    struct u50_priv *priv = get_priv(state);
    if (priv) {
		spin_lock_bh(&priv->lock);
	}
}

void smpLeaveCriticalSection(struct U50LinkState *state)
{
    struct u50_priv *priv = get_priv(state);
    if (priv) {
		spin_unlock_bh(&priv->lock);
	}
}

//////////////////////////////////////////////////////////////////////
// smpNeuronHealthEvent - Called whenever a timeout occurs.  Shouldn't
// happen so if it does, we reset the Neuron.
//////////////////////////////////////////////////////////////////////
static void smpNeuronHealthEvent(void)
{

}

//////////////////////////////////////////////////////////////////////
// Compute a checksum.  Used for both incoming and outgoing frames.
//////////////////////////////////////////////////////////////////////
BYTE smpComputeChecksum(BYTE* pPkt, int len)
{
	int ii;
	BYTE sum = 0;

	for(ii=0; ii<len; ii++)
		sum += pPkt[ii];
	return sum;
}

//////////////////////////////////////////////////////////////////////
WORD endianSwap16(WORD in)
{
	return (in >> 8) | (in << 8);
}
//////////////////////////////////////////////////////////////////////
WORD lonvxdMsgLength(pLONVXD_Buffer pvxdb)
{
	if(pvxdb->Length != EXT_LENGTH)
		return pvxdb->Length;
	else
	{
		pLONVXD_ExtBuffer pexb = (pLONVXD_ExtBuffer)pvxdb;
		return endianSwap16(pexb->ExtLength);
	}
}
//////////////////////////////////////////////////////////////////////
// Include length fields
WORD lonvxdTotalLength(pLONVXD_Buffer pvxdb)
{
	if(pvxdb->Length != EXT_LENGTH)
		return pvxdb->Length + 1;
	else
	{
		pLONVXD_ExtBuffer pexb = (pLONVXD_ExtBuffer)pvxdb;
		return endianSwap16(pexb->ExtLength) + 1 + 2;
	}
}

//////////////////////////////////////////////////////////////////////
// CU50Link class (Public)
//////////////////////////////////////////////////////////////////////
void U50LinkInit(struct U50LinkState *state)
{
    
	state->m_RTState = TSTATE_IDLE;
	state->m_hReadThreadNotifier = 0;
	state->m_hThisThread = 0;
	state->m_hClientEvent = NULL;
    state->m_hComPort = 0;
	state->m_neuronMipVersion = 0;
	state->m_supportsExBuffers = 0;
	// The LLP stuff gets reset in the Start() method.
	INIT_LIST_HEAD(&state->Dlist.list);
	INIT_LIST_HEAD(&state->Ulist.list);
}

// executed on close()
void U50LinkShutdown(struct U50LinkState *state)
{
	if(state->m_RTState == TSTATE_RUNNING)
	{
		state->m_RTState = TSTATE_KILL;
		// wake it up
		SIG_NOTIFIER(state->m_hReadThreadNotifier);
		// wait for thread death..
		while (state->m_RTState == TSTATE_KILL) {
			Sleep(25);
		}
		CloseThreadHandle(state->m_hThisThread);
		state->m_hThisThread = 0;
	}

	CLOSE_NOTIFIER(state->m_hReadThreadNotifier);
	// finally empty any queues.
    while (getUplinkBufferSize(state)) {
        removeUplinkBufferFront(state);
    }
    while (getDownlinkBufferSize(state)) {
        removeDownlinkBufferFront(state);
    }
    LDDebugInform("[%d] Shutdown stats: AckTMOs:%d  RxTmos:%d  CsumErrors:%d",
        state->m_DevIndex, state->m_Llpstat.AckTMOs, state->m_Llpstat.RxTmos,
        state->m_Llpstat.CsumErrors);
    LDDebugInform("[%d] Shutdown stats: CpFails:%d  ULDuplicates:%d  UlDiscarded:%d  MsgRejects:%d",
       state->m_DevIndex, state->m_Llpstat.CpFails, 
       state->m_Llpstat.ULDuplicates, state->m_Llpstat.UlDiscarded, 
       state->m_Llpstat.MsgRejects);
}

//////////////////////////////////////////////////////////////////////
// Mostly we create the reader thread.
//////////////////////////////////////////////////////////////////////
#define U50_MAC_WAIT		500		// MS
short U50LinkStart(struct U50LinkState *state, PORT_HANDLE hComPort, DWORD baudrate, U50OpenMode mode)
{
    int macRetries = 2;
	struct timespec ts;
	state->m_hComPort = hComPort;
	state->m_Options = (DCMP_BLIND|DCMP_DEFAULT);
	state->m_OpenMode = mode;

	OsalCreateEvent(&state->m_hReadThreadNotifier);
    OsalCreateEvent(&state->m_hReadMACNotifier);
	state->m_AckTimeoutStartValue = baudrate >= 115200 ? ACK_TIMEOUT : (WORD)(ACK_TIMEOUT * (115200/baudrate));
	state->m_TMOCount = 0;
	state->m_AckTimeoutPhase = 0;
	state->m_tCountKeepalive = OsalGetTickCount();
	state->m_tLogThrottle = 0;
	state->m_RxSequence = ~S10MASK_SEQN;	// Force mismatch on first frame.
	state->m_TxSequence = 0;
	state->m_NiCmdLocal = 0;
	state->m_bFreeDownlinkMsg = state->m_DownlinkAck = FALSE;
	state->m_StartupIndex = 0;
	state->m_UplinkLength = state->m_RxCountRead = state->m_NextRxCount = 0;
	memset(&(state->m_Llpstat), 0, sizeof(state->m_Llpstat));
	state->m_Llpstat.Size = sizeof(state->m_Llpstat);
	state->m_UplinkLvdp = state->m_pDownlinkMsg = NULL;
	state->m_expectedResponse = 0;
	state->m_partialLen = 0;
	memset(&state->m_downlinkRequest, 0, sizeof(state->m_downlinkRequest));
	state->m_UplinkReadPtr = NULL;
    state->m_bWaitForMAC = TRUE;
    state->m_bHaveMAC = FALSE;
	getnstimeofday(&ts);
	state->m_tStartup = ts.tv_sec;

	smpResetReader(state);
	smpReaderStateZap(state);
	smpClearAckTimerIdle(state);
	TMR_Stop(state->m_ReadStartTimer);
	TMR_Stop(state->m_RejectTimer);
	// Send a Resync to get things back in sync (sequence numbers and the like)
	smpDlCpNow(state, CpNiResync, 0);

	if (!WaitThreadStart(state)) {
		return LDVX_INITIALIZATION_FAILED;
	}
    // Get perm MAC addr, do before launching TheReaderThread!
    LDDebugInform("Link Start, acquire embedded MAC");
    while (macRetries--) {
        U50LinkWrite(state, (const pLDV_Message) MsgNeuronID);
        OsalWaitForEvent(state->m_hReadMACNotifier, U50_MAC_WAIT);
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
	return LDV_OK;
}

short U50LinkRead(struct U50LinkState *state, pLDV_Message pMsg, int iSize)
{
	short ldvRet = LDV_NO_MSG_AVAIL;
	smpEnterCriticalSection(state);
	if (getUplinkBufferSize(state)) {
		pLONVXD_Buffer pdqd = getUplinkBufferFront(state);
		int iCpyLength = lonvxdTotalLength(pdqd);
		if (iCpyLength <= iSize) {
			memcpy(pMsg, pdqd, iCpyLength);
			// then do the cmd / length shuffle
			if(pdqd->Length == EXT_LENGTH)
			{
				pLDV_ExtMessage pexm = (pLDV_ExtMessage)pMsg;
				pLONVXD_ExtBuffer pexb = (pLONVXD_ExtBuffer)pdqd;
				pexm->ExtFlag = EXT_LENGTH;
				pexm->ExtLength = endianSwap16(pexb->ExtLength);
				pexm->NiCmd = pexb->NiCmd;
			}
			else
			{
				pMsg->Length = pdqd->Length-1;
				pMsg->NiCmd = pdqd->NiCmd;
			}
//			delete pdqd;
            removeUplinkBufferFront(state);
			ldvRet = LDV_OK;
			// need to restart anything here?
		} else
			ldvRet = LDV_INVALID_BUF_LEN;
    }
	smpLeaveCriticalSection(state);
	return ldvRet;
}

//////////////////////////////////////////////////////////////////////
short U50LinkWrite(struct U50LinkState *state, const pLDV_Message pMsg) {
	short ldvRet = LDV_NO_BUFF_AVAIL;
	smpEnterCriticalSection(state);
	if (getDownlinkBufferSize(state) < DOWNLINK_BUF_COUNT)
	{
		// Queue it
		pLONVXD_Buffer pdeq = NULL;
		if(pMsg->Length == EXT_LENGTH)
		{
			// this is an extended message
			const LDV_ExtMessage *pexm = (LDV_ExtMessage *)pMsg;	// source
			pLONVXD_ExtBuffer pexb = NULL;
			pdeq = (pLONVXD_Buffer)allocateMemory(pexm->ExtLength + 4);
			pexb = (LONVXD_ExtBuffer *)pdeq;		// dest
			if(pexm->ExtLength <= MAXLONMSG)
			{
				memcpy(&pexb->ExpAppMessage, &pexm->ExpAppMessage, pexm->ExtLength);
				pexb->Length = EXT_LENGTH;
				pexb->ExtLength = endianSwap16(pexm->ExtLength + 1);
				pexb->NiCmd = pexm->NiCmd;
				ldvRet = LDV_OK;
			}
			else
				ldvRet = LDV_INVALID_BUF_LEN;
		} else {
			// Hook niLMODE commands from the client and translate to nicbMODE_L5 / nicbMODE_L2 commands.
			// Set the OpenMode so that if the NI resets we'll do the right thing.
			if (pMsg->NiCmd == niLMODE && pMsg->Length) {
				pMsg->NiCmd = (pMsg->ExpAppMessage[0] == 0) ? nicbMODE_L5 : nicbMODE_L2;
				pMsg->Length = 0;
				state->m_OpenMode = (pMsg->ExpAppMessage[0] == 0) ? U50_OPEN_LAYER5 : U50_OPEN_LAYER2;
			}
			pdeq = (pLONVXD_Buffer)allocateMemory(pMsg->Length + (2+2));	// pad to allow later possible length pad of +1
			memcpy(pdeq, pMsg, pMsg->Length + 2);
			pdeq->Length = pMsg->Length + 1;
			pdeq->NiCmd = pMsg->NiCmd;
			ldvRet = LDV_OK;
		}
        if (ldvRet == LDV_OK) {
			addToDownlinkBuffer(state, pdeq);
		}
	}
	smpLeaveCriticalSection(state);
	// some sort of signalling? yes.
	if (ldvRet == LDV_OK) {
		smpKickWriter(state);
    }
	return ldvRet;
}

//////////////////////////////////////////////////////////////////////
short U50LinkRegisterEvent(struct U50LinkState *state, OsalHandle hClientEvent)
{
	state->m_hClientEvent = hClientEvent;
	return LDV_OK;
}

//////////////////////////////////////////////////////////////////////
// Snapshot of statistics. Since the DWORD counters are considered atomic increments
// we don't worry about thread-safe issues.
int U50LinkGetStats(struct U50LinkState *state, pU50_Stats ps) 
{
	*ps = state->m_Llpstat;
	return sizeof(state->m_Llpstat);
}

//////////////////////////////////////////////////////////////////////
// CU50Link class
//////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////
// smpGetResponse
//
// Get the response expected for a given request
//
// Note on MIP Local Command Handling (do not change this label as it is a reference point)
//
// Note that the MIP has the following behavior:
// 1. The host sends down a CpNiCmdShort that requires a response (e.g., 0xE0)
// 2. The host gets an ack but MIP is still waiting to send the response via an uplink short (e.g., because the host
// has not yet acked a previously pending uplink short).
// 3. The host sends d own another CpNiCmdShort.  The command in #1 is overwritten and you'll never get the response.
// This is a bug in the MIP but rather than fix it, we'll make the driver deal with this (to be
// compatible with MIPs out there that have the bug).  The workaround is to wait for the response before
// sending another downlink local command.  The MIP fix is to not ack a downlink short if there is another
// downlink short up uplink short still pending.
//////////////////////////////////////////////////////////////////////
BYTE smpGetResponse(BYTE request)
{
	BYTE response = 0;
	switch (request)
	{
	case nicbSSTATUS:
	case nicbMODE_L5:
	case nicbMODE_L2:
		response = request;
		break;
	case nicbMODE_SSI:
		response = nicbMODE;
		break;
	case nicbINITIATE:
		response = nicbCHALLENGE;
	}
	return response;
}

//
// smpDlQueueCheck
//
// Get next downlink message to be sent.
//
void smpDlQueueCheck(struct U50LinkState *state)
{
	smpEnterCriticalSection(state);
	if(getDownlinkBufferSize(state))
	{
		state->m_pDownlinkMsg = getDownlinkBufferFront(state);
		state->m_bFreeDownlinkMsg = TRUE;
	}
	else
	{
		state->m_pDownlinkMsg = NULL;
	}
	smpLeaveCriticalSection(state);
}

// Reset reader state flags:
void smpReaderStateZap(struct U50LinkState *state)
{
	state->m_LlpRxState = LLPSIdle;
	// Drop this stuff:
	state->m_UplinkTailEscd = state->m_UlDuplicate = FALSE;
}

//////////////////////////////////////////////////////////////////////
// The condition that started the ACK timer has been satisfied.
// Remove the timer, un-signal it, and go to LLPTIdle.
void smpClearAckTimerIdle(struct U50LinkState *state)
{
	TMR_Stop(state->m_AckTimer);
	// Next timeout starts fast and then decays.
	state->m_AckTimeout = state->m_AckTimeoutStartValue;
	state->m_LlpTxState = LLPTIdle;
	state->m_TMOCount = 0;
}

//////////////////////////////////////////////////////////////////////
// Reset all of the read buffer pointers, offsets, counts.
// Buffer reset.
void smpResetReader(struct U50LinkState *state)
{
	// start HERE:
	state->m_LlpRxOffset = 0;
	// and HERE:
	state->m_UplinkLeftovers = 0;
	// and HERE:
	state->m_pULB = state->m_UplinkBuffer;
}

void smpKickWriter(struct U50LinkState *state)
{
	SIG_NOTIFIER(state->m_hReadThreadNotifier);
}

//////////////////////////////////////////////////////////////////////
// Determine if a checksum is valid.
//////////////////////////////////////////////////////////////////////
BOOL smpChecksumValid(struct U50LinkState *state, BYTE* pPkt, int len)
{
	BYTE sum = smpComputeChecksum(pPkt, len);
	BOOL isValid = sum == 0;

	if (!isValid)
	{
		state->m_Llpstat.CsumErrors++;
	}
	return isValid;
}

//////////////////////////////////////////////////////////////////////
// Only certain CP types use a real sequence number.
//////////////////////////////////////////////////////////////////////
void smpDlCpNow(struct U50LinkState *state, BYTE CpCode, BYTE CpParam)
{
	CodePacket cp;
	memset(&cp, 0, sizeof(cp));
	cp.Escape = S10ESC;
	// Duplicate detection only matters for messages so we send all others with TX# 0 (no duplicate detection).
	// Anomalous behaviors have been observed with local commands that could be tied to false duplicate detection so we just turn
	// it off for local commands for reduced chances of problems since all local commands are idempotent.
	if(CpCode == CpMsg)
		cp.Code = (BYTE) (CpCode | state->m_TxSequence);
	else
		cp.Code = CpCode;
	if(state->m_DownlinkAck)
	{
		// We set the ACK for good CP's rx'd, but for broken
		// data transfers don't send the ACK:
		if(CpCode != CpFail)
		{
			cp.Code |= S10MASK_ACK;
		}
		state->m_DownlinkAck = FALSE;
	}
	cp.Param = CpParam;
	cp.Csum = -smpComputeChecksum((BYTE*)&cp, 3);
	(void)CalLowerWrite(state, &cp, sizeof(cp));
    LDDebugTracePacket("CodePkt Tx", (BYTE*)&cp, SIZE_CP);
}

//////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////
void smpDlNiCmdLocal(struct U50LinkState *state)
{
	BYTE cmd;
	DCMPTXSTATE txstate;
	cmd = (BYTE)state->m_NiCmdLocal;
	// Certain local commands require waiting for the response (See MIP Local Command Handling)
	state->m_expectedResponse = smpGetResponse(cmd);
	txstate = state->m_expectedResponse ? LLPTRspWaitCP : LLPTAckWaitCP;
	smpDlCpNow(state, CpNiCmdShort, cmd);
	smpResetAckTimer(state, txstate);
}

// This needs to be in the format of the LONVXD_Buffer struct - length 1st
const unsigned char msgNdStatus[] = {1+14+(1), 0x22,
		0x6F, 0x08, (1),		// message tag:15 for 'private', response will be CMD/QUE of 0x16
		0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		ND|ND_REPORT_STATUS};
		
void smpPigReset(struct U50LinkState *state)
{
	state->m_tCountKeepalive = OsalGetTickCount();
}

void smpDlPig(struct U50LinkState *state)
{
	pLONVXD_Buffer l_pDownlinkMsg = state->m_pDownlinkMsg;
	state->m_pDownlinkMsg = (pLONVXD_Buffer)msgNdStatus;
	smpDlMsgNow(state);
	state->m_pDownlinkMsg = l_pDownlinkMsg;
	smpPigReset(state);
}

//////////////////////////////////////////////////////////////////////
// The NI is not responding. Panic.
//////////////////////////////////////////////////////////////////////
static char* shutdown_argv[] = 
	{ "/sbin/shutdown", "-r", "0", NULL };
	
void smpPanic(struct U50LinkState *state)
{
	LDDebugError("[%d] ACK timeout limit #%d, panic reboot.", state->m_DevIndex, state->m_AckTimeoutPhase);
	call_usermodehelper(shutdown_argv[0], shutdown_argv, NULL, UMH_NO_WAIT);
}

//////////////////////////////////////////////////////////////////////
// The NI is no longer accepting outgoing messages. Reset it.
//////////////////////////////////////////////////////////////////////
void smpResetNI(struct U50LinkState *state)
{
	LDDebugError("[%d] Message Reject timeout limit, resetting NI.", state->m_DevIndex);
	smpDlCpNow(state, CpNiCmdShort, nicbRESET);
}

//////////////////////////////////////////////////////////////////////
// Copy a message out of the buffer queue and into a transmission
// buffer, expanding for escaped data. Run a checksum.
//////////////////////////////////////////////////////////////////////
void smpDlMsgNow(struct U50LinkState *state)
{
	BYTE *pDCP, *pSRC, ThisByte;
 	WORD RealLength, ii;
	BYTE *dlBuffer;
 	BYTE CSum;

 	smpDlCpNow(state, CpMsg, 1);

	pSRC = (BYTE *)&(state->m_pDownlinkMsg)->Length;
	if (state->m_pDownlinkMsg->Length == S10ESC && state->m_Llpstat.MipVersion <= SMIP_VERSION_FENCE) {
		// Previous U60 SMIP versions had an issue with one length value. Pad this. The allocated memory was already padded a bit.
		state->m_pDownlinkMsg->ExpAppMessage[state->m_pDownlinkMsg->Length-1] = 0;		// -1 since Length includes the NiCmd
		state->m_pDownlinkMsg->Length++;
	}
	RealLength = ii = lonvxdTotalLength(state->m_pDownlinkMsg);
	dlBuffer = allocateMemory(RealLength * 2 + 4);
 	pDCP = dlBuffer;
	CSum = -smpComputeChecksum(pSRC, RealLength);

	while(ii--)
	{
		ThisByte = *pDCP++ = *pSRC++;
		if(ThisByte == S10ESC)
		{
			*pDCP++ = S10ESC;
			RealLength++;
		}
		if(RealLength >= (SIZE_DLB-2))
		{
			break;
		}
	}
	if((*pDCP++ = CSum) == S10ESC)
	{
		*pDCP++ = S10ESC;
		RealLength++;
	}
	RealLength++;
	smpResetAckTimer(state, LLPTAckWaitMsg);
	(void)CalLowerWrite(state, dlBuffer, RealLength);
    LDDebugTracePacket("Message Tx", (BYTE*)dlBuffer, RealLength);
    freeMemory(dlBuffer);
}


//////////////////////////////////////////////////////////////////////
// Request a CP.  We don't do it directly since we only want these sent via the TX thread.
//////////////////////////////////////////////////////////////////////
void smpInitiateCp(struct U50LinkState *state, BYTE cmd)
{
	// cmd should never be out of bounds - but safety first...
	if (cmd < CpMsgQueueCount)
	{
		state->m_downlinkRequest[cmd] = TRUE;
		smpKickWriter(state);
	}
}

//////////////////////////////////////////////////////////////////////
// smpInitiateCps
//
// Initiate any requested CPs.
//////////////////////////////////////////////////////////////////////
void smpInitiateCps(struct U50LinkState *state)
{
	int i;
	for (i=0; i<CpMsgQueueCount; i++)
	{
		if (state->m_downlinkRequest[i])
		{
			smpDlCpNow(state, i, 0);
			state->m_downlinkRequest[i] = FALSE;
		}
	}
}


//////////////////////////////////////////////////////////////////////
// Plunk in a new value into the Ack Timer.
void smpResetAckTimer(struct U50LinkState *state, DCMPTXSTATE NewState)
{
	TMR_Start(state->m_AckTimer);
	state->m_LlpTxState = NewState;
}


//////////////////////////////////////////////////////////////////////
// smpMessageComplete
//
// Called on an ack and during cleanup to free any outstanding message.
//////////////////////////////////////////////////////////////////////
void smpMessageComplete(struct U50LinkState *state)
{
	// Make sure we have a message just in case (this is called in clean up cases
	// where there might not be a message pending).
	smpEnterCriticalSection(state);
	if (state->m_pDownlinkMsg)
	{
		state->m_pDownlinkMsg = NULL;
		if (state->m_bFreeDownlinkMsg)
		{
			// remove from DL queue
			if (getDownlinkBufferSize(state)) {
                removeDownlinkBufferFront(state);
			}
			state->m_bFreeDownlinkMsg = FALSE;
		}
		TMR_Stop(state->m_RejectTimer);
	}
	smpLeaveCriticalSection(state);
	smpClearAckTimerIdle(state);
}

//////////////////////////////////////////////////////////////////////
// smpTxComplete
//
// Indicate a transaction is complete.  Could be due to an ack or a local command response.
//////////////////////////////////////////////////////////////////////
void smpTxCompleteModal(struct U50LinkState *state)
{
	smpUplinkAckd(state);
	smpKickWriter(state);
}

void smpTxComplete(struct U50LinkState *state)
{
	smpTxCompleteModal(state);
#if U50_LINK_TRACE
	if (state->m_AckTimeoutPhase >= 2) {
		LDDebugNotice("[%d] ACK mode restored.", state->m_DevIndex);
	}
#endif
	state->m_AckTimeoutPhase = 0;
}

//////////////////////////////////////////////////////////////////////
// Bump the TX Sequence -
//////////////////////////////////////////////////////////////////////
void smpBumpTxSequence(struct U50LinkState *state)
{
	WORD Txs;
	Txs = ((state->m_TxSequence + S10INC_SEQN) & 0xFF);
	if(Txs == 0)
		Txs = S10INC_SEQN;
	state->m_TxSequence = Txs;	
}

//////////////////////////////////////////////////////////////////////
// On uplink ACK: Free resources and bump tx sequence.
// Look for overlapped writes since we may be freeing up local
// buffer space.
//////////////////////////////////////////////////////////////////////
void smpUplinkAckd(struct U50LinkState *state)
{
	if (state->m_LlpTxState == LLPTAckWaitCP || state->m_LlpTxState == LLPTRspWaitCP)
	{
		state->m_NiCmdLocal = 0;
		smpClearAckTimerIdle(state);
	}
	else if (state->m_LlpTxState == LLPTAckWaitMsg)
	{
		smpMessageComplete(state);
	}
	smpBumpTxSequence(state);
	state->m_expectedResponse = 0;
}

//////////////////////////////////////////////////////////////////////
// Special version that handles local command request/response
//////////////////////////////////////////////////////////////////////
void smpUplinkQueue(struct U50LinkState *state, LONVXD_Buffer *lvdp)
{ 
	if (lvdp->Length != EXT_LENGTH && lvdp->NiCmd == nicbSSTATUS)
	{
		state->m_neuronMipVersion = lvdp->ExpAppMessage[1];
		state->m_Llpstat.MipVersion = state->m_neuronMipVersion;
		state->m_Llpstat.MipMode = lvdp->ExpAppMessage[2];
		LDDebugInform("MIP status returned: %02X %02X %02X %02X",
			lvdp->ExpAppMessage[0],
			lvdp->ExpAppMessage[1],
			lvdp->ExpAppMessage[2],
			lvdp->ExpAppMessage[3]);
		if (state->m_neuronMipVersion >= 0x90) {
			state->m_supportsExBuffers = 1;
		} else {
			struct u50_priv* priv = get_priv(state);
			priv->dev->mtu = MAXLONMSGNOEX;
		}
	}
	else {
        int iCpyLength = lonvxdTotalLength(lvdp) + 1;
        if (state->m_bWaitForMAC) {
            BYTE *buf = (BYTE *)lvdp;
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
            LDV_Message *pMsg = allocateMemory(iCpyLength+4);
            memcpy(pMsg, lvdp, iCpyLength);
            if(lvdp->Length == EXT_LENGTH)
            {
                pLDV_ExtMessage pexm = (pLDV_ExtMessage)pMsg;
                pLONVXD_ExtBuffer pexb = (pLONVXD_ExtBuffer)lvdp;
                pexm->ExtFlag = EXT_LENGTH;
                pexm->ExtLength = endianSwap16(pexb->ExtLength)-1;
                pexm->NiCmd = pexb->NiCmd;
            }
            else
            {
                pMsg->Length = lvdp->Length-1;
                pMsg->NiCmd = lvdp->NiCmd;
            }
            if (pMsg->NiCmd == 0x16 &&						// niCOMM|niRESPONSE
				pMsg->Length > (3+11) &&					// MsgHdr + ExpAddr
				(pMsg->ExpAppMessage[0] & 0x0F) == 0x0F) {	// tag:15
				; // local: do not post, or maybe process locally?
			} else {
				u50_bump(get_priv(state), (uint8_t*)pMsg, iCpyLength);
			}
            freeMemory(pMsg);
        }
	}
	state->m_DownlinkAck = TRUE;
	// Finally got the local command response so we consider the transaction complete (See MIP Local Command Handling)
	// Note that this must follow the uplink processing for the following reason.  Uplink processing stores the challenge
	// and the TX thread needs that to properly send the reply.
	if (state->m_expectedResponse == lvdp->NiCmd)
	{
		smpTxComplete(state);
	}
#ifndef U50_KERNEL
	//causes kernel panic - something incorrectly setting variable? is nulled 
	//out in init and trace never hit in the only place it is set.
	SIG_NOTIFIER(state->m_hClientEvent);
#endif
}


//////////////////////////////////////////////////////////////////////
// Take a look at a Code Packet, read at gslp.pULB.
// All sorts of behavior goes on here - even uplink dumps.
//////////////////////////////////////////////////////////////////////
void smpCodePacketRxd(struct U50LinkState *state, BOOL bRxReset)
{
	unsigned int ii;
	WORD Seqn, Cpcode;
	LONVXD_Buffer *lvdp;
	BYTE *pcp;
	BOOL bCpFailReject;

	// entered in LLPSIdle state
	pcp = state->m_pULB;
	// First look for a problem case - a partial CP caused by
	// front-end junk (could happen).
	if(pcp[0] != S10ESC)
	{
		// 1st byte was not the escape code!
		// see if it is in the CP anywhere, if it is we may need to
		// do a bit more reading to pick up the whole CP.
		for(ii=1; ii<SIZE_CP; ii++)
		{
			if(pcp[ii] == S10ESC)
			{
				// reset the start packet pointer to later in the buffer
				state->m_pULB = pcp+ii;
				// reader needs to know where to pick up, offset to
				// new pULB:
				state->m_LlpRxOffset = SIZE_CP - ii;
				return;
			}
		}
		// not found, give up and start over.
		smpResetReader(state);
		return;
	}

	if (state->m_RxCountRead < SIZE_CP - state->m_LlpRxOffset)
	{
		// reader needs to know where to pick up, offset to new pULB:
		state->m_LlpRxOffset += state->m_RxCountRead;
		return;
	}

	// after this point we can reset the receiver:
	if(bRxReset)
		smpResetReader(state);

	// Check out the Checksum.
	if (!smpChecksumValid(state, pcp, SIZE_CP))
	{
		return;
	}
    LDDebugTracePacket("CodePkt Rx", pcp, SIZE_CP);
	Cpcode = pcp[1] & S10MASK_CPC;
	Seqn = (pcp[1] & S10MASK_SEQN);
	// CpFail & CpMsgReject mostly get ignored for ACKs and SEQNs
	bCpFailReject = ((Cpcode == CpFail) || (Cpcode == CpMsgReject));
	if (Cpcode)
	{
		if (state->m_RxSequence == Seqn && !bCpFailReject)
		{
			// Duplicate! Process it anyway a bit in order
			// to be able to spool/dump any following messages
			// It will actually go into a buffer, but won't be
			// queued.
			state->m_UlDuplicate = TRUE;
			state->m_Llpstat.ULDuplicates++;
		}
		state->m_RxSequence = Seqn;
	}

	// Pick off the ACK bit and process it.  Note we probably don't need to exclude CpFail because it should never have the ack bit set.  But, we leave it here just in case.
	if((pcp[1] & S10MASK_ACK) && !bCpFailReject) {
		// Note that acks are essentially ignored for local request/response commands (see MIP Local Command Handling).
		if (state->m_LlpTxState != LLPTRspWaitCP)
		{
			smpTxComplete(state);
		}
	}

	switch(Cpcode)
	{
	case CpMsg:
		// The message count may be ONE or TWO.
		// If it is ONE then stuff a ZERO, else TWO for TWO.
		// (it's in the Param field)
		state->m_LlpRxState = LLPSReadyRec1;
		if(pcp[2] != 1)
		{
			state->m_LlpRxState = LLPSIdle; // others, inc. (0) not allowed.
			state->m_DownlinkAck = TRUE; // just make it go away.
		}
		// return and let the reader thread get the rest.
		break;

	case CpMsgAck:
		if(state->m_LlpTxState == LLPTMsgAckWait)
		{
			state->m_LlpTxState = LLPTMsgGo;
		}
		break;
	case CpMsgReq:
		smpInitiateCp(state, CpMsgAck);
		break;
	case CpNiCmdShort:
		state->m_DownlinkAck = TRUE;
		if(!state->m_UlDuplicate)
		{
			if(pcp[2] == nicbACK || pcp[2] == nicbNACK)
			{
				// no DL ack for these required.
				break;
			}
			// The local niCMD is in the Param field.
			// Look out for certain commands:
			if(pcp[2] == nicbRESET)
			{
				// restart many states...and force flush
				// any pending downlink.
				state->m_LlpTxState = LLPTIdle;
				state->m_TxSequence = 0;
				state->m_StartupIndex = 0;
			}
			// Queue it into our local uplink buffer scheme.
            // Translate runt packet error packets.
			lvdp = &state->m_UplinkMsg;
			lvdp->NiCmd = pcp[2];
	        if((pcp[2] & 0xF0) == nicbERROR)
			{
				lvdp->Length = 5;
				// zero these fields
				memset(lvdp->ExpAppMessage, 0, 4);
			}
			else
      			lvdp->Length = 1;
			smpUplinkQueue(state, lvdp);
		}
		smpReaderStateZap(state);
		break;

	case CpMsgReject:
		state->m_Llpstat.MsgRejects++;
        // Bah! No Room Downlink.
		if(state->m_LlpTxState == LLPTMsgAckWait || state->m_LlpTxState == LLPTAckWaitMsg)
		{
			smpClearAckTimerIdle(state);
			// This timer gets stopped once an ACK is received.
			if (!TMR_Running(state->m_RejectTimer)) {
				TMR_Start(state->m_RejectTimer);
			} else if (TMR_Elapsed(state->m_RejectTimer, SMP_MSECS_REJECT)) {
				TMR_Stop(state->m_RejectTimer);
				// Timer limit reached.
				smpResetNI(state);
			}
			// keep it at Idle state and keep banging away at it.
			// it's also required that the sequence # be cycled since the CP
			// itself was accepted.
		}
		else {
#if U50_LINK_TRACE
			// This isn't necessarily an error.
			LDDebugNotice("[%d] Unknown CpMsgReject Cause in state %d.", state->m_DevIndex, state->m_LlpTxState);
#endif
		}
		break;

	case CpFail:
		smpTxComplete(state); //Don't keep repeating a failed message
		smpClearAckTimerIdle(state);
		state->m_Llpstat.CpFails++;
		break;

	case CpNull:
		break;

	} // end of switch(cpc)
}

//////////////////////////////////////////////////////////////////////
// Copy source is always at <pULB>, remove any escaped codes.
// Be prepared to encounter an embedded CP!
// Adjust the <UplinkReadPtr>, when we are done (with the whole message
// we won't need it.
// Reset the reader when finished.
//////////////////////////////////////////////////////////////////////
void smpUplinkCopy(struct U50LinkState *state)
{
	BYTE *pSrc, *pDst, ThisByte;
	unsigned int delta;
	WORD ReadCount = state->m_RxCountRead;

	pSrc = state->m_pULB;
	pDst = (BYTE *)state->m_UplinkReadPtr;

	// first, test for a prior tail escaped condition.
	if(state->m_UplinkTailEscd)
	{
		if(*pSrc == S10ESC)
		{
			// Escaped data.
			if(ReadCount)
				ReadCount--;
			pSrc++;
			// <UplinkLength> was bumped to continue, now dec. it.
			if(state->m_UplinkLength)
				state->m_UplinkLength--;
		}
		// else, if not S10ESC, then don't modify the ReadCount. The following
		// code will see this as the start of a CP.
		state->m_UplinkTailEscd = FALSE;
	}

	while(ReadCount)
	{
		ThisByte = (*pDst++ = *pSrc++);
		if(ThisByte == S10ESC)
		{
			if(ReadCount == 1) { // S10ESC at the end of the stream!
				state->m_UplinkTailEscd = TRUE;
				break;
			}
			else if(*pSrc != S10ESC)
			{ // okay to look ahead for 2nd ESC
				// Start of CP detected! Blow off this message xfer.
				// If in message xfer state then RX data went missing. This is probably a retry.
				// N.A. this test is redundant - smpUplinkCopy() only called from these states.
				if(state->m_LlpRxState == LLPSReadyRec1 || state->m_LlpRxState == LLPSReadyRec2)
				{
#if U50_LINK_TRACE
					LDDebugNotice("[%d] CP received while reading message, ReadCount: %d, CP: %02X", state->m_DevIndex, ReadCount, *pSrc);
#endif
					// Typically this is "ReadCount: 2, CP: 10" (start of an ACK)
					// Does the U50 send an ACK CP after sending the CpMsg CP?
					// Not according to the source - it sends the CP then the message in that order.
					state->m_Llpstat.RxTmos++;
					// Clobber the sequence # so that the retry won't get tossed.
					state->m_RxSequence = 0;
				}
				state->m_pULB = --pSrc;  // start back here.
				state->m_LlpRxState = LLPSIdle;
				// Decide if there is CP size worth of bytes read.
				// There may be useable data following this CP so
				// keep at this buffer location
				if(ReadCount >= SIZE_CP)
				{
					smpCodePacketRxd(state, FALSE);
					// return and let the higher layer deal with the
					// current state.
					state->m_UplinkLeftovers = ReadCount - SIZE_CP;
				}
				else
				{
					// might be more coming.
					state->m_LlpRxOffset = ReadCount;
				}
				return;

			}
			else
			{ // Escaped data, skip 2nd escape.
				pSrc++;
				ReadCount--;
			}
		}
		ReadCount--;
	} // end of while(ReadCount)
	// Next read can start at the beginning of this buffer.
	smpResetReader(state);
	// Reduce the <UplinkLength> field by the amount of data copied.
	delta = pDst - (BYTE *)state->m_UplinkReadPtr;
	if (delta > state->m_UplinkLength)
	{
		LDDebugNotice("[%d] Uplink Length Underflow (Delta:%d Len:%d)", state->m_DevIndex, delta, state->m_UplinkLength);
		state->m_UplinkLength = 0;
	}
	else
	{
		state->m_UplinkLength -= delta;
		if(state->m_UplinkLength > SIZE_ULB)
		{
			LDDebugNotice("[%d] Uplink Length Overflow (Delta:%d Len:%d)", state->m_DevIndex, delta, state->m_UplinkLength);
			state->m_UplinkLength = 0;
		}
	}
	// update dest pointer:
	state->m_UplinkReadPtr = pDst;
	// look out for pesky trailing escapes:
	if(state->m_UplinkTailEscd)
		state->m_UplinkLength++;
	// What reader state now?
	if(state->m_UplinkLength)
	{
		state->m_LlpRxState = LLPSReadyRec2; // keep going.
	}
	else
	{
		// Verify the message before queueing. The ACK bit was set
		// when we received the CpMsg.
		int checkLength = state->m_UplinkLvdp->Length + 2;
		if (state->m_UplinkLvdp->Length == EXT_LENGTH) {
			pLONVXD_ExtBuffer lvdex = (pLONVXD_ExtBuffer)state->m_UplinkLvdp;
			// Previous U60 SMIP versions had a broken EXT_LENGTH transfer handler. Toss & ACK them.
			if (state->m_Llpstat.MipVersion <= SMIP_VERSION_FENCE) {
				state->m_LlpRxState = LLPSIdle;
				state->m_DownlinkAck = TRUE;
				smpDlCpNow(state, CpNull, 0);
				return;
			}
			checkLength = endianSwap16(lvdex->ExtLength)+4;
		}
        LDDebugTracePacket("Message Rx", &state->m_UplinkLvdp->Length, checkLength);
		
		if (smpChecksumValid(state, &state->m_UplinkLvdp->Length, checkLength))
		{
			state->m_LlpRxState = LLPSRecComplete;
		}
		else
		{
			state->m_LlpRxState = LLPSIdle;
			smpInitiateCp(state,CpFail);
            // Clobber the sequence # so that the retry won't get tossed.
			state->m_RxSequence = 0;
		}
	}
}

//////////////////////////////////////////////////////////////////////
// Chew on bytes read into the local uplink buffer.
//////////////////////////////////////////////////////////////////////
void smpReadProcess(struct U50LinkState *state)
{
	// Read occurred of one or more bytes.
	switch(state->m_LlpRxState)
	{
	case LLPSIdle:
		// process the CP:
		smpCodePacketRxd(state, TRUE);
		break;
	case LLPSReadyRec1:
		if (state->m_partialLen) {
			state->m_pULB -= state->m_partialLen;
			state->m_RxCountRead += state->m_partialLen;
			state->m_partialLen = 0;
		}
		// At the start of a message packet.
		// Have read in the front of the message packet.
		if(state->m_pULB[0] == S10ESC)
		{
			if(state->m_pULB[1] != S10ESC)
			{
				// This is a new CP!
				state->m_LlpRxState = LLPSIdle;
				smpCodePacketRxd(state, FALSE);
				return; // out of this case.
			}
			else
			{
				// This is an escaped data (length).
				// Just let the following code use the S10ESC as the length,
				// and smpUplinkCopy distill out the escape.
			}
		}
		// Save the length so we know how much more we need
		// to read on this message packet. Bump this by one
		// so that the checksum is included. Bump it by one
		// again because the first call to smpUplinkCopy()
		// will adjust the length including the length (and
		// the length is not self referencial).
		// Acquire a buffer even if duplicate.
		state->m_UplinkLvdp = &state->m_UplinkMsg;
		if(state->m_pULB[0] == EXT_LENGTH)	// extended length
		{
			// N.A. m_PartialLengthBuffer is never referenced...
			//If we don't have the full extended length then wait for it to arrive.
			if (state->m_RxCountRead < 3) {
				state->m_partialLen = state->m_RxCountRead;
				if (state->m_RxCountRead == 1) {
					state->m_PartialLengthBuffer[1] = state->m_pULB[0];
				} else {
					state->m_PartialLengthBuffer[0] = state->m_pULB[0];
					state->m_PartialLengthBuffer[1] = state->m_pULB[1];
				}
				return;
			}
			// 1st length byte won't be escaped.
			// If the 2nd length byte is escaped then grab the rest of the length after.
			// remember endian swap
			state->m_UplinkLength = ((WORD)state->m_pULB[1] << 8) + 1 + 1 + 1 + 1;	// include ext length fields (2)
			if(state->m_pULB[2] == S10ESC)
			{
				state->m_UplinkLength += state->m_pULB[3] + 1;
			}
			else
			{
				state->m_UplinkLength += state->m_pULB[2];
			}
			if(state->m_UplinkLength > MAXLONMSG+4)
			{
				// really bad length!
				LDDebugNotice("[%d] Out of range uplink length: %d", state->m_DevIndex, state->m_UplinkLength);
				smpReaderStateZap(state);
				return;
			}
		}
		else
		{
			state->m_UplinkLength = state->m_pULB[0] + 1 + 1;
		}
		// set up the read dest pointer.
		// smpUplinkCopy will copy the length field.
		state->m_UplinkReadPtr = &state->m_UplinkLvdp->Length;
        state->m_LlpRxState = LLPSReadyRec2;
		// Fall Into -->
	case LLPSReadyRec2:
		// In the middle of a message packet.
		// copy & distill what we have read:
		smpUplinkCopy(state);
		break;
	case LLPSRecComplete:
		break;

	} // end of switch
	if(state->m_LlpRxState == LLPSRecComplete)
	{
		// post this message, look for a possible second
		// message.
		if(!state->m_UlDuplicate)
		{
			smpUplinkQueue(state, state->m_UplinkLvdp);
			smpPigReset(state);		// reset this on uplink
		}
		else
		{
			state->m_DownlinkAck = TRUE; // make it go away
		}
		// Look for a second message packet
		smpReaderStateZap(state);
	}
}

static void U50DumpRawLTV2(BYTE *bp, WORD nCount)
{
#if 0
	char *pBuf = allocateMemory(1024);
	char hcBuf[16];
	int pbCount;
	if (!pBuf)
		return;

	strcpy(pBuf, KERN_INFO "U50: LTV2 Send: ");
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
// Look for either enqueued downlink traffic, or retries.
//////////////////////////////////////////////////////////////////////
void smpWriteService(struct U50LinkState *state)
{
	int iTxState;

	switch(state->m_LlpTxState)
	{
	// First test for a retry case. If so, then simply start over.
	case LLPTRspWaitCP:
	case LLPTAckWaitCP:
	case LLPTAckWaitMsg:
	case LLPTMsgAckWait:
		if (!TMR_Elapsed(state->m_AckTimer, state->m_AckTimeout))
		{
			// not timed out, go away.
			break;
		}
		smpNeuronHealthEvent();
		iTxState = (int)state->m_LlpTxState;
		state->m_LlpTxState = LLPTIdle;
		state->m_Llpstat.AckTMOs++;
		// Look for runt CPs in the RX path that could clog up things.
		if (state->m_LlpRxState == LLPSIdle && state->m_LlpRxOffset) {
			smpResetReader(state);
		}
		if (++state->m_TMOCount >= 2) {
			if (state->m_AckTimeoutPhase < 5) {
				// workaround - for repeated ack timeouts try a re-sync by requesting ND Status.
#if U50_LINK_TRACE
				struct u50_priv *priv = get_priv(state);
#endif
				smpBumpTxSequence(state);
				// Just overwrite what's at state->m_pDownlinkMsg
				state->m_pDownlinkMsg = (pLONVXD_Buffer)msgNdStatus;
				smpDlMsgNow(state);
				if (++state->m_AckTimeoutPhase == 0)
					state->m_AckTimeoutPhase--;
#if U50_LINK_TRACE
				LDDebugNotice("[%d] ACK timeout limit #%d, TXS: %02X, requesting status.",
					state->m_DevIndex, state->m_AckTimeoutPhase, state->m_TxSequence);
				LDDebugNotice("[%d] CsumErrors:%d  CpFails:%d",
					state->m_DevIndex, state->m_Llpstat.CsumErrors, state->m_Llpstat.CpFails);
				if (priv) {
					LDDebugNotice("[%d] RCount currently: %d, RxOffset %d",
						state->m_DevIndex, priv->rcount, state->m_LlpRxOffset);
				}
				LDDebugNotice("[%d] TX state %d, RX state %d",
					state->m_DevIndex, iTxState, state->m_LlpRxState);
#endif
			} else {		// just do this once.
				struct timespec ts;
				getnstimeofday(&ts);
				if (state->m_bHaveMAC && (ts.tv_sec - state->m_tStartup) > 60) {
					smpPanic(state);
					state->m_tStartup = ts.tv_sec;		// Don't keep doing this too rapidly.
				} else {	// not so fast..
					state->m_AckTimeoutPhase = 0;
				}
			}
			state->m_TMOCount = 0;
		} else {
#if U50_LINK_TRACE
			LDDebugNotice("[%d] ACK timeout (first case)", state->m_DevIndex);
#endif
		}
		// fall into:
	case LLPTIdle:
		// First look for post-reset startup work:
		if(state->m_StartupIndex != -1)
		{
			if (state->m_StartupIndex == 0)
			{
				// In case the downlink message or local command caused a reset, then free it.  Note that we could
				// also be freeing a message that never made it so we just have to take that chance.
				smpMessageComplete(state);
				state->m_NiCmdLocal = 0;
			}
			if (state->m_pDownlinkMsg == NULL && state->m_NiCmdLocal == 0)
			{
				const BYTE *pCmds;
				BYTE cmd;
				// startup commands may cause resets, so use longer ack timeout.
				if(state->m_StartupIndex == 0)
				{
					state->m_AckTimeout = STARTUP_ACK_TIMEOUT;
				}
				if (state->m_OpenMode == U50_OPEN_LAYER2 || state->m_OpenMode == U50_OPEN_PA)
					pCmds = StartupCommandsL2;
				else if (state->m_OpenMode == U50_OPEN_LAYER5)
					pCmds = StartupCommandsL5;
				else
					pCmds = StartupCommandsDef;
				cmd = pCmds[state->m_StartupIndex++];
				// Reply requires extra data so can't use command short - so send a DL msg.
				if (cmd == 0)
				{
					// We're done.
					state->m_StartupIndex = -1;
				}
				else
				{
					state->m_NiCmdLocal = cmd;
				}
			}
		}
		if (state->m_NiCmdLocal)
		{
			smpDlNiCmdLocal(state);
		}
		else
		{
			// Next check for messages queued.
			if(state->m_pDownlinkMsg == NULL)
			{
				smpDlQueueCheck(state);
			}

			if(state->m_pDownlinkMsg)
			{
				// Is this a message or local NI command?
				if(state->m_pDownlinkMsg->Length == 1)
				{
					// NiCmdLocal is 0. Use it and free the message now.
					state->m_NiCmdLocal = state->m_pDownlinkMsg->NiCmd;
					smpMessageComplete(state);
					smpDlNiCmdLocal(state);
				}
				else
				{
					BOOL bDropit = FALSE;
					// It's a message.
					// AP-2549 - drop LTV1 packets for now.
					#if AP2549
					if (state->m_OpenMode != U50_OPEN_LAYER5 &&
						(state->m_pDownlinkMsg->NiCmd == (niCOMM|niTQ) || state->m_pDownlinkMsg->NiCmd == (niCOMM|niTQ_P)) &&
						(state->m_pDownlinkMsg->ExpAppMessage[1] & 0xC0) == 0x40) {		// LTV1 message
						//
						BYTE *pExpM = state->m_pDownlinkMsg->ExpAppMessage;
						U50DumpRawLTV2(pExpM, state->m_pDownlinkMsg->Length-1);
						//
						if (pExpM[IPV4_TOS] == 0 && pExpM[IPV4_PROTO] == 1) {					// ICMP 
							if (pExpM[IPV4_ICMP_TYPE] == 8 && pExpM[IPV4_ICMP_CODE] == 0) {		// ICMP ping
							/*
							if (pExpM[IPV4_DEST_ADDR+3] == 255) {	// broadcast?
								bDropit = TRUE;
							} else if ((pExpM[IPV4_DEST_ADDR+0] & 0xF0) == 0xE0) { // multicast?
								bDropit = TRUE;
							}
							*/
							} else {
								bDropit = TRUE;
							}
						}
					}
					#endif
					if (bDropit) {
						smpMessageComplete(state);
					} else if(state->m_Options & DCMP_BLIND) {
						smpDlMsgNow(state);
					} else {
						// Start a downlink message transfer.
						smpInitiateCp(state, CpMsgReq);
						smpResetAckTimer(state, LLPTMsgAckWait);
					}
				}
			}
		}
		break;
	case LLPTMsgGo:
		// Proceed with the downlink message.
		if(state->m_pDownlinkMsg)
		{
			smpDlMsgNow(state);
		}
		else
		{
			state->m_LlpTxState = LLPTIdle;
		}
		break;
	default:
		// some unused state.
		state->m_LlpTxState = LLPTIdle;
		break;
	} // end of switch

	// Send any CPs plus possibly an ack.
	smpInitiateCps(state);

	if (state->m_DownlinkAck)
	{
		// Nothing cleared the ack so force a null CP.
		smpInitiateCp(state, CpNull);
		smpInitiateCps(state);
	}
}

// This routine is created to replace the TMR_Remaining macro.  
// The issue was that there was a tiny window where TMR_Current would change during the logic of the TMR_Remaining macro
OsalTickCount TimerRemaining(Timer theTimer, WORD duration)  
{
    OsalTickCount currentTickCount = TMR_Current;
    BOOL isRunning = theTimer.bRunning; 
    unsigned long startValue = theTimer.startValue;
    return (!isRunning ? INFINITE : ((currentTickCount - startValue) > duration ? 0 : duration - (currentTickCount - startValue)));
}

//////////////////////////////////////////////////////////////////////
// The reader thread:
//////////////////////////////////////////////////////////////////////
DWORD TheReaderThread(struct U50LinkState *state)
{
	DWORD RdStatus;
	state->m_RTState = TSTATE_RUNNING;

	// . . . 
	while (state->m_RTState == TSTATE_RUNNING) {
		// Top of Reader processing -
		// 
		// prior to requesting a read on the com port calculate the expected length.
		// begin code pulled from SMP.CPP
		// 
		// Need to deal with <UplinkLeftovers>, treat this as pre-read data.
		if(state->m_UplinkLeftovers)
		{
			state->m_NextRxCount = state->m_RxCountRead = state->m_UplinkLeftovers;
			state->m_UplinkLeftovers = 0;
		}
		else
		{
			// Calculate what to do next regarding reads -
			// Based on the state of the LLP, (possibly) go into a blocked read state.
			switch(state->m_LlpRxState)
			{
			case LLPSIdle:
				// Expect a Code Packet OR reading a Code Packet.
				// How much bytes..
				state->m_NextRxCount = SIZE_CP - state->m_LlpRxOffset; // sizeof CP
				break;

			case LLPSReadyRec1:
				// Expect a message packet. First read in 4 bytes. At least
				// 4 bytes will appear, they will either be the message or
				// possibly another CP. We need to look at the front of the
				// message to determine its size. This can also handle two
				// escaped data values if that should occur.
				state->m_NextRxCount = SIZE_CP;
				// Reset the reader. When multiple message packets are coming
				// uplink the tail of the previous message should have been read
				// up to the end of that message only, no forward reading of a
				// subsequent message should have occurred.
				smpResetReader(state);
				break;

			case LLPSReadyRec2:
				// In the middle of a message packet.
				// Calculate the next read size. This may not read in the entire
				// message when there is embedded escaped data, in that case
				// another read will take care of it (and another if there are
				// escaped data at the end).
				state->m_NextRxCount = state->m_UplinkLength;
				break;

			case LLPSRecComplete:
				break;

			} // end of switch

			// Sanity check: I would like to know if this is screwed up:
			if((state->m_pULB + state->m_LlpRxOffset + state->m_NextRxCount) >= &state->m_UplinkBuffer[SIZE_ULB])
			{
				LDDebugNotice("[%d] Uplink Buffer Overrun.", state->m_DevIndex);
				smpResetReader(state);
			}
			state->m_RxCountRead = 0;
			// read from COM port.
			// remember that overlapped reads fill out the read-to buffer in the background. (um, that's a Windows thing)
			RdStatus = CalLowerRead(state, state->m_pULB + state->m_LlpRxOffset, state->m_NextRxCount, &state->m_RxCountRead);
			// if ERROR_IO_PENDING then wait.
			if (RdStatus == ERROR_IO_PENDING && state->m_RTState == TSTATE_RUNNING) {
				//////////////////////////////////////////////////////////////////////
				// sleep on the com port, or until kill notification, or a write event notification.
				// This is also handling "write" processing,
				// so the ACK timer needs to be involved.
				//////////////////////////////////////////////////////////////////////
				DWORD msWait = TMR_Remaining(state->m_AckTimer, state->m_AckTimeout);		// returns INFINITE if not running.
				if(msWait == INFINITE) {
					msWait = 1000;	// loop through once per second.
				} else if (msWait > 25) {
					msWait -= 25;	// a little quicker than the ACK timeout.
				}
				if (msWait) {
					OsalWaitForEvent(state->m_hReadThreadNotifier, msWait);//*1000);
				}
			}
			if (state->m_RTState != TSTATE_RUNNING)
				break;
		} // end of if/else UplinkLeftovers.

		// at the beginning of any NEW serial input start a total uplink timer to limit
		// how long we stay in the non-idle state.
		if (state->m_RxCountRead && state->m_LlpRxState == LLPSIdle)
		{
			TMR_Start(state->m_ReadStartTimer);
		}

		// Go on and process the uplink stuff.
		if (state->m_RxCountRead)
		{
			smpReadProcess(state);
			// In case we need to respond to something.  This could be more refined but it works...
			// smpKickWriter();
		}

		// don't get stuck in the non-idle state if a partial input shows up
		if ((state->m_LlpRxState != LLPSIdle || state->m_LlpRxOffset) && TMR_Elapsed(state->m_ReadStartTimer, READ_TIMEOUT))
		{
			smpResetReader(state);
			smpNeuronHealthEvent();
			// Maybe send CpFail if in LLPSReadyRec1 or 2? You bet!
			if (state->m_LlpRxState == LLPSReadyRec1 || state->m_LlpRxState == LLPSReadyRec2)
			{
				smpInitiateCp(state, CpFail);
			}
			// Zap the reader state flags.
			smpReaderStateZap(state);
			// Clobber the sequence # so that the retry won't get tossed.
			state->m_RxSequence = 0;
			state->m_DownlinkAck = FALSE;
			// peg a stat?
			state->m_Llpstat.RxTmos++;
#if U50_LINK_TRACE
			LDDebugNotice("[%d] Incomplete input stream, restart.", state->m_DevIndex);
#endif			
		}
//		if (CalLowerReadCount(state)) {
//			continue;		// more RX data to process!
//		}
		// "always do the write thing"
		smpWriteService(state);
		// "Keepalive"?
		if (1) {
			OsalTickCount tCount = OsalGetTickCount();
			if ((tCount - state->m_tCountKeepalive) > SMP_MSECS_KA) {
				smpDlPig(state);
			}
		}
	}
	state->m_RTState = TSTATE_STOPPED;		// sez we done.
	return 0;
}

BOOL WaitThreadStart(struct U50LinkState *state)		// returns TRUE if success
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
	// In the old SLTA driver we did this:
	// SetThreadPriority(state->m_hThisThread, THREAD_PRIORITY_TIME_CRITICAL);

	// Wait for thread creation to complete.
	dwTaskTime = OsalGetTickCount();
/*	while (state->m_RTState != TSTATE_IDLE) {
		Sleep(25);
		if (OsalGetTickCount() - dwTaskTime > 3000)
			return FALSE;
	}*/
	return TRUE;
}

