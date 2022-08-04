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
//
// Definitions private to the DLL.
///////////////////////////////////////////////////////////////////////////////
#pragma once

#include "Ldv32.h"
#include "platform.h"
#include "U50Driver.h"

// For now we just run at this baud rate:
#define SMPBAUD						115200

void LDDebugError(LPCSTR szFormat, ... );
void LDDebugInform(LPCSTR szFormat, ... );
void LDDebugNotice(LPCSTR szFormat, ... );
void LDDebugTracePacket(LPCSTR szType, BYTE *mp, WORD length);
PORT_HANDLE U50OpenComPort(LPCSTR szComPort);

#define COUNT_WaitObjects		2
//
///////////////////////////////////////////////////////////////////////////////
#define MAXLONMSGNOEX				240
#define MAXLONMSG					1280
// We limit the size of the queues in both directions:
#define DOWNLINK_BUF_COUNT		20		// was 4
#define UPLINK_BUF_COUNT		16

typedef struct 
{
	BYTE NiCmd;     // Network Interface Command
	BYTE Length;    // size of ExpAppMessage
	BYTE ExpAppMessage[MAXLONMSG];
} LDV_Message, *pLDV_Message;

#define SIZE_CHALLENGE 8
#define SIZE_MIP_KEY  6

// The message structures:
//#define SIZE_ULB  (MAXLONMSG+4)  // size of ul serial buffer (including expansions)
//#define SIZE_DLB  (MAXLONMSG+4)  // size of dl serial buffer (including expansions)
#define SIZE_ULB  ((MAXLONMSG+4)*2)  // size of ul serial buffer (including expansions)
#define SIZE_DLB  ((MAXLONMSG+4)*2)  // size of dl serial buffer (including expansions)

// The full message element as stored in this driver:
typedef struct LONVXD_Buffer {
	BYTE Length;					// size of NiCmd + ExpAppMessage
	BYTE NiCmd;						// Network Interface Command
	BYTE ExpAppMessage[MAXLONMSG+1];	// represents max size plus checksum.
	BYTE pad[3];
} LONVXD_Buffer, *pLONVXD_Buffer;

// Alternate LONVXD_Buffer, but assembled for extension messages
#pragma pack(1)
typedef struct LONVXD_ExtBuffer {
	BYTE Length;						// this would be EXT_LENGTH
	WORD ExtLength;						// remember any endian swapping
	BYTE NiCmd;							// Network Interface Command
	BYTE ExpAppMessage[MAXLONMSG+1];	// represents max size plus checksum.
} LONVXD_ExtBuffer, *pLONVXD_ExtBuffer;

// A short version used for nicbREPLY's
typedef struct LONVXD_BufferShort {
	BYTE Length;					// size of NiCmd + ExpAppMessage
	BYTE NiCmd;						// Network Interface Command
	BYTE ExpAppMessage[1+SIZE_CHALLENGE+1];	// represents max size plus checksum.
} LONVXD_BufferShort, *pLONVXD_BufferShort;

// A short version for local commands:
typedef struct LONVXD_CmdLocal {
	BYTE Length;
	BYTE NiCmd;					// Network Interface Command
} LONVXD_CmdLocal;

#pragma pack()
typedef enum {
	TSTATE_IDLE = 0,
	TSTATE_RUNNING,
	TSTATE_KILL,
	TSTATE_STOPPED
} ThreadState;

//////////////////////////////////////////////////////////////////////
// Millisecond timers
//#define ACK_TIMEOUT  		150		// ref: 115200 baud
//#define STARTUP_ACK_TIMEOUT	250
#define ACK_TIMEOUT  		100		// ref: 115200 baud
#define STARTUP_ACK_TIMEOUT	100

#define READ_TIMEOUT		100		// ref: 115200 baud
#define BACKOFF_TIMEOUT		5		// ref: 115200 baud

#define S10ESC       0x7E // Slta10 Escape Character
#define S10MASK_CPC  0x0F // mask for CP Code
#define S10MASK_ACK  0x10 // mask for ACK bit
#define S10MASK_SEQN 0xE0 // mask for sequence number
#define S10INC_SEQN  0x20 // sequence number increment

// CPC Codes: These MUST concur with the SLTA's
typedef enum 
{
	CpNull   = 0,
	CpFail   = 1,
	CpMsg   = 2,
	CpMsgReq  = 3,
	CpMsgAck  = 4,

	CpMsgQueueCount,        // Messages prior to this one can be queued.

	CpMsgReject  = 5,
	CpNiCmdShort = 6,
	CpNiResync  = 7,
	CpNiCmdPassw = 8,
	CpNiCallback = 9,
	CpInvalid  = 14,
	CpEscape  = 15
} DCMP_CPCODES;

typedef struct
{
	BYTE	Escape;
	BYTE	Code;
	BYTE	Param;
	BYTE	Csum;
} CodePacket;

#define SIZE_CP ((unsigned int)sizeof(CodePacket))

// Local NI commands
#define nicbMODE			0x40
#define nicbMODE_SSI		0x42
#define nicbRESET			0x50	
#define nicbINITIATE		0x51
#define nicbCHALLENGE		0x52
#define nicbREPLY			0x53
#define nicbACK				0xC0
#define nicbNACK			0xC1
#define nicbPHASE_SET		0xC0	// IO_0 - IO_3 output low
#define nicbMODE_L5			0xD0
#define nicbMODE_L2			0xD1
#define nicbSSTATUS			0xE0
// This is a ULTA command that this driver hooks:
#define niLMODE				0xE5	// ULTA: mode follows

#define	nicbERROR			0x30

// Receiver States:
typedef enum 
{
	LLPSIdle = 0,  // receiver idle, waiting for a CP
	LLPSReadyRec1,  // CpMsg rx'd, waiting for message packet
	LLPSReadyRec2,  // Partial message packet rx'd
	LLPSRecComplete  // whole message completely read
} DCMPRXSTATE;

// Transmitter States:
typedef enum 
{
	LLPTIdle = 0,  // nothing really.
	LLPTAckWaitCP,  // waiting for ack on a CP.
	LLPTAckWaitMsg,  // waiting for ack on a message.
	LLPTMsgAckWait,  // waiting for CpMsgAck.
	LLPTMsgGo,   // CpMsgAck rx'd go ahead.
	LLPTRspWaitCP  // waiting for uplink local command.
} DCMPTXSTATE;

typedef enum 
{
	RSTSIdle = 0,   // nothing really.
	RSTSVersion,	// query version
	RSTSWait4Status,// wait for query version response
	RSTSInitiate,   // must initiate 
	RSTSWait4Challenge1, // 
	RSTSDoReply,   // must reply
	RSTSDoChallenge,  // 
	RSTSWait4Challenge2,
} DCMPRSTSTATE;

//=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/
#define NM			0x60	/* NetMgr command base */
#define NMR			0x20	/* NetMgr pass response */
#define ND			0x50	/* NetDiag command base */
#define NDR			0x30	/* NetDiag pass response */
#define NM_SERVICE_PIN		31
#define ND_REPORT_STATUS	1
#define NM_READ_MEMORY		13
#define NM_WRITE_MEMORY		14
#define NM_CHANGE_STATE		12
#define NM_UPDATE_DOMAIN	3
#define NM_QUERY_DOMAIN		10
#define NM_ESCAPE			29

#define niCOMM		0x10	// to/from network
#define niTQ		0x02	// transaction queue
#define niTQ_P		0x03	// priority transaction queue


typedef unsigned short DcmpOptions;
#define DCMP_DEFAULT 		0x0000
#define DCMP_BLIND			0x0001
#define DCMP_TRACE_MSG		0x0002	// Trace at API send/rcv message level
#define DCMP_SIM_ERROR		0x0004
#define DCMP_TRACE_ERROR	0x0008	// Trace checksum errors
#define DCMP_L2				0x0010
#define DCMP_TRACE_PKT		0x0020	// Trace all packets
#define DCMP_UNLOCK			0x0400

//////////////////////////////////////////////////////////////////////
#define IDX_CommReadEvent		0
#define IDX_ReadThreadNotifier	1

LPSECURITY_ATTRIBUTES GetNullSecurityAttributes(void);
#define CREATE_EVENT(x)		OsalCreateEvent(&x)
#define SIG_NOTIFIER(x)		if(x) {OsalSetEvent(x);}
#define CLOSE_NOTIFIER(x)	if(x) {OsalDeleteEvent(&x); x = NULL;}
#define WAIT_NOTIFIER(x, y)	OsalWaitForEvent(x, y);
#define GET_MS_TICKS()		OsalGetTickCount()
#define SLEEP_TASK(x)		Sleep(x)

#define MAX_ADDR_LEN	32		/* Largest hardware address length */

// The version is used to apply workarounds.
#define SMIP_VERSION_FENCE		0xA0

#ifdef  __cplusplus
#include <queue>
typedef stdQueue<pLONVXD_Buffer> t_UDlist;
#else
#ifdef U50_KERNEL
struct data_list {
	struct list_head list;
	pLONVXD_Buffer data;
};
typedef struct data_list t_UDlist;
#else
typedef char* t_UDlist;
#endif
#endif
