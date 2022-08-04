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
// $Header: //depot/Software/IotRouter/dev/U61Module/include/U61Defs.h#6 $
//
// Definitions private to the DLL.
///////////////////////////////////////////////////////////////////////////////

#include "Ldv32.h"
#include "platform.h"
#include "U61Driver.h"

#ifndef PACK
#   ifdef WIN32
#       define PACK
#   else
#       define PACK __attribute__((__packed__))
#   endif
#endif

typedef enum {
	UL_IDLE1,		// Start of frame.
	UL_IDLE2,		// UMIP_ESC rx'd
	UL_PACKET,		// packet streaming
	UL_ESCD1,		// packet streaming, escaped data
} UlState;

// This is the frame sync byte value
#define UMIP_ESC	0x7E

// For now we just run at this baud rate:
#define U61BAUD						B921600

void LDDebugError(LPCSTR szFormat, ... );
void LDDebugInform(LPCSTR szFormat, ... );
void LDDebugNotice(LPCSTR szFormat, ... );
void LDDebugTracePacket(LPCSTR szType, BYTE *mp, WORD length);
PORT_HANDLE U61OpenComPort(LPCSTR szComPort);

// #define COUNT_WaitObjects		2
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

// #define SIZE_CHALLENGE 8
// #define SIZE_MIP_KEY  6

// The message structures:
#define SIZE_ULB  ((MAXLONMSG+4)*2)  // size of ul serial buffer (including expansions)
#define SIZE_DLB  ((MAXLONMSG+4)*2)  // size of dl serial buffer (including expansions)

typedef struct PACK USBLTA_Message {
	BYTE NiCmd;					// Network Interface Command
	BYTE Length;				// size of ExpAppMessage
	BYTE Message[MAXLONMSG];
	BYTE pad[3];				// sizes to LDV_ExtMessage
} USBLTA_Message, *pUSBLTA_Message;

typedef struct PACK USBLTA_Cmd {
	BYTE NiCmd;					// Network Interface Command
	BYTE Length;				// size of CmdData
	BYTE CmdData[2];
} USBLTA_Cmd;

// The full message element as stored in this driver:
typedef struct PACK LONVXD_Buffer {
	BYTE Length;					// size of NiCmd + ExpAppMessage
	BYTE NiCmd;						// Network Interface Command
	BYTE ExpAppMessage[MAXLONMSG];	// represents max size.
	BYTE pad[3];					// sizes to LONVXD_ExtBuffer
} LONVXD_Buffer, *pLONVXD_Buffer;

// Alternate LONVXD_Buffer, but assembled for extension messages
typedef struct PACK LONVXD_ExtBuffer {
	BYTE Length;						// this would be EXT_LENGTH
	WORD ExtLength;						// remember any endian swapping
	BYTE NiCmd;							// Network Interface Command
	BYTE ExpAppMessage[MAXLONMSG];		// represents max size.
} LONVXD_ExtBuffer, *pLONVXD_ExtBuffer;

// A short version for local commands:
typedef struct PACK LONVXD_CmdLocal {
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
// Driver parameters, FTDI and our own.
#define DEF_INTRANSFERSIZE		4096
#define DEF_READTIMEOUT			500
#define DEF_WRITETIMEOUT		500
#define DEF_UPLINKLIMIT			200
#define DEF_LATENCYTIMER		10
#define DEF_LLPTIMEOUT			1000
#define DEF_PIGTIMER			5000
#define DEF_PIG_XTN_COUNT		5
typedef struct USBLTA_Params_s {
	DWORD InTransferSize;		// bytes
	DWORD ReadTimeout;			// milliseconds
	DWORD WriteTimeout;			// milliseconds
	DWORD UplinkContainerLimit;	// packets
	DWORD LLPTimeout;			// milliseconds
	UCHAR LatencyTimer;			// milliseconds
	UCHAR PigCount;				// How many downlink packets per pig
} USBLTA_Params, *pUSBLTA_Params;

// Local NI commands
// USBLTA-specific NI commands
#define niLAYER			0xE5
#define niDRIVER		0xD0
#define niIDENTIFY		(niDRIVER|4)
#define niPIG			(niDRIVER|5)
#define niDRV_RST		(niDRIVER|6)
#define niDRV_CYC		(niDRIVER|7)
#define niRESET			0x50
#define niINCOMING		0x18
#define niCRCERR        0x31

#define niCMD_MASK		0xF0
#define niQUE_MASK		0x0F	// includes priority bit
#define niCOMM			0x10
#define niTQ			0x02	// outgoing acceptable start
#define niNTQ_P			0x05	// outgoing acceptable end
#define niTQ_P			0x03	// priority transaction queue

#define OFFS_MCODE		14		// assuming EXP ADDR is ON
#define NM_WINK			0x70

#define nicbMODE			0x40
#define nicbMODE_SSI		0x42
#define nicbRESET			0x50	
#define nicbACK				0xC0
#define nicbNACK			0xC1
//#define nicbMODE_L5		0xD0			// SMIP only
//#define nicbMODE_L2		0xD1			// SMIP only
#define nicbSSTATUS			0xE0
#define	nicbERROR			0x30
#define niIDENTIFY		(niDRIVER|4)
#define niPIG			(niDRIVER|5)
#define niLMODE				0xE5			// ULTA: mode follows
#define niFLUSH				0x90
#define niFLUSH_COMPLETE	0x60


#define DWORD_PEG(x)	{if(x != 0xFFFFFFFF) x++;}

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

#ifdef  __cplusplus
#include <queue>
typedef stdQueue<pLONVXD_Buffer> t_UDlist;
#else
#ifdef U61_KERNEL
struct data_list {
	struct list_head list;
	pLONVXD_Buffer data;
};
typedef struct data_list t_UDlist;
#else
typedef char* t_UDlist;
#endif
#endif

void LDDebugError(LPCSTR szFormat, ... );
void LDDebugInform(LPCSTR szFormat, ... );
void LDDebugTracePacket(LPCSTR szType, BYTE *mp, WORD length);
void LDDebugUplinkMessage(uint8_t bIfUplink, const uint8_t* mp);
