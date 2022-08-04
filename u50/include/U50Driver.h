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
// Prototype definitions for both the DLL and client apps.
///////////////////////////////////////////////////////////////////////////////
#pragma once

#include "Ldv32.h"
#include "platform.h"

//////////////////////////////////////////////////////////////////////
// Open() mode enumerations
typedef enum {
	U50_OPEN_DEFAULT,		// Affect no change
	U50_OPEN_LAYER5,		// Enforce L5
	U50_OPEN_LAYER2,		// Enforce L2
	U50_OPEN_PA,			// Enforce PA, currently same as L2
	U50_OPEN_UNK = -1
} U50OpenMode;

typedef struct
{
	DWORD Size;         // set to sizeof(U50_Stats);
	DWORD AckTMOs;      // # of Ack timeouts
	DWORD RxTmos;       // # of receive timeouts
	DWORD CsumErrors;   // # of uplink checksum errors
	DWORD CpFails;      // # uplink CpFail rx'd (implies downlink cs error)
	DWORD ULDuplicates; // # of duplicates sensed
	DWORD UlDiscarded;  // # of tossed uplinks
    DWORD MsgRejects;   // # CpMsgReject received
	WORD  MipVersion;
	WORD  MipMode;
    DWORD ReferenceCount;
} U50_Stats, *pU50_Stats;

//////////////////////////////////////////////////////////////////////
// Extended message alternate structure:
#define EXT_LENGTH	0xFF	// extended message length indicator.
typedef struct LDV_ExtMessage
{
	BYTE NiCmd;				// Network Interface Command
	BYTE ExtFlag;			// will be set to EXT_LENGTH
	WORD ExtLength;
	BYTE ExpAppMessage[1];	// size is based on ExtLength
} LDV_ExtMessage, *pLDV_ExtMessage;

