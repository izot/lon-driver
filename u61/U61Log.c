// SPDX-License-Identifier: GPL-2.0 AND MIT
// Copyright © 2022 Dialog Semiconductor
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

#include <linux/module.h>       /* Needed by all modules */
#include <linux/kernel.h>       /* Needed for KERN_INFO */
#include <linux/init.h>         /* Needed for the macros */


//////////////////////////////////////////////////////////////////////
// Debug output
//////////////////////////////////////////////////////////////////////

// #define LDDebugOut(format,arg...) vprintk(format, ##arg)
#define U50_LOG 0
static const char szcPrepend[] = "U61: ";

void LDDebugOut(const char *cLevel, const char* fmt, va_list args)
{
	char szBuffer[128];
	size_t preSize;
	strcpy(szBuffer, cLevel);
	strcat(szBuffer, szcPrepend);
	preSize = strlen(szBuffer);
	vsnprintf(&szBuffer[preSize], sizeof(szBuffer)-preSize-2, fmt, args);
	strcat(szBuffer, "\n");
	printk(szBuffer);
}

void LDDebugError(char* szFormat, ... )
{
	va_list args;
	va_start(args, szFormat);
	LDDebugOut(KERN_ERR, szFormat, args);
	va_end(args);
}

void LDDebugInform(char* szFormat, ... )
{
	va_list args;
	va_start(args, szFormat);
	LDDebugOut(KERN_INFO, szFormat, args);
	va_end(args);
}

void LDDebugNotice(char* szFormat, ... )
{
	va_list args;
	va_start(args, szFormat);
	LDDebugOut(KERN_NOTICE, szFormat, args);
	va_end(args);
}

void LDDebugTracePacket(char* szType, uint8_t *mp, int length)
{
#if U50_LOG
	print_hex_dump_bytes(szType, DUMP_PREFIX_OFFSET, mp, length);
#endif
}

void LDDebugUplinkMessage(uint8_t bIfUplink, const uint8_t* mp)
{
#if U50_LOG

#endif
}
