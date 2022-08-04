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

//
// Timer.h
//
// This file contains definitions used for timers.
//

#ifndef _TIMER_H
#define _TIMER_H

#include "platform.h"
// Time related but not related to timers below
typedef struct
{
	BYTE year;
	BYTE month;
	BYTE day;
	BYTE hour;
	BYTE minute;
	BYTE second;
} LTimeDate;

// The timer macros hide some implementation specific aspects
// of using the timer directly.  A timer is started and then can
// be checked against various time out values until it is explicitly stopped.
// A timer has a fundamental limit of 10.9 minutes (65,536/100 seconds).
//
// For example,
//
//		// Define a timer.
//		Timer myTimer;
//
//		// Start the timer.
//		TMR_Start(myTimer);
//
//		// Check if the timer is still running
//		if (TMR_Running(myTimer))
//		{
//			// Do something while timer is running.
//		}
//
//		// Check if the timer has been running for at least 2 seconds.
//		// Note that expiration does not cause the timer to stop running.
//		// You just stop it explicitly.
//		if (TMR_Elapsed(myTimer, 2000))
//		{
//			// Do something based on timer running for 2 seconds.
//
//			// And now stop the timer.
//			TMR_Stop(myTimer);
//		}
//
typedef struct
{
	BOOL  bRunning;
	unsigned long startValue;
} Timer;

#define TMR_Current (OsalGetTickCount())

// Use this to start milliseconds "timer"
#define TMR_Start(timer)		\
	timer.bRunning = TRUE; timer.startValue = TMR_Current;

#define TMR_Stop(timer) 		\
	timer.bRunning = FALSE;

#define TMR_Running(timer) 	\
	timer.bRunning

// Use this to check "timer" for "duration" milliseconds having elapsed since starting
#define TMR_Expired(timer, duration) \
	(!timer.bRunning || (TMR_Current - timer.startValue) > duration)

// Same as TMR_Expired but also makes sure the timer is running.
#define TMR_Elapsed(timer, duration)	\
	(timer.bRunning && TMR_Expired(timer, duration))

// Replaced with TimerRemaining to fix the issue where there was a tiny window  
// where the TMR_Current would change during the logic of the original macro	
#define TMR_Remaining(timer, duration)	TimerRemaining(timer, duration)

#endif
