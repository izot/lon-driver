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

#pragma once

#include <linux/spinlock.h>

#include <linux/netdevice.h>
#include <linux/tty.h>
#include "U61Link.h"

#define U61_PRIV_BUF_SIZE 150			// N.A. never referenced
struct u61_priv {
	struct U61LinkState		state;
	spinlock_t 				lock;
	struct tty_struct 		*tty;
	struct net_device* 		dev;
	unsigned char 			*rbuff;
	int 					rcount;
	unsigned char 			*xbuff;
	unsigned char 			*xhead;
	int			 			xleft;		// why was this 8 bits?
//	unsigned char			xleft;
	int 					buffsize;
};

void u61_bump(struct u61_priv *priv, uint8_t *buf, int count);

#define get_priv(state) container_of(state, struct u61_priv, state)
