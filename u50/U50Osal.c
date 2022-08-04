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

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/tty.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>

#include "platform.h"
#include "U50Osal.h"
#include "U50Link.h"

#include "u50_priv.h"

static struct data_list* allocate_new_entry(pLONVXD_Buffer data) {
    struct data_list *new_entry;
    new_entry = allocateMemory(sizeof(struct data_list));
//kmalloc(sizeof(struct data_list), GFP_ATOMIC);
    new_entry->data = data;
    return new_entry;
}

static struct data_list* getFirstElement(struct data_list* pDataList) {
    return list_first_entry(&pDataList->list, struct data_list, list);
}

static int getListCount(struct data_list* pDataList) {
    int count = 0;
    struct list_head *i;
    list_for_each(i, &pDataList->list) count++;
    return count;
}

pLONVXD_Buffer getUplinkBufferFront(struct U50LinkState *state) {
    return getFirstElement(&state->Ulist)->data;
}

void removeUplinkBufferFront(struct U50LinkState *state) {
    struct data_list* entry = getFirstElement(&state->Ulist);
    list_del(&entry->list);
    freeMemory(entry->data);
    freeMemory(entry);
//  kfree(entry->data);
//    kfree(entry);
}

void addToUplinkBuffer(struct U50LinkState *state, pLONVXD_Buffer data) {
    list_add_tail(&allocate_new_entry(data)->list, &state->Ulist.list);
}

size_t getUplinkBufferSize(struct U50LinkState *state) {
    return getListCount(&state->Ulist);
}

pLONVXD_Buffer getDownlinkBufferFront(struct U50LinkState *state) {
    return getFirstElement(&state->Dlist)->data;
}

void removeDownlinkBufferFront(struct U50LinkState *state) {
    struct data_list* entry = getFirstElement(&state->Dlist);
    list_del(&entry->list);
//  kfree(entry->data);
//    kfree(entry);
    freeMemory(entry->data);
    freeMemory(entry);
}

void addToDownlinkBuffer(struct U50LinkState *state, pLONVXD_Buffer data) {
    list_add_tail(&allocate_new_entry(data)->list, &state->Dlist.list);
}

size_t getDownlinkBufferSize(struct U50LinkState *state) {
    return getListCount(&state->Dlist);
}

#if 0
int CalLowerReadCount(struct U50LinkState *state)
{
	struct u50_priv *priv = get_priv(state);
	int copyAmount = 0;
	if (priv) {
		spin_lock_bh(&priv->lock);
		copyAmount = priv->rcount;
		spin_unlock_bh(&priv->lock);
	}
	return copyAmount;
}
#endif

int LogThrottleCheck(struct U50LinkState *state)
{
    if ((OsalGetTickCount() - state->m_tLogThrottle) >= SMP_MSECS_LOGT) {
        state->m_tLogThrottle = OsalGetTickCount();
        return 1;   // okay
    }
    return 0;   // nope
}

DWORD CalLowerRead(struct U50LinkState *state, PVOID pDest, WORD Count, PWORD pActual)
{
    struct u50_priv *priv = get_priv(state);
    int copyAmount = 0;
    if (priv) {
        spin_lock_bh(&priv->lock);
        copyAmount = priv->rcount;
        if (priv->rcount) {
            if (copyAmount > Count) copyAmount = Count;
            memcpy(pDest, priv->rbuff, copyAmount);
            priv->rcount -= copyAmount;
            if (priv->rcount) {
                memcpy(priv->rbuff, priv->rbuff+copyAmount, priv->rcount);
            }
        }
        *pActual = copyAmount;
        spin_unlock_bh(&priv->lock);
    }
    return copyAmount ? ERROR_SUCCESS : ERROR_IO_PENDING;
}

void CalLowerWrite(struct U50LinkState *state, PVOID OutputBuffer, ULONG OutputBufferLength)
{
    struct u50_priv *priv = get_priv(state);
    if (priv) {
        int actual = 0;
        spin_lock_bh(&priv->lock);
        memcpy(priv->xbuff, OutputBuffer, OutputBufferLength);
        if (priv->tty) {
            set_bit(TTY_DO_WRITE_WAKEUP, &priv->tty->flags);
            actual = priv->tty->ops->write(priv->tty, priv->xbuff, OutputBufferLength);
        }
        priv->xleft = OutputBufferLength - actual;
        priv->xhead = priv->xbuff + actual;
        spin_unlock_bh(&priv->lock);
    }
}

WORD CalLowerGetOvlr(struct U50LinkState *state)
{
    return 0;
}

OsalStatus OsalCreateEvent(OsalHandle *pHandle) {
    OsalEvent *pEvent = (OsalEvent*)allocateMemory(sizeof(OsalEvent));
    init_waitqueue_head(&pEvent->queue);
    pEvent->flag = 0;
    *pHandle = (OsalHandle) pEvent;
    return OSALSTS_SUCCESS;
}

OsalStatus OsalDeleteEvent(OsalHandle *pHandle) {
    return OSALSTS_SUCCESS;
}

OsalStatus OsalWaitForEvent(OsalHandle handle, unsigned int waittime) {
    OsalStatus retVal;
    OsalEvent *pEvent = (OsalEvent*)handle;
    if (pEvent->flag == 0)
        wait_event_timeout(pEvent->queue, (pEvent->flag == 1), /* jiffies_to_msecs(waittime) */ waittime * HZ / 1000);
    retVal = (pEvent->flag == 1) ? OSALSTS_SUCCESS : OSALSTS_TIMEOUT;
    pEvent->flag = 0;
    return retVal;
}

OsalStatus OsalSetEvent(OsalHandle handle) {
    OsalEvent *pEvent = (OsalEvent*) handle;
    if (handle) {
        if (pEvent->flag == 0) {
            pEvent->flag = 1;
            wake_up(&pEvent->queue);
        }
    }
    return OSALSTS_SUCCESS;
}

OsalTickCount OsalGetTickCount(void) {
    return jiffies_to_msecs(jiffies);
}

OsalThreadId OsalCreateThread(OsalEntryPoint threadEntry, void* threadData) {
    struct task_struct *task;
    task = kthread_run((int (*)(void*))threadEntry, threadData, "U50Thread");
    return (OsalThreadId)task;
}

#ifdef U50_KERNEL
#include <linux/slab.h>
#else
#include <string.h>
#endif
void* allocateMemory(size_t size) {
#ifdef U50_KERNEL
    void* buf = kmalloc(size, GFP_ATOMIC);

    return buf;
#else
    return malloc(size);
#endif
}

void freeMemory(void * buf) {
#ifdef U50_KERNEL
    kfree(buf);
#else
    free(buf);
#endif
}
