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

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/tty.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>

#include "platform.h"
#include "U61Osal.h"
#include "U61Link.h"

#include "u61_priv.h"

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

pLONVXD_Buffer getUplinkBufferFront(struct U61LinkState *state) {
    return getFirstElement(&state->Ulist)->data;
}

void removeUplinkBufferFront(struct U61LinkState *state) {
    struct data_list* entry = getFirstElement(&state->Ulist);
    list_del(&entry->list);
    freeMemory(entry->data);
    freeMemory(entry);
//  kfree(entry->data);
//    kfree(entry);
}

#ifndef U61_KERNEL
void addToUplinkBuffer(struct U61LinkState *state, pLONVXD_Buffer data) {
    list_add_tail(&allocate_new_entry(data)->list, &state->Ulist.list);
}
#endif

size_t getUplinkBufferSize(struct U61LinkState *state) {
    return getListCount(&state->Ulist);
}

pLONVXD_Buffer getDownlinkBufferFront(struct U61LinkState *state) {
    return getFirstElement(&state->Dlist)->data;
}

void removeDownlinkBufferFront(struct U61LinkState *state) {
    struct data_list* entry = getFirstElement(&state->Dlist);
    list_del(&entry->list);
//  kfree(entry->data);
//    kfree(entry);
    freeMemory(entry->data);
    freeMemory(entry);
}

void addToDownlinkBuffer(struct U61LinkState *state, pLONVXD_Buffer data) {
    list_add_tail(&allocate_new_entry(data)->list, &state->Dlist.list);
}

size_t getDownlinkBufferSize(struct U61LinkState *state) {
    return getListCount(&state->Dlist);
}


// return ERROR_SUCCESS or ERROR_IO_PENDING
DWORD CalLowerRead(struct U61LinkState *state, PVOID pDest, WORD Count, PWORD pActual)
{
    struct u61_priv *priv = get_priv(state);
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

// Return <actual>
int CalLowerWrite(struct U61LinkState *state, PVOID OutputBuffer, ULONG OutputBufferLength)
{
    struct u61_priv *priv = get_priv(state);
    int actual = 0;
    if (priv) {
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
    return actual;
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
    task = kthread_run((int (*)(void*))threadEntry, threadData, "U61Thread");
    return (OsalThreadId)task;
}

OsalStatus OsalEnterNamedCriticalSection(OsalHandle handle) {
    //struct U61LinkState* state = (struct U61LinkState*)handle;
//  spin_lock_bh(&(get_priv(state)->lock));
    return OSALSTS_SUCCESS;
}

OsalStatus OsalLeaveNamedCriticalSection(OsalHandle handle) {
    //struct U61LinkState* state = (struct U61LinkState*)handle;
//  spin_unlock_bh(&(get_priv(state)->lock));
    return OSALSTS_SUCCESS;
}


#ifdef U61_KERNEL
#include <linux/slab.h>
#else
#include <string.h>
#endif
void* allocateMemory(size_t size) {
#ifdef U61_KERNEL
    void* buf = kmalloc(size, GFP_ATOMIC);

    return buf;
#else
    return malloc(size);
#endif
}

void freeMemory(void * buf) {
#ifdef U61_KERNEL
    kfree(buf);
#else
    free(buf);
#endif
}
