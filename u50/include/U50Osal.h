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

#ifndef _OSAL_H

#define _OSAL_H



#if defined(WIN32) && defined(FTXL_PLATFORM)

    #ifdef VXLAYER_EXPORTS

        #define OSAL_EXTERNAL_FN			__declspec(dllexport) 

    #else

        #ifdef LTA_LIBRARY

            #define OSAL_EXTERNAL_FN

        #else

	        #define OSAL_EXTERNAL_FN		__declspec(dllimport) 

		#endif

    #endif

#else

    #define OSAL_EXTERNAL_FN

#endif



/*=============================================================================

 *                                  DEFINITIONS 

 *============================================================================*/



#ifndef MAX_PATH

#define MAX_PATH 260

#endif



typedef int OsalProcessId;		// 0 is reserved - not a valid process ID



// OsalHandle used to be "void*" which actually looks better.  However, "void*" has the following weakness.  Say you call

// a routine such as OsalSetEvent() like so OsalSetEvent(&event) rather than OsalSetEvent(event).  If OsalHandle is void*,

// either compiles but as int*, only the correct one compiles.  But, why would you pass &event to OsalSetEvent?  You get

// what you deserve if you do, you might say.  Well, in pthreads, the event mechanism requires that you pass the address

// of the handle rather than the handle itself (not sure why).  So, it is easy to confuse the two conventions (Osal vs. pthreads).

typedef int *OsalHandle;



// Certain Operating Systems (Linux!) don't automatically create thread specific data for

// C APIs that use static data.  So... This affects all kinds of APIs like strtok(), ctime()

// localtime(), etc.  The only fix is to require that the caller provide the buffer.

// For time functions, that buffer is OsalTime.  The ctime size is 26 bytes but we

// round up to 50 just in case.

typedef char OsalTime[50];



typedef enum

{

    OSALSTS_SUCCESS,			/* Succeeded. */

    OSALSTS_TIMEOUT,			/* A wait operation timed out. */

    OSALSTS_CSERROR,			/* Generic error accessing a critical section. */

    OSALSTS_BSEM_ERROR,			/* A generic error creating or accessing a binary semaphore. */

    OSALSTS_EVENT_ERROR,		/* A generic error creating or accessing an event. */

    OSALSTS_CREATE_TASK_FAILED,	/* Failed to create a task. */

    OSALSTS_SLEEP_ERROR,		/* Failed to sleep. */

    OSALSTS_TASK_ERROR,			/* Failed a basic tasking operation */

    OSALSTS_EXEC_CMD_FAILED,	/* Failed to execute a command line */

} OsalStatus;



/******************************************************************************

 *                          Timeing Definitions

 *****************************************************************************/



/* A 32 bit unsigned value representing the number of ticks since startup. */

typedef unsigned int OsalTickCount;



/*

 * Macro: OSAL_WAIT_FOREVER

 * Used as a tick count indicating that the function should never time out.  

 * See <OsalWaitForBinarySemaphore> and <OsalWaitForEvent>

 */

#define OSAL_WAIT_FOREVER 0xffffffff



/******************************************************************************

 *                          Synchronization Definitions

 *****************************************************************************/

typedef enum

{

    OSAL_SEM_CLEAR,

    OSAL_SEM_SET,

} OsalBinarySemState;



/*

 * Enumeration: OsalTraceLevel

 * OSAL trace level.

 *

 * This enumeration controls the OSAL trace level.  OSAL tracing can be used

 * to debug the OSAL implementation.

 *

 */

typedef enum

{

    OSALTRACE_DISABLED, /* No OSAL tracing */

    OSALTRACE_ERROR,    /* Trace OSAL errors only */

    OSALTRACE_WARNING,  /* Trace OSAL errors and warnings */

    OSALTRACE_VERBOSE   /* Trace OSAL errors, warnings and general information. */

} OsalTraceLevel;



/*

 *  Typedef: OsalResourceStats

 *  Statistics for an OSAL resource.

 *

 *  The OSAL layer keeps track of the number of critical sections, semaphores,

 *  events and tasks currently allocated, maximum allocated, etc.

 */

typedef struct OsalResourceStats

{

    unsigned numInUse;      /* Number of these resources currently allocated. */

    unsigned maxUsed;       /* Maximum # of this type of resource ever allocated. */

    unsigned numCreated;    /* Number of allocation requests for this type of resource. */

} OsalResourceStats;



/*

 *  Typedef: OsalStatistics

 *  OSAL Statistics.

 *

 *  Used to store the OSAL statistics for each of the critical resources.  

 *  See <OsalGetStatistics>.

 */

typedef struct OsalStatistics

{

    OsalResourceStats tasks;    

    OsalResourceStats criticalSections;  

    OsalResourceStats events;    

    OsalResourceStats binarySemaphores; 

} OsalStatistics;



/*=============================================================================

 *                          Tasking Definitions

 *============================================================================*/

typedef unsigned int OsalTaskId;

typedef unsigned int OsalThreadId;



#ifdef  __cplusplus

extern "C"

{

#endif



/*=============================================================================

 *                          Synchronization Primitives

 *============================================================================*/



/******************************************************************************

 *                          Critical Sections

 *

 *  <TBD describe properties of critical sections...

 *****************************************************************************/

OsalStatus OsalCreateCriticalSection(OsalHandle *pHandle);

OsalStatus OsalDeleteCriticalSection(OsalHandle *pHandle);

OsalStatus OsalEnterCriticalSection(OsalHandle handle);

OsalStatus OsalLeaveCriticalSection(OsalHandle handle);



typedef struct

{

	OsalHandle lock;

	int count;

	int fd;

} OsalNamedCriticalSection;





OsalStatus OsalCreateNamedCriticalSection(const char *szName, OsalHandle *pHandle);

OsalStatus OsalDeleteNamedCriticalSection(OsalHandle *pHandle);

OsalStatus OsalEnterNamedCriticalSection(OsalHandle handle);

OsalStatus OsalLeaveNamedCriticalSection(OsalHandle handle);



/******************************************************************************

 *                          Binary Semaphores

 *

 *  <TBD describe properties of ...

 *****************************************************************************/

OsalStatus OsalCreateBinarySemaphore(OsalHandle *pHandle, OsalBinarySemState initialState);

OsalStatus OsalDeleteBinarySemaphore(OsalHandle *pHandle);

OsalStatus OsalWaitForBinarySemaphore(OsalHandle handle, unsigned int ticks);

OsalStatus OsalReleaseBinarySemaphore(OsalHandle handle);



/******************************************************************************

 *                                 Events

 *

 *  <TBD describe properties of ...

 *****************************************************************************/

OsalStatus OsalCreateEvent(OsalHandle *pHandle);

OsalStatus OsalDeleteEvent(OsalHandle *pHandle);

OsalStatus OsalWaitForEvent(OsalHandle handle, unsigned int ticks);

OsalStatus OsalSetEvent(OsalHandle handle);



/*=============================================================================

 *                          Timing Primitives

 *============================================================================*/



// For DCD application purposes, we declare years before 2010 not ok.

// Value returned is boolean: 0-> Time is invalid 1-> Time is OK

int OsalIsRealTimeClockOk(void);

OsalTickCount OsalGetTickCount(void);

OsalTickCount OsalGetTicksPerSecond(void);

char* OsalGetCurrentTime(OsalTime pBuf);



/*=============================================================================

 *                          Tasking Primitives

 *============================================================================*/



//

// VxWorks inspired interface

//

typedef void (*OsalTaskEntryPointType)(int taskIndex);

OsalStatus OsalCreateTask(OsalTaskEntryPointType pEntry, int taskIndex, int stackSize,

                          int priority, 

                          OsalHandle *pHandle, 

                          OsalTaskId *pTaskId);

OsalStatus OsalCloseTaskHandle(OsalHandle handle);

OsalTaskId OsalGetTaskId(void);

int OsalGetTaskIndex(void);

int OsalGenerateTaskIndex(void);

int OsalGetPreviousTaskIndex(void);



//

// Pthreads inspired interface

//

typedef void *(*OsalEntryPoint) (void *);

OsalThreadId OsalCreateThread(OsalEntryPoint threadEntry, void* threadData);

OsalThreadId OsalGetThreadId(void);



// Common primitives for both of the above models

OsalStatus OsalSleep(int ticks);



/* Get the process ID of the current process */

OsalProcessId OsalGetProcessId(void);



/* Get the name the current process */

void OsalGetProcessName(char *szName, int maxLength);



/* Get the key the current process. */

/* For a normal process, that is the process name; */

/* For a FPM, that is the FPM name */

void OsalGetProcessKey(char *szKey, int maxLength);



/* Kill any previous instance of this process */

/* Assumes initially process calls OsalEnsureSingleInstance() */

void OsalKillPreviousInstance(void);



/* Exit if another instance of this process is already running */

void OsalEnsureSingleInstance(void);



/* Determine if a process exists - return 1 if exists else 0 */

int OsalProcessExists(OsalProcessId pid);



/* Kill a process */

OsalStatus OsalKillProcess(OsalProcessId pid);



/* And wait for a process to exit */

OsalStatus OsalDeadProcessWait(OsalProcessId pid);



/* Kill a process and its subprocesses

 * This is not guaranteed to kill subprocesses in any particular order.  This method uses the OsalGetFirstSubprocess()

 * and OsalGetNextSubprocess() methods which return PIDs in numerical order.  Most of the time, this means the

 * parent processes are killed first.

 */

OsalStatus OsalKillProcessTree(OsalProcessId pid);



/* Indicate that you want your subprocesses marked. */

OsalStatus OsalMarkSubprocesses(void);



/* Get a list of processes for a parent (that called OsalMarkSubprocesses).  Enumerate using OsalGetNextProcess()

 * until it returns 0.  You must call OsalFreeProcessList() when done.  Re-enumerate using OsalResetProcessList()

 * Note that these are not guaranteed to return the Process IDs in a particular chronological order.  They return the

 * process IDs in numerical order (which usually will be chronological - as in first spawned first - but not in all cases).

 */

void OsalGetProcessList(OsalHandle *pHandle, OsalProcessId parentPid);

OsalProcessId OsalGetNextProcess(OsalHandle handle);

void OsalResetProcessList(OsalHandle handle);

void OsalFreeProcessList(OsalHandle handle);

int OsalProcessIsDaemon(OsalProcessId pid);





void OsalKillAll(const char *szFilename);



/* OsalExecCmd and OsalExecCmdEx can take up to EXCMD_MAX_ARGS parameters as cmd arguments */

#define EXCMD_MAX_ARGS			10

/* OsalExecCmd Returns: 0 if successful, otherwise exit status of the executed command. */

int OsalExecCmd(const char* cmd, ...);

/* OsalExecCmdEx returns output string from command execution. */

const char* OsalExecCmdEx(char * buf, int len, const char* cmd, ...);



/*=============================================================================

 *                          File Primitives

 *============================================================================*/

/* OsalFileExists returns true if the specified file exists */

int OsalFileExists(const char *szFile);

/* OsalDeleteFile() Returns 0 if file was deleted */

int OsalDeleteFile(const char *szFile);

/* OsalDisableInheritance prevents a file handle from being inherited */

void OsalDisableInheritance(int fd);

/* OsalCopyFile copies a file from szFromPath to szToPath returns true if the file was copied */

int OsalCopyFile(const char *szFileSrc, const char *szFileDst);

/* OsalMoveFile returns true if the file was moved */

int OsalMoveFile(const char *szFileSrc, const char *szFileDst);

/* OsalRenameFile renames a file from szFrom to szTo. */

int OsalRenameFile(const char* szFrom, const char* szTo);

/* OsalCreateDirectoryTree creates directory tree hierarchy where mkdir does not */

int OsalCreateDirectoryTree(const char* szPath);

/* OsalRemoveDirectoryTree remove directory tree hierarchy */

void OsalRemoveDirectoryTree(const char* szPath);

/* OsalUnmountDirectory unmounts a directory. Returns 0 for failure and 1 for success */

int OsalUnmountDirectory(const char* szPath);

/* OsalOpenSynchedFile opens a file that is flushed to the disk. */

int OsalOpenSynchedFile(const char* szPath, void **pFileID);

/* OsalWriteToSynchedFile writes to file that is flushed to the disk. */

int OsalWriteToSynchedFile(void* fileID, const unsigned char* pData, int nSize);

/* OsalCloseSynchedFile closes a file that is flushed to the disk. */

int OsalCloseSynchedFile(void* fileID);

/* OsalWriteSynchedFile writes to file that is flushed to the disk. */

int OsalWriteSynchedFile(const char* szPath, const unsigned char* pData, int nSize);

/* OsalFlushDisk flushes all files to the disk */

void OsalFlushDisk(void);



/*=============================================================================

 *                          User Account Primitives

 *============================================================================*/

typedef enum _OsalKeyType

{

	OSAL_ACCOUNT_KEY_NONE,

	OSAL_ACCOUNT_KEY_UID,

	OSAL_ACCOUNT_KEY_USER,



	OSAL_ACCOUNT_KEY_MAX

} OsalKeyType;



/* Delete or create user account, or to modify an existing account's username, password, or other attributes */

int OsalSetUserAccount(	int 		bDelete,		// false create or modify; true = delete

						OsalKeyType	keyType,		// type of key argument to use

						unsigned	keyUid,			// if keyType == OSAL_ACCOUNT_KEY_UID, the uid to modify

						const char	*szKeyUser,		// if keyType == OSAL_ACCOUNT_KEY_USER, the user to modify

						const char	*szUser,		// desired user (required if not bDelete)

						const char	*szPassword,	// desired password (null means empty password)

						const char 	*szGroup,		// desired group

						const char	*szHome,		// desired home (required if not bDelete)

						const char	*szComment,		// GECKO (null means use system default)

						const char	*szShell);		// shell (null means use system default)



/* Takes a lock so that no other application modifies the user information in /etc/passwd and /etc/groups */

OsalStatus OsalLockUserAccounts(void);



/* Release the above lock */

OsalStatus OsalUnlockUserAccounts(void);



/*=============================================================================

 *                           Debug Support

 *============================================================================*/

void OsalPrintDebugString(const char *string);



int OsalGetLastOsError(void);



/*

 *  Function: OsalGetStatistics

 *  Get operating system statistics.

 *

 *  Parameters:

 *  pStatistics - pointer to receive statistics.

 *

 *  Remarks:

 *  Get operating system statistics.  

 */

OSAL_EXTERNAL_FN OsalStatus OsalGetStatistics(OsalStatistics * const pStatistics);



/*

 *  Function: OsalClearStatistics

 *  Clear operating system statistics.

 */

OSAL_EXTERNAL_FN void OsalClearStatistics(void);



/*

 *  Function: OsalDisplayStackStatistics

 *  Display stack statistics.

 */

OSAL_EXTERNAL_FN void OsalDisplayStackStatistics(void);



/*

 * Function: OsalPrintError

 * Display error string

 */

OSAL_EXTERNAL_FN void OsalPrintError(int osError, char *szContext);



/*=============================================================================

 *                          System Performance Primitives

 *============================================================================*/



/*

 * Function: OsalGetSystemPerformance

 * Calculates the System Performance Parameters

 */

OSAL_EXTERNAL_FN void OsalGetSystemPerformance(double *cpuUtil, unsigned long *ramUsage, unsigned long *ramTotal);



#define OsalGetCpuUtilization(x) OsalGetSystemPerformance(x,NULL,NULL)

#define OsalGetRamUsage(x) OsalGetSystemPerformance(NULL,x,NULL)

#define OsalGetRamTotal(x) OsalGetSystemPerformance(NULL,NULL,x)



#ifdef __cplusplus

}

#endif



#endif

