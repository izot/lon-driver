// SPDX-License-Identifier: GPL-2.0 AND MIT
// Copyright © 2021-2025 EnOcean
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

/*********************************************************************
 *
 * EnOcean OpenLDV (TM) 4.0  API
 *
 ********************************************************************/

#ifndef _LDV32_H_
#define _LDV32_H_


#ifndef IN
    #define IN                      /**/
#endif

#ifndef OUT
    #define OUT                     /**/
#endif

#ifndef WM_APP
    #define WM_APP                  0x8000
#endif


/*
 * Override the following type definitions
 * if your compiler does not already supply them.
 */

#ifndef LDV_TYPES_DEFINED
    typedef          void*          PVOID;
    typedef          short          SHORT;      /*   signed 16-bit */
    typedef          long           LONG;       /*   signed 32-bit */
    typedef unsigned char           BYTE;       /* unsigned  8-bit */
    typedef unsigned short          WORD;       /* unsigned 16-bit */
    typedef unsigned long           DWORD;      /* unsigned 32-bit */
    typedef          int            SIZET;      /*   signed 32-bit */
    typedef          char*          LPSTR;
    typedef const    char*          LPCSTR;

    typedef          void*          HWND;
    typedef          void*          HANDLE;

    #define VOID     void
#ifdef windows
    #define LDVAPI   __stdcall
#else
    #define LDVAPI  /**/
//    typedef          int            HANDLE;
#endif
#endif


/* OpenLDV structure members are aligned on 32-bit boundaries */
#pragma pack(push, 4)

typedef SHORT                       LdvHandle;


/* return codes */
enum LdvCode {
    LDV_OK                               =  0,
    LDV_NOT_FOUND                        =  1,
    LDV_ALREADY_OPEN                     =  2,
    LDV_NOT_OPEN                         =  3,
    LDV_DEVICE_ERR                       =  4,
    LDV_INVALID_DEVICE_ID                =  5,
    LDV_NO_MSG_AVAIL                     =  6,
    LDV_NO_BUFF_AVAIL                    =  7,
    LDV_NO_RESOURCES                     =  8,
    LDV_INVALID_BUF_LEN                  =  9,
    LDV_NOT_ENABLED                      = 10,

    /* added in OpenLDV 1.0 */
    LDVX_INITIALIZATION_FAILED           = 11,
    LDVX_OPEN_FAILED                     = 12,
    LDVX_CLOSE_FAILED                    = 13,
    LDVX_READ_FAILED                     = 14,
    LDVX_WRITE_FAILED                    = 15,
    LDVX_REGISTER_FAILED                 = 16,
    LDVX_INVALID_XDRIVER                 = 17,
    LDVX_DEBUG_FAILED                    = 18,
    LDVX_ACCESS_DENIED                   = 19,

    /* added in OpenLDV 2.0 */
    LDV_CAPABLE_DEVICE_NOT_FOUND         = 20,
    LDV_NO_MORE_CAPABLE_DEVICES          = 21,
    LDV_CAPABILITY_NOT_SUPPORTED         = 22,
    LDV_INVALID_DRIVER_INFO              = 23,
    LDV_INVALID_DEVICE_INFO              = 24,
    LDV_DEVICE_IN_USE                    = 25,
    LDV_NOT_IMPLEMENTED                  = 26,
    LDV_INVALID_PARAMETER                = 27,
    LDV_INVALID_DRIVER_ID                = 28,
    LDV_INVALID_DATA_FORMAT              = 29,
    LDV_INTERNAL_ERROR                   = 30,
    LDV_EXCEPTION                        = 31,
    LDV_DRIVER_UPDATE_FAILED             = 32,
    LDV_DEVICE_UPDATE_FAILED             = 33,
    LDV_STD_DRIVER_TYPE_READ_ONLY        = 34,

    /* added in OpenLDV 4.0 */
    LDV_OUTPUT_BUFFER_SIZE_MISMATCH      = 40,  // priority and non-priority output buffer sizes must be the same
    LDV_INVALID_BUFFER_PARAMETER         = 41,  // invalid buffer parameter (e.g. too large)
    LDV_INVALID_BUFFER_COUNT             = 42,  // invalid buffer count (e.g. need at least one buffer of each type)
    LDV_PRIORITY_BUFFER_COUNT_MISMATCH   = 43,  // if one of the priority output buffer counts is zero, then both must be zero
    LDV_BUFFER_SIZE_TOO_SMALL            = 44,  // buffer size is too small to support subsequent buffer configuration changes
    LDV_BUFFER_CONFIGURATION_TOO_LARGE   = 45,  // requested buffer configuration is too large to fit in available space
    LDV_WARNING_APP_BUFFER_SIZE_MISMATCH = 46,  // application buffer input-output size mismatch may cause problems (warning only)
};

typedef SHORT                       LDVCode;


/*
 * Windows Messages for session change notifications
 * (see ldvx_open and/or ldvx_register_window)
 *
 * NOTE: This feature was added in OpenLDV/LNS (V3.20.29).
 */
#define LDVX_APP                    ((UINT)(WM_APP + 1640))
#define LDVX_WM_CLOSED              ((UINT)(LDVX_APP + 0))      /* 34408 */
#define LDVX_WM_CONNECTING          ((UINT)(LDVX_APP + 1))      /* 34409 */
#define LDVX_WM_ESTABLISHED         ((UINT)(LDVX_APP + 2))      /* 34410 */
#define LDVX_WM_FAILED              ((UINT)(LDVX_APP + 3))      /* 34411 */

/*
 * Windows Messages for LON interface (e.g. U10)
 * detachment/attachment notifications
 *
 * NOTE: This feature was added in OpenLDV 2.0.
 *
 */
#define LDVX_WM_DETACHED            ((UINT)(LDVX_APP + 4))      /* 34412 */
#define LDVX_WM_ATTACHED            ((UINT)(LDVX_APP + 5))      /* 34413 */


#ifdef __cplusplus
extern "C"
{
#endif  /* __cplusplus */


/*============== OpenLDV 1.0 Interface =====================================*/

/*
 * Retrieves version number of OpenLDV API.
 *
 *  Release         Version No
 *  --------------------------
 *  OpenLDV 1.0     5.308.09
 *  OpenLDV/LNS     5.320.122
 *  OpenLDV 2.0     5.321.034
 *  OpenLDV 2.1     5.322.002
 *  OpenLDV 3.3     5.330.036
 *  OpenLDV 3.4     5.340.016
 *  OpenLDV 4.0     5.400.102
 */
LPCSTR LDVAPI ldv_get_version(VOID);


/*
 * Opens specified LON network interface device,
 * returning a handle to be used in subsequent calls.
 *
 * See also ldvx_open and ldv_open_cap.
 */
#ifdef windows
LDVCode LDVAPI ldv_open(
    IN  LPCSTR     id,              /* name of network interface device */
    OUT LdvHandle* handle           /* pointer to returned session handle */
);
#endif // windows

/*
 * Opens specified network interface device,
 * registers a Windows HWND object for receiving session change notifications,
 * and returns a handle to be used in subsequent calls.
 *
 * See also ldv_open_cap.
 *
 * NOTE: This function was added in OpenLDV/LNS (V3.20.29).
 */
#ifdef windows
LDVCode LDVAPI ldvx_open(
    IN  LPCSTR     id,              /* name of network interface device */
    OUT LdvHandle* handle,          /* pointer to returned session handle */
    IN  HWND       hWnd,            /* Windows HWND to receive notifications */
    IN  LONG       tag              /* LPARAM to use in notification */
);
#endif // windows

/*
 * Closes specified open session.
 */
#ifdef windows
LDVCode LDVAPI ldv_close(
    IN  LdvHandle handle            /* session handle (from ldv_open) */
);
#endif // windows

/*
 * Reads a message from specified open session into specified buffer.
 * Packet format is controlled by the LDV_DEVCAP_SICB and LDV_DEVCAP_LDVEX
 * passed to ldv_open_cap (other 'open' APIs default to SICB format).
 * If no messages are available, returns LDV_NO_MSG_AVAIL.
 * If specified buffer is too small, returns LDV_INVALID_BUF_LEN.
 * If packet contains no SICB, returns LDV_NOT_FOUND.
 */
#ifdef windows
LDVCode LDVAPI ldv_read(
    IN  LdvHandle handle,           /* session handle (from ldv_open) */
    OUT PVOID     msg_p,            /* pointer to buffer to receive message */
    IN  SHORT     len               /* length  of buffer to receive message */
);
#endif // windows

/*
 * Writes a message to specified open session from specified buffer.
 * Message can be in SICB or LdvEx format and will be converted internally
 * as necessary.
 */
#ifdef windows
LDVCode LDVAPI ldv_write(
    IN LdvHandle handle,            /* session handle (from ldv_open) */
    IN PVOID     msg_p,             /* pointer to buffer containing message */
    IN SHORT     len                /* length  of message to write */
);
#endif // windows

/*
 * Registers a Windows Event object.
 * When a new message is received this event will be signaled.
 * After signaling, to ensure that all messages are retrieved,
 * clients should repeatedly call ldv_read until no more messages are
 * available (LDV_NO_MSG_AVAIL) or an error (other than LDV_NOT_FOUND).
 */ 
#ifdef windows
LDVCode LDVAPI ldv_register_event(
    IN LdvHandle handle,            /* session handle (from ldv_open) */
    IN HANDLE    event              /* event object to be signaled */
);
#endif // windows

/*
 * Registers a Windows HWND object for receiving session change notifications.
 * If <hWnd> is NULL then this client is shutting down for window notifications.
 *
 * NOTE: This function was added in OpenLDV/LNS (V3.20.29).
 */
#ifdef windows
LDVCode LDVAPI ldvx_register_window(
    IN LdvHandle handle,            /* session handle (from ldv_open) */
    IN HWND      hWnd,              /* Windows HWND to receive notifications */
    IN LONG      tag                /* LPARAM to use in notification */
);
#endif // windows

/*
 * Retrieves debugging information from the network interface.
 *
 * NOTE: This function is deprecated and provided for compatibility only.
 */
#ifdef windows
LDVCode LDVAPI ldv_get_debug_info(
    IN  LdvHandle handle,           /* session handle (from ldv_open) */
    OUT PVOID     data_p,           /* pointer to buffer to receive debug info */
    IN  SIZET     data_len          /* length  of buffer to receive debug info */
);
#endif // windows

/*
 * Retrieves name of driver associated with specified
 * local network interface.
 *
 * NOTE: This function is deprecated and provided for compatibility only.
 */
#ifdef windows
LDVCode __cdecl ldv_xlate_device_name(
    IN     LPCSTR device_name,      /* name of network interface device */
    OUT    LPSTR  driver_name,      /* pointer to buffer to receive driver name */
    IN OUT SIZET* driver_name_len   /* length  of buffer to receive driver name */
);
#endif

LDVCode LDVAPI ldv_xlate_device_name_std(
    IN     LPCSTR device_name,      /* name of network interface device */
    OUT    LPSTR  driver_name,      /* pointer to buffer to receive driver name */
    IN OUT SIZET* driver_name_len   /* length  of buffer to receive driver name */
);

/* force use of standard calling convention function for new code */
#define ldv_xlate_device_name       ldv_xlate_device_name_std


/*
 * Sets the LDV32 enable code.
 *
 * NOTE: This function is deprecated and provided for compatibility only.
 */
LDVCode LDVAPI ldv_enable(
    IN DWORD enable                 /* LDV32 enable code */
);


/*
 * Cleanly shuts down OpenLDV/xDriver subsystem.  Call once before
 * allowing application to exit to avoid delays on shutdown.
 * Once called, OpenLDV/xDriver should not be accessed again.
 *
 * NOTE: This function was added in OpenLDV/LNS (V3.20.29).
 */
LDVCode LDVAPI ldvx_shutdown(VOID);



/*============= OpenLDV 2.0 Interface =======================================*/

/*------------- Driver Information -----------------------------------------*/

/*
 * The LDVDriverID enumeration contains constants describing
 * the driver class of an associated LON interface device.
 *
 * NOTE: This feature was added in OpenLDV 2.0.
 */
enum LdvDriverID
{
    LDV_DRIVERID_UNKNOWN     =   0,
    LDV_DRIVERID_ILON        =   1,     /* i.LON */
    LDV_DRIVERID_ILON10      =   2,     /* i.LON-10 */
    LDV_DRIVERID_ILON100     =   3,     /* i.LON-100 */
    LDV_DRIVERID_ILON600     =   4,     /* i.LON-600 */
    LDV_DRIVERID_LONIP       =   5,     /* LON/IP Device */
    LDV_DRIVERID_U10_FT_AB   =   6,     /* U10 FT USB Network Interface Rev A and B */
    LDV_DRIVERID_SLTA10      =   7,     /* Serial LonTalk Adapter */
    LDV_DRIVERID_PCC10       =   8,     /* PCC-10 PC Card Adapter */
    LDV_DRIVERID_PCLTA10     =   9,     /* PCLTA-10 Adapter */
    LDV_DRIVERID_PCLTA20     =  10,     /* PCLTA-20 Adapter */
    LDV_DRIVERID_PCLTA21     =  11,     /* PCLTA-21 Adapter */
    LDV_DRIVERID_TA          =  12,     /* Turnaround Channel */
    LDV_DRIVERID_RNISIM      =  13,     /* RNI Simulator */
    LDV_DRIVERID_U60_FT      =  14,     /* U60 FT USB Network Interface */
    LDV_DRIVERID_U60_TP1250  =  15,     /* U60 TP-1250 USB Network Interface */
    LDV_DRIVERID_U10_FT_C    =  16,     /* U10 FT USB Network Interface Rev C */
    LDV_DRIVERID_SMARTSERVER =  17,     /* SmartServer and SmartConnect */

    /* Driver IDs through 127 are reserved for EnOcean use */
    LDV_DRIVERID_STD_MAX     = 127,
    LDV_DRIVERID_DONT_CHANGE =  -1
};

typedef SHORT               LDVDriverID;


/*
 * The LDVDriverType enumeration contains constants describing
 * the driver type of an associated LON interface device.
 *
 * NOTE: This feature was added in OpenLDV 2.0.
 */
enum LdvDriverType
{
    LDV_DRIVERTYPE_UNKNOWN =   0,       /* Unknown (or unspecified) Driver */
    LDV_DRIVERTYPE_LNI     =   1,       /* Local Network Interface Driver */
    LDV_DRIVERTYPE_RNI     =   2,       /* Remote Network Interface Driver (xDriver) */
    LDV_DRIVERTYPE_USB     =   3,       /* U10 USB LTA Driver */
    LDV_DRIVERTYPE_U60     =   4,       /* U60 USB LTA Driver */

    /* Driver types through 127 are reserved for EnOcean use */
    LDV_DRIVERTYPE_STD_MAX = 127,
};

typedef SHORT               LDVDriverType;


/*
 * The LDVDriverInfo structure contains information describing a specific
 * LON interface device driver (as identified by its driver ID).
 *
 * size         The size (in bytes) of this structure.  This field must be set
 *              before calling any of the set functions that pass this
 *              structure as a parameter.  It is used to determine the current
 *              version of this structure and to support its extension in
 *              future releases.
 * id           The device driver class ID.
 * type         The device driver type.
 * name         A string containing the name of the device driver.
 * desc         A string containing the description of the device driver.
 *
 * See Also:    ldv_get_driver_info, ldv_set_driver_info, ldv_free_driver_info
 *
 * NOTE:        This feature was added in OpenLDV 2.0.
 */
typedef struct LDVDriverInfo
{
    DWORD           size;
    LDVDriverID     id;
    LDVDriverType   type;
    LPCSTR          name;
    LPCSTR          desc;
}                               LDVDriverInfo;

typedef const LDVDriverInfo*    LDVDriverInfoPtr;       /* (read-only) */


/*
 * Retrieves information about the specified LON interface
 * device driver class.
 *
 * nDriverId    The driver class ID of the driver whose information is being
 *              requested.
 * ppDriverInfo A pointer to an LDVDriverInfo pointer to receive the
 *              information of the requested driver.  Note that the contents
 *              of the returned structure is constant (read-only) and should
 *              not be modified.  If this function returns successfully,
 *              it must be freed by calling ldv_free_driver_info.
 *
 * Returns:     An LDV32 status code representing success (LDV_OK) or failure.
 *
 * See Also:    LDVDriverInfo, ldv_set_driver_info, ldv_free_driver_info
 *
 * NOTE:        This feature was added in OpenLDV 2.0.
 */
LDVCode LDVAPI ldv_get_driver_info(
    IN  LDVDriverID     nDriverId,
    OUT LDVDriverInfo** ppDriverInfo
);


/*
 * Creates or modifies the information about the specified LON interface
 * device driver class.  Before calling this function, the LDVDriverInfo
 * structure pointed to by pDriverInfo must be initialized correctly:
 *
 *  - Set size to the size of the LDVDriverInfo structure.
 *  - If the driver type is not to be modified, set 'type' to -1,
 *    otherwise set 'type' to the new driver type.
 *  - If the name of the driver is not to be modified, set 'name' to NULL
 *    or an empty string.  Otherwise set 'name' to point to the new name.
 *  - If the description of the driver is not to be modified,
 *    set 'desc' to NULL or an empty string.  Otherwise set 'desc'
 *    to point to the new description.
 *
 * NOTE: The Driver ID is read-only and cannot be modified using this function.
 *
 * NOTE: The Driver Type is read-only for the standard Driver IDs and cannot
 *       be modified using this function.  Non-standard drivers can have their
 *       driver type set.
 *
 * nDriverId    The driver class ID of the driver whose information is being
 *              modified.
 * pDriverInfo  A pointer to an LDVDriverInfo structure containing the driver
 *              information to update.
 *
 * Returns:     An LDV32 status code representing success (LDV_OK) or failure
 *              (e.g. LDV_DRIVER_INFO_INVALID, LDV_DRIVER_UPDATE_FAILED,
 *              LDV_STD_DRIVER_TYPE_READ_ONLY).
 *
 * See Also:    LDVDriverInfo, ldv_get_driver_info
 *
 * NOTE:        This feature was added in OpenLDV 2.0.
 */
LDVCode LDVAPI ldv_set_driver_info(
    IN       LDVDriverID    nDriverId,
    IN const LDVDriverInfo* pDriverInfo
);


/*
 * Releases the resources allocated by a call to ldv_get_driver_info.
 *
 * pDriverInfo  A pointer to an LDVDriverInfo structure (returned from
 *              ldv_get_driver_info) to be freed.
 *
 * Returns:     An LDV32 status code representing success (LDV_OK) or failure.
 *
 * See Also:    ldv_get_driver_info
 *
 * NOTE:        This feature was added in OpenLDV 2.0.
 */
LDVCode LDVAPI ldv_free_driver_info(
    IN LDVDriverInfo* pDriverInfo
);


/*------------- Device Information -----------------------------------------*/

/*
 * LDVDeviceCaps (32-bit) contains constants describing the capabilities of a
 * LonWorks Interface device.  These constants can be OR-ed together where
 * LonWorks Interface devices support multiple capabilities (e.g. an i.LON-100
 * Interface will specify LDV_DEVCAP_L5 | LDV_DEVCAP_PA; a USB Interface will
 * specify LDV_DEVCAP_L2 | LDV_DEVCAP_L5 | LDV_DEVCAP_SWITCHABLE | LDV_DEVCAP_PA).
 *
 * LDV_DEVCAP_L5            The device can operate as a layer 5 network interface.
 * LDV_DEVCAP_L2            The device can operate as a layer 2 network interface.
 *                          (This typically also means that the device could operate
 *                          as a protocol analyzer, but this assumption should not be relied upon.
 *                          There may be legitimate reasons why a layer 2 device has
 *                          been configured to operate only as a layer 2 network interface).
 * LDV_DEVCAP_LWIP          The device can operate as a LonWorks/IP device (channel).
 *                          Note that these type of devices cannot be opened using OpenLDV;
 *                          they can only be opened with LNS.
 * LDV_DEVCAP_PA            The device can operate as a protocol analyzer interface.
 * LDV_DEVCAP_XDRIVER       The device is an xDriver-based device and so is (typically)
 *                          physically located remotely from the host PC.
 *                          This is more of an informative flag than a capability,
 *                          but it still might be useful to know and be able to filter
 *                          based on this information (especially when considering that
 *                          remote network interfaces may have possibly undesirable side-effects
 *                          such as latency and response time issues, and connection costs;
 *                          and with device aliasing it might not otherwise be possible to tell).
 * LDV_DEVCAP_SICB          The device supports/generates SICB  formatted packets.
 * LDV_DEVCAP_LDVEX         The device supports/generates LdvEx formatted packets.
 * LDV_DEVCAP_NOSTATUS      The device does not support niSSTATUS.
 * LDV_DEVCAP_SWITCHABLE    The device can be switched to operate as either a layer 5
 *                          or a layer 2 network interface using this API.
 * LDV_DEVCAP_ATTACHABLE    The device is capable of being attached/detached from the
 *                          host PC.  It is possible to receive attachment/detachment
 *                          notifications for this device by registering a Window handle
 *                          using the ldv_register_window function.
 * LDV_DEVCAP_CURRENTLY_L5  The device is currently operating as a layer 5 network interface.
 * LDV_DEVCAP_CURRENTLY_L2  The device is currently operating as a layer 2 network interface.
 * LDV_DEVCAP_CURRENTLY_ATTACHED
 *                          The device is currently attached to the host PC.
 *                          This applies to devices that can be physically removed
 *                          (whilst their device entries remain, assuming that the driver
 *                          disconnect doesn't remove all driver entries).
 *                          This includes USBLTAs, and could also possibly be extended
 *                          to include xDriver RNIs that have become disconnected
 *                          (whether or not xDriver Recovery is in effect).
 *                          The opposite of this state implies that the device
 *                          is currently detached from the host PC.
 * LDV_DEVCAP_CURRENTLY_AVAILABLE
 *                          The device is currently not in use by any process on
 *                          this machine.  If it is not is use by another machine
 *                          then this indicates that the device is available for use.
 *
 *
 * NOTE:                    This feature was added in OpenLDV 2.0.
 */
enum LdvDeviceCaps
{
    LDV_DEVCAP_UNKNOWN              = 0x00000000,
    LDV_DEVCAP_NOCHANGE             = 0x00000000,

    // static capabilities
    LDV_DEVCAP_L5                   = 0x00000001,
    LDV_DEVCAP_L2                   = 0x00000002,

    LDV_DEVCAP_LWIP                 = 0x00000010,
    LDV_DEVCAP_PA                   = 0x00000020,
    LDV_DEVCAP_XDRIVER              = 0x00000040,

    LDV_DEVCAP_SICB                 = 0x00000100,
    LDV_DEVCAP_LDVEX                = 0x00000200,
    LDV_DEVCAP_NOSTATUS             = 0x00000800,

    LDV_DEVCAP_SWITCHABLE           = 0x00001000,
    LDV_DEVCAP_ATTACHABLE           = 0x00002000,

    LDV_DEVCAP_ALL_STATIC           = 0x0000FFFF,

    LDV_DEVCAP_ANY                  = (LDV_DEVCAP_L5 | LDV_DEVCAP_L2 | LDV_DEVCAP_PA),

    // dynamic capabilities
    LDV_DEVCAP_CURRENTLY_L5         = 0x00010000,
    LDV_DEVCAP_CURRENTLY_L2         = 0x00020000,

    LDV_DEVCAP_CURRENTLY_ATTACHED   = 0x20000000,
    LDV_DEVCAP_CURRENTLY_AVAILABLE  = 0x40000000,

    LDV_DEVCAP_ALL_DYNAMIC          = 0xFFFF0000,
};

typedef DWORD                       LDVDeviceCaps;


/*
 * The LDVDeviceInfo structure contains information describing a specific
 * LON interface device (as identified by its name).
 *
 * size         The size (in bytes) of this structure.  This field must be set
 *              before calling any of the set functions that pass this structure
 *              as a parameter.  It is used to determine the current version of
 *              this structure and to support its extension in future releases.
 * driver       A pointer to a driver information object describing the driver
 *              used by this device.  Ignored by ldv_set_device_info.
 * name         A pointer to a string containing the name of the
 *              (logical) device, if available.
 * physName     A pointer to a string containing the name of the
 *              physical device, if available.
 * desc         A pointer to a string containing the description of the device,
 *              if available.
 * caps         An LDVDeviceCaps value describing the capabilities of this device,
 *              where known.
 * capsMask     An LDVDeviceCaps mask describing which of the above capabilities
 *              bits are known (valid).
 * transId      Transceiver ID of the device.
 * driverId     Driver ID of the associated driver.
 *              A value of -1 signifies 'don't change'.
 *
 * See Also:    ldv_get_device_info, ldv_set_device_info
 *
 * NOTE:        This feature was added in OpenLDV 2.0.
 */
typedef struct LDVDeviceInfo
{
    DWORD                   size;
    const LDVDriverInfo*    driver;
    LPCSTR                  name;
    LPCSTR                  physName;
    LPCSTR                  desc;
    LDVDeviceCaps           caps;
    LDVDeviceCaps           capsMask;
    BYTE                    transId;
    LDVDriverID             driverId;
}                               LDVDeviceInfo;

typedef const LDVDeviceInfo*    LDVDeviceInfoPtr;       /* (read-only) */

#define LDV_TRANSID_UNKNOWN     255


/*
 * Retrieves information about the specified LON interface device.
 *
 * szDevice     The name of the LON interface device whose information
 *              is being requested.
 * ppDeviceInfo A pointer to an LDVDeviceInfo pointer to receive the
 *              information of the requested device.  Note that the contents
 *              of the returned structure is constant (read-only) and should
 *              not be modified.  If this function returns successfully,
 *              resources must be freed by calling ldv_free_device_info.
 *
 * Returns:     An LDV32 status code representing success (LDV_OK) or failure.
 *
 * See Also:    LDVDeviceInfo, ldv_set_device_info, ldv_free_device_info
 *
 * NOTE:        This feature was added in OpenLDV 2.0.
*/
LDVCode LDVAPI ldv_get_device_info(
    IN        LPCSTR          szDevice,
    OUT const LDVDeviceInfo** ppDeviceInfo
);


/*
 * Creates or modifies the information about the specified LON interface
 * device.  Before calling this function, the LDVDeviceInfo structure pointed
 * to by pDeviceInfo must be initialized correctly:
 *
 *  - Set 'size' to the size of the LDVDeviceInfo structure.
 *  - The 'driver' field will be ignored by this function.
 *  - If the name of the physical device is not to be modified,
 *    set 'physName' to NULL or an empty string.
 *    Otherwise set 'physName' to point to the new physical device name.
 *  - If the description of the device is not to be modified,
 *    set 'desc' to NULL or an empty string.  Otherwise set 'desc'
 *    to point to the new description.
 *  - If the driver ID is not to be modified, set 'driverId' to -1,
 *    otherwise set 'driverId' to the new driver ID.
 *  - Set all other fields to their desired values.
 *
 * In order to modify individual fields (read-modify-write) for an existing
 * device it is necessary to:
 *
 *  1. get the old information using ldv_get_device_info,
 *  2. allocate and initialize a new LDVDeviceInfo structure,
 *  3. copy unchanging fields from the old structure into the new
 *     (if strings aren't to be modified they can be simply set to NULL),
 *  4. set fields to be changed in the new structure,
 *  5. call ldv_set_device_info function,
 *  6. deallocate the new structure,
 *  7. free the old resources by calling ldv_free_device_info.
 *
 * NOTE: The (logical) device name, 'name', is read-only
 *       and cannot be modified using this function.
 *
 * NOTE: A driver cannot be modified using this function
 *       (an attached LDVDriverInfo object will be ignored)
 *       - use ldv_set_driver_info for that purpose.
 *
 * szDevice     The name of the LonWorks Interface device whose information
 *              is being requested.
 * pDeviceInfo  A pointer to an LDVDeviceInfo structure containing the device
 *              information to update.
 *
 * Returns:     An LDV32 status code representing success (LDV_OK) or failure
 *              (e.g. LDV_DEVICE_INFO_INVALID).
 *
 * See Also:    LDVDeviceInfo, ldv_get_device_info
 *
 * NOTE:        This feature was added in OpenLDV 2.0.
 */
LDVCode LDVAPI ldv_set_device_info(
    IN       LPCSTR         szDevice,
    IN const LDVDeviceInfo* pDeviceInfo
);


/*
 * Releases the resources allocated by a call to ldv_get_device_info
 * or ldv_get_matching_devices.
 *
 * ppDeviceInfo  An LDVDeviceInfo pointer to be freed.
 *
 * Returns:      An LDV32 status code representing success (LDV_OK) or failure.
 *
 * See Also:     ldv_get_device_info,  ldv_get_matching_devices, ldv_free_matching_devices
 *
 * NOTE:         This feature was added in OpenLDV 2.0.
 */
LDVCode LDVAPI ldv_free_device_info(
    IN const LDVDeviceInfo* pDeviceInfo
);


/*------------- Device Enumeration -----------------------------------------*/

/**
 * Enumeration to specify how multiple bits are combined when
 * determining device capability support.
 */
enum LdvCombineFlags
{
    LDV_COMBINE_DEFINITELY_ALL = 0,     /* all of the specified capabilities must definitely exist */
    LDV_COMBINE_POSSIBLY_ALL   = 1,     /* all of the specified capabilities must possibly   exist */
    LDV_COMBINE_DEFINITELY_ANY = 2,     /* any of the specified capabilities must definitely exist */
    LDV_COMBINE_POSSIBLY_ANY   = 3      /* any of the specified capabilities must possibly   exist */
};

typedef SHORT               LDVCombineFlags;


/*
 * The LDVDevices structure contains information describing a set of
 * LON interface devices.
 *
 * nInfos       The number of Device Info pointers in the array
 *              pointed to by pInfos.
 * pInfos       A pointer to an array of Device Info pointers.
 *
 * See Also:    ldv_get_matching_devices, ldv_free_matching_devices
 *
 * NOTE:        This feature was added in OpenLDV 2.0.
 */
typedef struct LDVDevices
{
    DWORD             nInfos;           /* number of Device Info pointers in array */
    LDVDeviceInfoPtr* pInfos;           /* array of Device Info pointers */
}                           LDVDevices;


/*
 * Retrieves information about the LON interface devices
 * that match the specified set of capabilities.
 *
 * nCaps        An LDVDeviceCaps value specifying the device capabilities
 *              to match.  Matching will be performed using the value specified
 *              in the nCombine parameter.
 * nCombine     Specifies the criterion used for matching.  This can be set
 *              to one of the LDV_COMBINE_* values.
 * pDevices     A pointer to a user-supplied LDVDevices structure
 *              that will receive the information of devices whose
 *              capabilities match those requested.
 *              Note that the contents of the returned array and structures
 *              are read-only and should not be modified.
 *              If this function returns successfully, resources must be
 *              freed by calling ldv_free_matching_devices.
 *              Do not call ldv_free_device_info on individual elements.
 *
 * Returns:     An LDV32 status code representing success (LDV_OK) or failure.
 *
 * See Also:    LDVDevices, ldv_free_matching_devices
 *
 * NOTE:        This feature was added in OpenLDV 2.0.
 */
LDVCode LDVAPI ldv_get_matching_devices(
    IN  LDVDeviceCaps   nCaps,
    IN  LDVCombineFlags nCombine,
    OUT LDVDevices*     pDevices
);


/*
 * Releases the resources allocated by a call to ldv_get_matching_devices.
 *
 * pDevices     A pointer to the user-supplied LDVDevices structure
 *              containing the resources to be freed.
 *
 * Returns:     An LDV32 status code representing success (LDV_OK) or failure.
 *
 * See Also:    LDVDevices, ldv_get_matching_devices
 *
 * NOTE:        This feature was added in OpenLDV 2.0.
 */
LDVCode LDVAPI ldv_free_matching_devices(
    IN LDVDevices* pDevices
);



/*------------- Device Access ----------------------------------------------*/

/*
 * This function is an extended version of ldv_open and ldvx_open that
 * additionally allows the caller to specify the 'mode' in which to open
 * the specified device.  For devices that support it, this will actually
 * control the switching to the requested mode.
 *
 * szDevice     Name of network interface to open.  For xDriver-based remote
 *              network interfaces (RNIs), this will be of the form
 *              "X.<Profile>.<RNI>".
 * pHandle      A pointer to a variable that will receive the LDV32 handle
 *              associated with a successfully opened session.  This handle
 *              will be assigned on return even if the session connection
 *              is continuing in the background.
 * nDeviceCaps  For devices that support multiple device capability 'modes',
 *              this parameter specifies the desired mode.
 *              e.g. a USBLTA can be opened as a layer 2 or a layer 5
 *              network interface by specifying the appropriate
 *              LDVDeviceCaps value.
 *              The packet format returned by ldv_read can be controlled by
 *              specifying LDV_DEVCAP_SICB and/or LDV_DEVCAP_LDVEX.
 * hWnd         The window handle that will receive session state change
 *              (and/or attachment) notification messages, where available
 *              (e.g. xDriver and USBLTA).
 *              If NULL, no notifications messages will be sent.
 * tag          A caller-supplied tag for correlating notification messages
 *              with sessions.  This tag will be supplied as the LPARAM
 *              parameter of all session state change messages.
 *
 * Returns:     An LDV32 status code representing success (LDV_OK) or failure.
 *              In particular, if the device does not support the requested
 *              capability, the error LDV_CAPABILITY_NOT_SUPPORTED will be
 *              returned.
 *
 * NOTE:        This feature was added in OpenLDV 2.0.
 */
LDVCode LDVAPI ldv_open_cap(
    IN  LPCSTR        szDevice,
    OUT LdvHandle*    pHandle,
    IN  LDVDeviceCaps nDeviceCaps,
    IN  HWND          hWnd,
    IN  LONG          tag
);


/**
 * Locates the SICB portion of the data within an LdvEx (or SICB) formatted
 * message, if present.
 *
 * pData        Pointer to a buffer containing an LdvEx (or SICB) message.
 *
 * nDataLen     Length of the buffer containing the LdvEx (or SICB) message.
 *
 * pnSicbOff    Pointer to a variable to receive the offset (in bytes) of the
 *              start of the SICB portion within the specified message.
 *
 * pnSicbLen    Pointer to a variable to receive the length of the SICB
 *              portion within the specified message.
 *
 * Returns:     An LDV32 status code representing success (LDV_OK) or failure.
 *              In particular, if an LdvEx packet does not contain
 *              an SICB message, the error LDV_NOT_FOUND will be returned,
 *              and if the packet is badly formed (e.g. not enough bytes),
 *              the error LDV_INVALID_DATA_FORMAT will be returned.
 *
 * NOTE:	    It is OK to pass a buffer containing just an SICB packet
 *              into this routine.  It will simply return with a zero offset
 *              and a decoded length.
 *
 * NOTE:        This feature was added in OpenLDV 2.0.
 */
LDVCode LDVAPI ldv_locate_sicb(
    IN  PVOID pData,
    IN  WORD  nDataLen,
    OUT WORD* pnSicbOff,
    OUT WORD* pnSicbLen
);



#ifdef __cplusplus
}
#endif  /* __cplusplus */

#pragma pack(pop)

#endif  /* _LDV32_H_ */
