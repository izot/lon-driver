// SPDX-License-Identifier: GPL-2.0 AND MIT
// Copyright © 2022-2025 EnOcean
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

#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <errno.h>
#include <ifaddrs.h>
#include <syslog.h>
#include <stdint.h>
#include <signal.h>
#include <sys/stat.h>
#include <systemd/sd-daemon.h>
#include <sys/file.h>
#include <time.h>                   /* for time()  */

/*
    See http://ftdi-usb-sio.sourceforge.net/#sec13
*/

// line disciplines - as defined in the drivers
#define N_U50           28
#define N_U61           27
#define BRATE_U61       B921600
#define BRATE_U50       B115200
#define BRATE_U61a      B460800

static char londevice[IFNAMSIZ];
static int londevicecount = 0;

#define NM_write_memory         0x6E
#define NM_read_memory          0x6D
#define NM_read_memory_succ     0x2D

#define L2_PKT_TYPE_LOCAL_NM_RESP		0x16	// Response to local NM command

#define STD_XCVR_NAMES_SIZE     32    // number of tansceiver supported
#define STD_XCVR_NAME_LEN       30    // max tansceiver name length
const char *xcvr_name[] = {
    "unspecified",      "TP/XF-78",     "XID-02",           "TP/XF-1250",
    "TP/FT-10",         "TP/RS485-39",  "LP-10-20",         "RF-10",
    "XID-08",           "PL-10",        "TP/RS485-625",     "TP/RS485-1250",
    "TP-RS485-78",      "XID-0D",       "XID-0E",           "XID-0F",
    "PL-20C",           "PL-20N",       "PL-30",            "XID-13",
    "XID-14",           "RF-450",       "IR-20",            "IR-10",
    "FO-10",            "XID-19",       "XID-1A",           "DC-78",
    "DC-625",           "DC-1250",      "custom",           "XID-1F"
};
typedef enum {
    XCVR_UNKNOWN,   TP_XF_78,       XCVR_2,         TP_XF_1250,
    FT_10,          TP_RS485_39,    LP_10_20,       RF_10,
    XCVR_8,         PL_10,          TP_RS485_625,   TP_RS485_1250,
    TP_RS485_78,    XCVR_13,        XCVR_14,        PL_20A,
    PL_20C,         PL_20N,         PL_30,          XCVR_19,
    XCVR_20,        RF_450,         IR_20,          IR_10,
    FO_20S,         XCVR_25,        XCVR_26,        DC_78,
    DC_625,         DC_1250,        XCVR_CUSTOM,    XCVR_31
} xcvr_ID;

#define LTIP_OBD_PREFIX_FILE "/var/apollo/conf.d/ltip_obd_prefix"
#define U50_LTIP_OBD_DRIVER_FILE "/sys/module/u50/ltip_obd_prefix"
#define U61_LTIP_OBD_DRIVER_FILE "/sys/module/u50/ltip_obd_prefix"
#define DEFAULT_PREFIX 44
volatile uint8_t ipv6_domain_len_1_prefix = DEFAULT_PREFIX;

// This function create a LON network interface using the Line disciplines
// return < 0 if failure
static int setup_serial_interface(char* devstr, int ldisc) {
    int fd;
    FILE *mod_sysfs_file;
    struct termios tio;
    tcflag_t c_cflag;
    bzero(&tio, sizeof(tio));
    if (ldisc == N_U61)
        c_cflag = BRATE_U61a;
    else
        c_cflag = BRATE_U50;
    tio.c_cflag = c_cflag | CS8 | CLOCAL | CREAD;
    tio.c_iflag = IGNPAR;
    tio.c_oflag = 0;
    tio.c_lflag = 0;
    tio.c_cc[VMIN] = 0;
    tio.c_cc[VTIME] = 1;

    fd = open(devstr, O_RDWR | O_NOCTTY);
    if (fd < 0) {
        perror("open");
        syslog(LOG_ERR, "Error opening device %s: %s\n", devstr, strerror(errno));
    } else {
        tcflush(fd, TCIFLUSH);
        if(tcsetattr(fd, TCSANOW, &tio) < 0) {
            perror("tcsetattr");
            syslog(LOG_ERR, "Error setting device attributes (tcsetattr): %s\n", strerror(errno));
        }
        if (ioctl(fd, TIOCSETD, &ldisc) < 0) {
            perror("ioctl");
            syslog(LOG_ERR, "Error setting device attributes (ioctl %d): %s\n", ldisc, strerror(errno));
        }
    }
    if (ldisc == N_U61)
        mod_sysfs_file = fopen(U61_LTIP_OBD_DRIVER_FILE, "w+");
    else
        mod_sysfs_file = fopen(U50_LTIP_OBD_DRIVER_FILE, "w+");
    if (mod_sysfs_file) {
        fseek(mod_sysfs_file, 0, SEEK_SET);
        fprintf(mod_sysfs_file, "%d", ipv6_domain_len_1_prefix);
        fclose(mod_sysfs_file);
    }
    return fd;
}

static int read_domain_len_1_prefix()
{
    FILE *f = fopen(LTIP_OBD_PREFIX_FILE, "r");
    char bufferStr[512];
    int prefix = DEFAULT_PREFIX;

    if (f == NULL) return prefix;
    if (fgets(bufferStr, sizeof(bufferStr), f) != NULL)
        prefix = atoi(bufferStr);
    fclose(f);
    return prefix;
}

static int read_neuron_id(uint8_t *nid_buf, int sockfd)
{
    struct ifreq ifr = {0};
    int init_sock= 0;
    int retval = 0;

	//
    // typedef struct {
    //     byte        code;
    //     byte        mode;
    //     byte        offset_hi;
    //     byte        offset_lo;
    //     byte        count;
    // } NM_read_memory_request;
    //	
    // Read Memory Local Message
    // Here's the break down of the message: 	
    // Network Interface header (2 bytes) :
    //    Network interface command with queue
    //    0x22 = (niNETMGMT (2) << 4) | niTQ (2)
    //    0x13 =  Length of the buffer to follow  (19)
    // Message header (3 bytes) : 
    //    0x70 =  tag = 0(0000), auth = 1 (1) serviceType = 3 (11) msg_type = 0 (explicit msg)
    //    0x00 =  response = no
    //    0x05 =  Length of msg or NV to follow
    //             not including any explicit address field,
    //             includes code byte 	
	// MsgData (5 bytes): (see the NM_read_memory_request stucture above)
	//    0x6d = NM_read_memory code
	//    0x01 = READ_ONLY_RELATIVE mode
    //    0x00 = offset_hi
    //    0x00 = offset_lo
    //    0x06 = length to read (neuron ID length)	
    uint8_t a[] = { 0x22, 0x13, 0x70, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, NM_read_memory, 0x01, 0x00, 0x00, 0x06 };

    if (sockfd == -1)
    {
        init_sock= 1;
        sockfd = socket(AF_PACKET, SOCK_RAW, htons(0x8950));
        memcpy(ifr.ifr_name, londevice, IFNAMSIZ);
        if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
            perror("ioctl");
            syslog(LOG_ERR, "Ioctl:%d: %s\n", __LINE__, strerror(errno));
            retval = -1;
        }

        struct sockaddr_ll addr_ll = { 0 };
        addr_ll.sll_family = AF_PACKET;
        addr_ll.sll_ifindex = ifr.ifr_ifindex;

        if(bind(sockfd, (struct sockaddr*) &addr_ll, sizeof(struct sockaddr_ll)) < 0) {
            perror("bind");
            syslog(LOG_ERR, "Bind: %s\n", strerror(errno));
            retval = -1;
        }
    }

    int readlen = 0;
    fd_set fds;
    struct timeval tv;

    // Execute read memory local message to read neuronID
    for (;;) {
        int b;
        if ((b = write(sockfd, a, sizeof(a))) < 0) perror("write");
        uint8_t readbuf[32];
        memset(readbuf, 0, 32);
        readlen = 0;

        FD_ZERO(&fds);
        FD_SET(sockfd, &fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (select(sockfd+1, &fds, NULL, NULL, &tv))
            readlen = read(sockfd, readbuf, 32);
        if (readlen >= 23 && readbuf[0] == L2_PKT_TYPE_LOCAL_NM_RESP && 
		        readbuf[16] == NM_read_memory_succ) {
            // read memory response is 23 bytes, this could be parsed
            // with a lot more headers brought in
            int i;
            for (i=0; i < 6; i++)
                nid_buf[i] = readbuf[i+17];
            break;
        }
    }

    if (init_sock)
        close(sockfd);
    return retval;
}

/*
 ****************************************************************************
 * CONFIG structure addresses
 ****************************************************************************
 */
typedef unsigned char   bits;
typedef unsigned short  word;      /* 16 bits */
typedef unsigned short  uint16_t;
typedef unsigned int    uint32_t;
typedef short			LNI;
typedef unsigned char   byte;

#define LOCATION_ID_LEN 6
typedef struct {
    word    chan_id;
    byte    location[ LOCATION_ID_LEN ];
} config_struct;

#define OFS_CONFIG_STRUCT 0x0000
#define NUM_SPMODE_PARAMS 7
typedef struct {
    bits    input_clock     : 3;
    bits    comm_clock      : 5;
    bits    comm_pin_dir    : 5;
    bits    comm_type       : 3;
    byte    preamble_length;
    byte    packet_cycle;
    byte    beta2_control;
    byte    xmit_interpacket;
    byte    recv_interpacket;
    byte    node_priority;
    byte    channel_priorities;
    union {
        byte    spmode_params[ NUM_SPMODE_PARAMS ];
        struct {
            bits    hysteresis          : 3;
            bits    filter              : 2;
            bits    bit_sync_threshold  : 2;
            bits    collision_detect    : 1;
            bits    cd_preamble         : 1;
            bits    cd_tail             : 1;
            bits    cd_to_end_packet    : 6;
        } dir_params;
    } params;
} xcvr_param_type;

                  //clks pin  prea pktc bet2 xmip rcip ndpr chpr fltr cdet			
byte PL_20N_10[] = {0x05,0x5E,0x00,0x3F,0xA6,0x77,0x67,0x00,0x08,0x0E,0x01};
byte PL_20C_10[] = {0x05,0x5E,0x00,0x3F,0xA6,0x77,0x67,0x00,0x08,0x4A,0x00};

#define OFS_COMM_PARAMS         ( OFS_CONFIG_STRUCT + sizeof( config_struct ) )
#define OFS_COMM_XCVR_PARAMS    0x11
#define COMM_PARAM_BYTES 11
#define LOCAL_WAIT       3     /* default wait time for local response */

typedef enum {
    NO_ACTION      = 0,
    BOTH_CS_RECALC = 1,
    CNFG_CS_RECALC = 4,
    NODE_RESET     = 8,
    NO_ERASE       = 16,        // Don't erase flash.
    FLASH_SYSTEM_IMAGE = 0x80
} _nm_mem_form;
typedef int nm_mem_form;

typedef enum {
    ABSOLUTE_ADDR      = 0,
    READ_ONLY_RELATIVE = 1,
    CONFIG_RELATIVE    = 2,
    STATS_RELATIVE     = 3,
	ABSOLUTE_NONVM     = 5,		// do not shadow to NVM
	SI_WORD_OFFSET     = 6,		// system image word (16B) offset
	APP_WORD_OFFSET    = 7,		// application image word (16B) offset
	ABS_WORD_OFFSET    = 8,		// absolute image word (16B) offset

    MEM_MODE_NUM,
} nm_mem_mode;

typedef enum {
    niNULL           = 0x00,
    niTIMEOUT        = 0x30,        /* Not used                             */
    niCRC            = 0x40,        /* Not used                             */
    niRESET          = 0x50,
    niFLUSH_COMPLETE = 0x60,        /* Uplink                               */
    niFLUSH_CANCEL   = 0x60,        /* Downlink                             */
    niONLINE         = 0x70,
    niOFFLINE        = 0x80,
    niFLUSH          = 0x90,
    niFLUSH_IGN      = 0xA0,
    niSLEEP          = 0xB0,
    niACK            = 0xC0,
    niNACK           = 0xC1,        /* SLTA only                            */
    niSSTATUS        = 0xE0,
    niPUPXOFF        = 0xE1,
    niPUPXON         = 0xE2,
    niPTRHROTL       = 0xE4,        /* Not used                             */
    niIRQENA         = 0xE5,
    niSERVICE        = 0xE6,
    niTXID           = 0xE8,
    niSLTAPLS        = 0xEA,
    niDRV_CMD        = 0xF0,        /* Not used                             */
} NI_NoQueueCmd;


// Send the network management message to read the CENELEC protocol
static int get_protocol(int sockfd, uint8_t* result)
{
    int init_sock= 0;
    struct ifreq ifr = {0};
	int IsCenelec = -1;

    if (sockfd == -1)
    {
        init_sock = 1;
        sockfd = socket(AF_PACKET, SOCK_RAW, htons(0x8950));
        memcpy(ifr.ifr_name, londevice, IFNAMSIZ);
        if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0)
            perror("ioctl");

        struct sockaddr_ll addr_ll = { 0 };
        addr_ll.sll_family = AF_PACKET;
        addr_ll.sll_ifindex = ifr.ifr_ifindex;

        if(bind(sockfd, (struct sockaddr*) &addr_ll, sizeof(struct sockaddr_ll)) < 0) 
            perror("bind");
    }

    int readlen = 0;
    fd_set fds;
    struct timeval tv;
    int ret;
 
    // Send the read memory message to get the transceiver params 
	//
    // typedef struct {
    //     byte        code;
    //     byte        mode;
    //     byte        offset_hi;
    //     byte        offset_lo;
    //     byte        count;
    // } NM_read_memory_request;
    //
    // Here's the complete message: 	
    // Network Interface header (2 bytes) :
    //    Network interface command with queue
    //    0x22 = (niNETMGMT (2) << 4) | niTQ (2)
    //    0x13 =  Length of the buffer to follow  (19)
    // Message header (3 bytes) :
    //    0x74 =  tag = 4(0100), auth = 1 (1) serviceType = 3 (0x11 -  Request) msg_type = 0 (explicit msg)
    //    0x00 =  response = no
    //    0x05 =  Length of msg or NV to follow
    //             not including any explicit address field,
    //             includes code byte 
	// MsgData (5 bytes): (see the NM_read_memory_request structure above)
	//    0x6d = NM_read_memory code
	//    0x02 = CONFIG_RELATIVE mode
    //    0x00 = offset_hi
    //    0x0A = offset_lo - offset to the xcvr_params  -> OFS_COMM_PARAMS + 2
    //    0x09 = length to read (xcvr_params size)	-> COMM_PARAM_BYTES - 2
    //   
    // The first two bytes of xcvr_params contains the CENELEC bytes	
    uint8_t t[] = { 0x22, 0x13, 0x74, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, NM_read_memory, 0x02, 0x00, OFS_COMM_PARAMS + 2, 
		COMM_PARAM_BYTES - 2 };

    time_t  deadline;
    deadline = time( NULL ) + LOCAL_WAIT;
    for (;;) {
        int b;

        if( time( NULL ) > deadline )
            break;

        if ((b = write(sockfd, t, sizeof(t))) < 0) perror("write");
        uint8_t readbuf[32];
        memset(readbuf, 0, 32);
        readlen = 0;

        FD_ZERO(&fds);
        FD_SET(sockfd, &fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (select(sockfd+1, &fds, NULL, NULL, &tv))
            readlen = read(sockfd, readbuf, 32);
        printf("Read Length = %02x\n", readlen);
        for (int i = 0; i < readlen; ++i)
        {
            printf("%02x ", readbuf[i]);
            if ((i % 10) == 0 && i != 0)  printf("\n");
        }
        printf("\n");
        if (readlen >= 26 && readbuf[0] == L2_PKT_TYPE_LOCAL_NM_RESP && 
            readbuf[16] == NM_read_memory_succ) {
            // read memory response is 26 bytes, this could be parsed
            // with a lot more headers brought in
                                    //clks pin  prea pktc bet2 xmip rcip ndpr chpr fltr cdet			
            // #define PL_20N_10     {0x05,0x5E,0x00,0x3F,0xA6,0x77,0x67,0x00,0x08,0x0E,0x01}
            // #define PL_20C_10     {0x05,0x5E,0x00,0x3F,0xA6,0x77,0x67,0x00,0x08,0x4A,0x00}			
            if (readbuf[24] == PL_20N_10[9] && readbuf[25] == PL_20N_10[10])
				IsCenelec = 0;
			else if (readbuf[24] == PL_20C_10[9] && readbuf[25] == PL_20C_10[10])
				IsCenelec = 1;
	    // xcvr param type and first two bytes of params.xcvr_params
            if (result != NULL)
                memcpy(result, &readbuf[17], COMM_PARAM_BYTES - 2); 				
            break;
        }
    }

    if (init_sock)
        close(sockfd);
    return IsCenelec;	// returns -1 if there's an error 
}

// Send the network management message to
// enable or disable the CENELEC protocol for a PL-20 node
static int set_protocol(int sockfd, int enableCenelec)
{
    struct ifreq ifr = {0};
    int retval = -1;
    int init_sock= 0;

    if (sockfd == -1)
    {
        init_sock = 1;
        sockfd = socket(AF_PACKET, SOCK_RAW, htons(0x8950));
        memcpy(ifr.ifr_name, londevice, IFNAMSIZ);
        if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0)
            perror("ioctl");

        struct sockaddr_ll addr_ll = { 0 };
        addr_ll.sll_family = AF_PACKET;
        addr_ll.sll_ifindex = ifr.ifr_ifindex;

        if(bind(sockfd, (struct sockaddr*) &addr_ll, sizeof(struct sockaddr_ll)) < 0) 
            perror("bind");
    }

	// Read the existing protocol setting 
    // The first two bytes of xcvr_params contains the CENELEC bytes	
	uint8_t readbuf[32];
    memset(readbuf, 0, 32);	
    int isCENELEC = get_protocol(sockfd, readbuf);
    if (isCENELEC == enableCenelec)
    {
        printf("No change\n");		
		return 0;  // no change
    }

    if (isCENELEC != -1)
    {
        // The first two bytes of xcvr_params contains the CENELEC bytes
		// The rest of the bytes are using the current settings 
        if  (enableCenelec)
        {
            readbuf[7] = PL_20C_10[9];
            readbuf[8] = PL_20C_10[10];
        }
        else
        {
            readbuf[7] = PL_20N_10[9];
            readbuf[8] = PL_20N_10[10];
        }
    }
    else
    {
        // Problem on reading the comm param bytes		
        if  (enableCenelec)
            memcpy(readbuf, &PL_20C_10[2], COMM_PARAM_BYTES - 2);
        else
            memcpy(readbuf, &PL_20N_10[2], COMM_PARAM_BYTES - 2);			
    }

    // Send the network management message to update the protocol 
    // typedef struct {
    //    byte    code;
    //    byte    mode;
    //    byte    offset_hi;
    //    byte    offset_lo;
    //    byte    count;          // byte count or page count for high memory
    //    byte    form;           // followed by the data
    //} NM_write_memory_request;
    //
    // Here's the message: 	
    // Network Interface header (2 bytes) :
    //    Network interface command with queue
    //    0x22 = (niNETMGMT (2) << 4) | niTQ (2)
    //    0x1D =  Length of the buffer to follow  (29)
    // Message header (3 bytes) :
    //    0x71 =  tag = 1(0001), auth = 1 (1) serviceType = 2 (0x10 - UNACKD) msg_type = 0 (explicit msg)
    //    0x00 =  response = no
    //    0x0F =  Length of NM_write_memory_request (6) + data to write (COMM_PARAM_BYTES - 2 = 9)
    //
	// MsgData (6 bytes): (see the NM_write_memory_request structure above)
	//    0x6e = NM_write_memory code
	//    0x02 = CONFIG_RELATIVE mode
    //    0x00 = offset_hi
    //    0x0A = offset_lo - offset to the xcvr_params (skip xcvr type and comm rate bytes)
    //    0x09 = length to write (xcvr_params size)	--> COMM_PARAM_BYTES - 2
    //    CNFG_CS_RECALC | NODE_RESET = form 
    uint8_t t[] = { 0x22, 0x1D, 0x71, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, NM_write_memory, CONFIG_RELATIVE, 0x00, OFS_COMM_PARAMS + 2, 
		 COMM_PARAM_BYTES - 2, CNFG_CS_RECALC | NODE_RESET,  
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    // Update the last 9 bytes of the data to write which are the comm param data bytes
	// NOTE: don't write xcvr type and comm rate bytes
    memcpy(&t[22], readbuf, COMM_PARAM_BYTES - 2);
    printf("Data to write\n");
    for (int i = 0; i < sizeof(t); ++i)
    {
        printf("%02x ", t[i]);
        if ((i % 10) == 0 && i != 0)  printf("\n");
    }
    printf("\n");

    time_t  deadline;
    deadline = time( NULL ) + LOCAL_WAIT;
    // Loop until the network interface provides a message, or timeout
    for (;;) {
        int b;
        int readlen = 0;
        fd_set fds;
        struct timeval tv;

        if( time( NULL ) > deadline )
            break;
 
        // Otherwise, keep trying 
        if ((b = write(sockfd, t, sizeof(t))) < 0) perror("write");
        memset(readbuf, 0, 32);

        FD_ZERO(&fds);
        FD_SET(sockfd, &fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (select(sockfd+1, &fds, NULL, NULL, &tv))
            readlen = read(sockfd, readbuf, 32);
        printf("set_protocol Read Length = %d\n", readlen);
        for (int i = 0; i < readlen; ++i)
        {
            printf("%x ", readbuf[0]);
            if ((i % 10) == 0 && i != 0)  printf("\n");
        }
        printf("\n");
        if (readlen >= 0 && readbuf[0] == niRESET) {
            // receive uplink local reset
            printf("Received uplink local reset.\n");			
            sleep(2);
			retval = 0;
            break;
        }
    }

    if (init_sock)
        close(sockfd);
    return retval;
}

// Returns the transceiver ID
static int read_xcvr_id(int sockfd, int ldisc)
{
    struct ifreq ifr = {0};
    int xcvr_id = XCVR_UNKNOWN;
    int init_sock= 0;

    if (sockfd == -1)
    {
        init_sock = 1;
        sockfd = socket(AF_PACKET, SOCK_RAW, htons(0x8950));
        memcpy(ifr.ifr_name, londevice, IFNAMSIZ);
        if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0)
            perror("ioctl");

        struct sockaddr_ll addr_ll = { 0 };
        addr_ll.sll_family = AF_PACKET;
        addr_ll.sll_ifindex = ifr.ifr_ifindex;

        if(bind(sockfd, (struct sockaddr*) &addr_ll, sizeof(struct sockaddr_ll)) < 0) 
            perror("bind");
    }

    int readlen = 0;
    fd_set fds;
    struct timeval tv;
    int ret;

    // Send the network management message to read the transceiver ID
    // typedef struct ANM_slta_gen_request {
    //    byte    code;                // 0x7D
    //    byte    sub_code;            // 1 - use enum ANM_sub_code
    //    byte    app_command;        // 1 - use enum ANM_slta_code
    // } ANM_slta_gen_request    
    // Network Interface header (2 bytes) :
    //    Network interface command with queue
    //    0x22 = (niNETMGMT (2) << 4) | niTQ (2)
    //    0x11 =  Length of the buffer to follow  (17)
    // Message header (3 bytes) :
    //    0x75 =  tag = 5(0101), auth = 1 (1) serviceType = 3 (11) msg_type = 0 (explicit msg)
    //  0x00 =  response = no
    //  0x03 =  Length of msg or NV to follow
    //             not including any explicit address field,
    //             includes code byte 
    // MsgData:
    //     0x7d = message code NM_anm_escape
    //     0x01 = subc_slta
    //    0x01 = ANM_product_query
    //    
    uint8_t t[] = { 0x22, 0x11, 0x75, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7d, 0x01, 0x01 };

       for (;;) {
        int b;
        if ((b = write(sockfd, t, sizeof(t))) < 0) perror("write");
        uint8_t readbuf[32];
        memset(readbuf, 0, 32);
        readlen = 0;

        FD_ZERO(&fds);
        FD_SET(sockfd, &fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (select(sockfd+1, &fds, NULL, NULL, &tv))
            readlen = read(sockfd, readbuf, 32);

        if (readlen >= 22 && readbuf[0] == L2_PKT_TYPE_LOCAL_NM_RESP && readbuf[16] == 0x3d) {
            // get_xcvr_id response is 6 bytes, this could be parsed
            // with a lot more headers brought in
            //typedef struct ANM_product_query_response {
            //    byte    code;
            //    byte    product;    // Use ANM_product
            //    byte    model;      // Use xxx_model
            //    byte    version;
            //    byte    config;     // Use slta_config for SLTA
            //    bits    transceiver_ID      : 5;
            //    bits    XID_reserved        : 3;
             //} ANM_product_query_response;
            // Network Interface header (2 bytes) :
            // Network interface command with queue
            //    0x16 = (niCOMM (1) << 4) | niRESPONSE (6)
            //    0x14 =  Length of the buffer to follow
            // Message header (3 bytes) :
            //    0x75 =  tag = 0(0101), auth = 1 (1) serviceType = 3 (11) msg_type = 0 (explicit msg)
            //  0x01 =  response = yes
            //  0x06 =  Length of msg or NV to follow
            //             not including any explicit address field,
            //             includes code byte
            // MsgData:
            //     0x3d = successful response code
            //     0x02 = product - subc_nss_xx (??)
            //    0x03 = model
            //  0x1f = version
            //    0x00 = config
            //    0x1e = transceiver_ID
            //
            xcvr_id = readbuf[21] & 0x1f;
            if ((xcvr_id == XCVR_CUSTOM) || (xcvr_id >= STD_XCVR_NAMES_SIZE) )
            {
                // The U60 (FT and 1250) returns Custom as a transceiver ID.
                // Use the USB model#
                if (ldisc == N_U50)
                    xcvr_id = FT_10;
                else
                if (ldisc == N_U61)
                    xcvr_id = TP_XF_1250;
            } 

            if (xcvr_id >= STD_XCVR_NAMES_SIZE)
            {
                // For now it always defaulted to N_U50.  So it never goes here.
                syslog(LOG_ERR, "Error reading xcvr_id - %d.  Set xcvr_id to Unknown. \n", xcvr_id);
                xcvr_id = XCVR_UNKNOWN;
            }
            break;
        }
    }

    if (init_sock)
        close(sockfd);
    return xcvr_id;
}

#define VERSION_FILE            "/etc/apollo/version"
#define LON_NI_CONF_FILE        "/var/apollo/data/router/lonNi.conf"
#define SINGLE_LON_MODE_KEY     "single_lon_mode"
// We only try to enforce single network interface to be lon0 
// if single lon mode is enforced in lonNI.conf file -> single_lon_mode=true 
static int lon0_is_enforced()
{
    FILE *f = fopen(LON_NI_CONF_FILE, "r");
    char bufferStr[512];
    int retval = 0;

    if (f == NULL) return 0;
    while (fgets(bufferStr, sizeof(bufferStr), f) != NULL)
    {
        if (bufferStr[0] == '#')
            continue;  // the line is commented out
        if (strstr(bufferStr, SINGLE_LON_MODE_KEY) != NULL)
        {
            if (strstr(bufferStr, "true") != NULL)
            {
                retval = 1;
            }
            break;
        }
    }
    fclose(f);
    return retval;
}

#define NID_INDEX_FILE        "/var/apollo/data/router/nid_index"
#define TEMP_FILE        "/var/apollo/data/router/nid_indexXXXXXX"

// Return: -1 if there was a problem.
// tempFilename[255] expected.
static int create_temp_file(char *tempFilename)
{
    strcpy(tempFilename, TEMP_FILE);
    int fdTemp = mkstemp(tempFilename);
    if (fdTemp != -1) {
        // mkstemp() creates with mode 0600 - kind of restrictive, so:
        fchmod(fdTemp, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
    } else {
        syslog(LOG_ERR, "%s: Failed to create temp file\n", __func__);
    }
    return fdTemp;
}

int update_nid_index(FILE *f, FILE *fBak, int indexToReplace, char *searchnid, const char *searchXcvrType, char* devstr)
{
    char nidstr[18], xcvrtypestr[STD_XCVR_NAME_LEN], ttydevstr[16];
    char bufferStr[255];
    int index;
    int found = 0;

    fseek(f, 0L, SEEK_SET);    // rewind file f -> NID_INDEX_FILE
    if (f != NULL && fBak !=NULL) {
        xcvrtypestr[0] = '\0';
        ttydevstr[0] = '\0';
        while (fgets(bufferStr, sizeof(bufferStr), f) != NULL)  {
            if (sscanf(bufferStr, "%3d %17s %29s %15s", &index, nidstr, xcvrtypestr, ttydevstr) >= 2)  {
                if (index == indexToReplace) {
                    // Replace the entry
                    fprintf(fBak, "%i %s %s %s\n", index, searchnid, searchXcvrType, devstr);
                    found = 1;
                }
                else if (!(found && !strcmp(searchnid, nidstr)))  //  Check for duplicate entries
                    fprintf(fBak, "%i %s %s %s\n", index, nidstr, xcvrtypestr, ttydevstr);
                xcvrtypestr[0] = '\0';
                ttydevstr[0] = '\0';
            }
        }
        if (!found)
            fprintf(f, "%i %s %s %s\n", indexToReplace, searchnid, searchXcvrType, devstr);
    }

    if (found)
        return 1;
    else
        return 0;
}

int find_xcvr_type(const char* ifname, char *xcvr_type) 
{
    int nTries = 5;
    FILE *f;
    int fd;
    int retval = -1;

    while(nTries--)
    {
        f = fopen(NID_INDEX_FILE, "r");
        fd = fileno(f);
        if (flock(fd, LOCK_EX|LOCK_NB) == 0)
            break;
        fclose(f);
        syslog(LOG_INFO, "find_xcvr_type: File %s is locked\n", NID_INDEX_FILE);
        sleep(2);
    }

    if (nTries == 0 || f == NULL)
    {
        syslog(LOG_INFO, "find_xcvr_type: Failed to open %s\n", NID_INDEX_FILE);
        return retval;
    }

    int index = -1;
    char indexstr[8], nidstr[18], xcvrtypestr[STD_XCVR_NAME_LEN], devtty[20];

    xcvrtypestr[0] = '\0';
    while (fscanf(f, "%d %17s %29s %19s", &index, nidstr, xcvrtypestr, devtty) >= 3) {
        sprintf(indexstr, "lon%d", index);
        if (!strcmp(indexstr, ifname)) {
            strcpy(xcvr_type, xcvrtypestr);
            break;    // found the nid in the list
        }
        xcvrtypestr[0] = '\0';
    }
    if (ferror(f)) {
        syslog(LOG_INFO, "Error in reading %s\n", NID_INDEX_FILE);
        retval = -1;
    }
    else
        retval = 0;
    flock(fd, LOCK_UN);
    fclose(f);
    return retval;
}

int update_xcvr_type(const char* ifname, const char *newXcvrType) 
{
    int nTries = 5;
    FILE *f;
    int fd;
    int retval = -1;


    while(nTries--)
    {
        f = fopen(NID_INDEX_FILE, "r");
        fd = fileno(f);
        if (flock(fd, LOCK_EX|LOCK_NB) == 0)
            break;
        fclose(f);
        syslog(LOG_INFO, "update_xcvr_type: File %s is locked\n", NID_INDEX_FILE);
        sleep(2);
    }

    if (nTries == 0 || f == NULL)
    {
        syslog(LOG_INFO, "update_xcvr_type: Failed to open %s\n", NID_INDEX_FILE);
        return retval;
    }

    int index = -1;
    char indexstr[8], nidstr[18], xcvrtypestr[STD_XCVR_NAME_LEN], ttydevstr[16];
    char tempFilename[255] = "";
    char bufferStr[255];

    if (create_temp_file(tempFilename) != -1) {
        FILE *fBak = fopen(tempFilename, "w");

        if (f != NULL && fBak !=NULL) {
            while (fgets(bufferStr, sizeof(bufferStr), f) != NULL)  {
                nidstr[0] = '\0';
                xcvrtypestr[0] = '\0';
                ttydevstr[0] = '\0';			
                if (sscanf(bufferStr, "%3d %17s %29s %15s", &index, nidstr, xcvrtypestr, ttydevstr) == 4)  {
                    sprintf(indexstr, "lon%d", index);		
                    if (!strcmp(indexstr, ifname))
                        // Replace the xcvr type
                        fprintf(fBak, "%i %s %s %s\n", index, nidstr, newXcvrType, ttydevstr);
                    else
                        fprintf(fBak, "%i %s %s %s\n", index, nidstr, xcvrtypestr, ttydevstr);
                }
            }
            retval = 1;
        }

        if (fBak != NULL) fclose(fBak);
        if (retval == 1)  {
            remove(NID_INDEX_FILE);
            rename(tempFilename, NID_INDEX_FILE);
        }
        else {
            remove(tempFilename);
        }
    }
    flock(fd, LOCK_UN);
    fclose(f);
    return retval;
}

int find_nid_index(uint8_t *nid, char* name, const char *xcvr_type, char* devstr)
{
    FILE *f = fopen(NID_INDEX_FILE, "a+");

    if (f == NULL) return -1;

    int fd = fileno(f);
    if (flock(fd, LOCK_EX|LOCK_NB) == -1)
    {
        syslog(LOG_INFO, "find_nid_index: File %s is locked\n", NID_INDEX_FILE);
        fclose(f);
        return -1;
    }
    // The following prevents a race condition, where a program holding
    // a lock on a file that is still on the file system causing every
    // other program that has a leftover file will have a wrong inode number.
    struct stat st0, st1;
    fstat(fd, &st0);
    stat(NID_INDEX_FILE, &st1);
    if(st0.st_ino != st1.st_ino) {
        syslog(LOG_INFO, "find_nid_index: Race condition file %s %ld - %ld\n", NID_INDEX_FILE, st0.st_ino, st1.st_ino);
        flock(fd, LOCK_UN);
        fclose(f);
        return -1;
    }

    int found = 0, max_index = 0, needupdt = 0;
    char indexstr[8], nidstr[18], searchnid[18], xcvrtypestr[STD_XCVR_NAME_LEN], ttydevstr[16];
    char bufferStr[255];

    sprintf(searchnid, "%02x:%02x:%02x:%02x:%02x:%02x",
        nid[0], nid[1], nid[2], nid[3], nid[4], nid[5]);
    xcvrtypestr[0] = '\0';
    ttydevstr[0] = '\0';

    while (fgets(bufferStr, sizeof(bufferStr), f) != NULL) {
        if (sscanf(bufferStr, "%3s %17s %29s %15s", indexstr, nidstr, xcvrtypestr, ttydevstr) >= 2) {
            if (!strcmp(searchnid, nidstr)) {
                found = 1;
                if (strcmp(xcvr_type, xcvrtypestr))
                    needupdt = 1;
                else if (strcmp(devstr, ttydevstr))
                    needupdt = 1;
                max_index = strtol(indexstr, NULL, 10);
                break;    // found the nid in the list
            } else {
                max_index = strtol(indexstr, NULL, 10)+1;
            }
        }
        xcvrtypestr[0] = '\0';
        ttydevstr[0] = '\0';
    }
    if (ferror(f)) {
        flock(fd, LOCK_UN);
        fclose(f);
        return -1;
    }

    FILE *fBak = NULL;
    int retval = -1;
    char tempFilename[255] = "";

    // AP-945 Support single LON mode
    // AP-4799 the single LON mode is also enforced whether or not 
    // the interface has already been registered or not (already part of nid_index file)
    if (londevicecount == 0 && lon0_is_enforced())
    {
        // It is only one LON device connected.  We want to force it to be lon0
        // Update the NID_INDEX_FILE file if necessary.
        if (create_temp_file(tempFilename) != -1) {
            fBak = fopen(tempFilename, "w");
            retval = update_nid_index(f, fBak, 0, searchnid, xcvr_type, devstr);
            max_index = 0;  // force it to lon0
            sprintf(name, "lon%i", max_index);
        }
    }
    else
    {
        if (!found) {
            fprintf(f, "%i %s %s %s\n", max_index, searchnid, xcvr_type, devstr);
            sprintf(name, "lon%i", max_index);
        }
        else {
            if (needupdt)
            {
                // Need to update the entry with a new transceiver type
                // (or transceiver type was not there at the first place)
                // or ttydevstr has been changed
                if (create_temp_file(tempFilename) != -1) {
                    fBak = fopen(tempFilename, "w");
                    retval = update_nid_index(f, fBak, max_index, searchnid, xcvr_type, devstr);
                }
            }
            sprintf(name, "lon%s", indexstr);
        }
    }

    if (fBak != NULL) fclose(fBak);
    if (retval == 1)  {
        remove(NID_INDEX_FILE);
        rename(tempFilename, NID_INDEX_FILE);
    }
    else if(tempFilename[0]) {
        remove(tempFilename);
    }
    flock(fd, LOCK_UN);
    fclose(f);
    return 0;
}

static int init_sockfd()
{
    struct ifreq ifr = {0};
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(0x8950));

    memcpy(ifr.ifr_name, londevice, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl");
        syslog(LOG_ERR, "Ioctl:%d: %s\n", __LINE__, strerror(errno));
    }

    struct sockaddr_ll addr_ll = { 0 };
    addr_ll.sll_family = AF_PACKET;
    addr_ll.sll_ifindex = ifr.ifr_ifindex;

    if(bind(sockfd, (struct sockaddr*) &addr_ll, sizeof(struct sockaddr_ll)) < 0) {
        perror("bind");
        syslog(LOG_ERR, "Bind: %s\n", strerror(errno));
    }

    return sockfd;
}

static void assign_default_address(int ldisc, char* devstr) {
    struct ifreq ifr = {0};
    char addr[16];
    uint8_t nidbuf[6];
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (s < 0) {
        perror("socket");
        exit(1);
    }

    char ifbuf[IFNAMSIZ];
    memset(ifbuf, 0, IFNAMSIZ);
    memcpy(ifr.ifr_name, londevice, IFNAMSIZ);
    ioctl(s, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    //Set to running so neuron id can be read
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
        perror("run");
        syslog(LOG_ERR, "Run: %s\n", strerror(errno));
    }

    int sockfd = init_sockfd();
    read_neuron_id(nidbuf, sockfd);
    int xcvr_id = read_xcvr_id(sockfd, ldisc);
    if (sockfd >0) close(sockfd);

    int tries = 5;
    while (find_nid_index(nidbuf, ifbuf, xcvr_name[xcvr_id], devstr) && tries-- > 0)
        sleep(2);
    // Unique ID read, set down so name can change and ip can be set
    ifr.ifr_flags &= !(IFF_UP | IFF_RUNNING);
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
        perror("set flags");
        syslog(LOG_CRIT, "Set flags: %s -- Exiting!\n", strerror(errno));
        exit(4);
    }

    if (strlen(ifbuf)) {
        //found an interface name this should be using, change it to use it
        memcpy(ifr.ifr_newname, ifbuf, IFNAMSIZ);
        if (ioctl(s, SIOCSIFNAME, &ifr) < 0) {
            perror("set name");
            syslog(LOG_CRIT, "Set name: %s -- Exiting!\n", strerror(errno));
            exit(3);
        }
        memcpy(londevice, ifbuf, IFNAMSIZ);
    }

    syslog(LOG_INFO, "Transceiver ID for %s: %s\n", londevice, xcvr_name[xcvr_id]);
    syslog(LOG_INFO, "Neuron ID for %s: %02x:%02x:%02x:%02x:%02x:%02x\n", londevice,
        nidbuf[0], nidbuf[1], nidbuf[2], nidbuf[3], nidbuf[4], nidbuf[5]);
    syslog(LOG_INFO, "TTY Dev for %s: %s\n", londevice, devstr);

    memcpy(ifr.ifr_name, londevice, IFNAMSIZ);

    //
    // Assign default address 
    //

    //Don't configure lon0 with the assumption it's managed by ifupdown
    // AP-857 and AP-866
    // lon0 is no longer default in /etc/network/interfaces file
    if (strcmp(londevice, "lon0"))
        //set a default ip and mask
        // AP - 3173 Change default address of lon devices to ayse a XX.1.YY.128 address
        // was set to 192.168.YY.1
        sprintf(addr, "%d.1.1%s.125", ipv6_domain_len_1_prefix, londevice + strlen("lon"));
    else
        sprintf(addr, "%d.1.5.125", ipv6_domain_len_1_prefix);

    syslog(LOG_INFO, "Assigning %s to %s\n", addr, londevice);
    struct sockaddr_in *in_addr = (struct sockaddr_in*)&ifr.ifr_addr;
    ifr.ifr_addr.sa_family = AF_INET;
    inet_pton(AF_INET, addr, &in_addr->sin_addr);
    if (ioctl(s, SIOCSIFADDR, &ifr) < 0) {
        perror("if set");
        syslog(LOG_CRIT, "IF set: %s -- Exiting!\n", strerror(errno));
        exit(2);
    }

    //
    // Assign net mask
    //
    inet_pton(AF_INET, "255.255.255.0", ifr.ifr_addr.sa_data + 2);
    if (ioctl(s, SIOCSIFNETMASK, &ifr) < 0) {
        perror("mask set");
        syslog(LOG_CRIT, "Mask set: %s -- Exiting!\n", strerror(errno));
        exit(2);
    }

    //done setting everything, set running again
    ioctl(s, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
        perror("run");
        syslog(LOG_CRIT, "Run: %s -- Exiting!\n", strerror(errno));
        exit(2);
    }
}

static int setup_lon_iface(char* devstr, int ldisc) {
    struct ifreq ifr = {0};
    struct ifaddrs *ifaddr, *ifa;
    int found = 0;
    int lonsd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    //This iterates through each lonX device and queries what tty is being used.
    //The SIOCDEVPRIVATE is defined in the u50 module's ioctl handler.
    getifaddrs(&ifaddr);
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        char socketdev[64];
        if (strncmp(ifa->ifa_name, "lon", 3)) continue;
        memcpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ);
        if (ioctl(lonsd, SIOCDEVPRIVATE, &ifr) < 0) {
            perror("ioctl");
            syslog(LOG_ERR, "Ioctl:%d: %s\n", __LINE__, strerror(errno));
        }
        sprintf(socketdev, "/dev/%s", (char*)&ifr.ifr_data);
        if (!memcmp(devstr, socketdev, strlen(devstr))) {
            found = 1;
            memcpy(londevice, ifa->ifa_name, IFNAMSIZ);
            break;
        }
    }
    freeifaddrs(ifaddr);
    if (!found) return -1;
    memcpy(ifr.ifr_name, londevice, strlen(londevice));

    assign_default_address(ldisc, devstr);
    return lonsd;
}

// Returns the number of LON devices are currently connected
static int lon_device_count()
{
    int index, count = 0;
    char londevStr[16];

    FILE *fd = popen("ip -f inet -o addr | grep lon", "r");
    if (fd)
    {
        char response[1024];
        while (fgets(response, sizeof(response)-1, fd) != NULL)
        {
            sscanf(response, "%d: %15s:", &index, londevStr);
            if (strncmp(londevStr, "lon", 3)) continue;
            count++;
        }
        pclose(fd);
    }
    return count;
}

static volatile int exiting = 0;
void sigpipe_handler(int sig)
{
    syslog(LOG_CRIT, "SIGPIPE caught\n");
    exiting = 1;
}

void sigdefault_handler(int sig)
{
    syslog(LOG_CRIT, "Caught signal %d!\n", sig);
}

int serial_valid(int fd)
{
    struct stat s;
    fstat(fd, &s);

    if( s.st_nlink < 1 ){
        return 0;
    }
    return 1;
}
 
// The U50 ldisc is 28, the U61 ldisc is 27
int main(int argc, char* argv[]) {
    int c;
    int unkopt = 0;
    int ldisc = 0;
    int serFd = 0;
    int lonSock = 0;
    int exitVal = 0;
    int read_nid = 0;
	int update_CENELEC = 0;
	int isCENELEC = -1;
    char xcvrtypestr[STD_XCVR_NAME_LEN];

    // N_U50; // Defined in kernel module, default is N_U50
    char *devstr = "/dev/ttyACM0";
    openlog("echlonifd", 0, LOG_USER);
    syslog(LOG_INFO, "echlonifd 1.6\n");

    while ((c = getopt(argc, argv, "d:l:x:n:p:u:c:")) != -1) {
        switch (c) {
            case 'd':
                // Specify the USB device (/dev/) to create the lonX device 
                devstr = optarg;
                break;
            case 'l':
                // Specify the line discipline to create the lonX device
                if (isdigit(optarg[0])) {
                     ldisc = atoi(optarg);
                    syslog(LOG_INFO, "Line disc is set to %d", ldisc);
                }
                break;
            case 'x':
                // Specify the lonX device to read the transceiver ID from the nid_index file
                // This option can't be used with any other options.
                strcpy(londevice, optarg);
                memset(xcvrtypestr, 0, sizeof(xcvrtypestr));
                exitVal = find_xcvr_type(londevice, xcvrtypestr);
                printf("%s\n", xcvrtypestr);
                closelog();
                return exitVal;
            case 'n':
			    // Specify the lonX device to read the neuron ID.
                // This option can't be used with any other options.
                strcpy(londevice, optarg);
                read_nid = 1;
                break;
            case 'p':
			    // Specify the lonX device to read the CENELEC protocol setting.
                // This option can't be used with any other options.
				strcpy(londevice, optarg);
                // Check if( xcvr_id == PL_20C || xcvr_id == PL_20N )
                memset(xcvrtypestr, 0, sizeof(xcvrtypestr));
                exitVal = find_xcvr_type(londevice, xcvrtypestr);
				if (!memcmp(xcvrtypestr, "PL-20", 5))
				{
				    exitVal = get_protocol(-1, NULL);
					if (exitVal == -1)
                        printf("Error: Cannot communicate with the %s device\n", londevice);
					else
					    printf("%s\n", (exitVal == 1) ? "CENELEC_On" : "CENELEC_Off");
				}
                else if (xcvrtypestr[0] == 0)
                {
                   	exitVal = -1;
                    printf("Error: %s is not registered in the system\n", londevice);
                }
                else
                {
                   	exitVal = -1;			
                    printf("Error: %s is not a powerline interface\n", londevice);
                }	
				closelog();
                return exitVal;
            case 'c':
                // Specify whether is to enable/disable the CENELEC protocol
                // Use this in conjunction with -u option (see below)		
                isCENELEC = optarg[0] == '1' ? 1 : 0;
				break;
            case 'u':
                // Specify the londevice to enable/disable the CENELEC protocol
                // This option can't be used with any other option				
				strcpy(londevice, optarg);
				update_CENELEC = 1;
                break;				
            default:
                unkopt = 1;
                break;
        }
    }
    if (unkopt) {
        syslog(LOG_ERR, "Error - unknown option.");
    }
    if (ldisc == 0) {
        if (strstr(devstr, "ttyACM")) {
            ldisc = N_U50;
        } else if (strstr(devstr, "ttyUSB")) {
            ldisc = N_U61;
        } else {
            ldisc = N_U50;
        }
    }

	if (update_CENELEC)
    {
        // Update the CENELEC protocol of the LON device
        memset(xcvrtypestr, 0, sizeof(xcvrtypestr));
        exitVal = find_xcvr_type(londevice, xcvrtypestr);
        // Check if( xcvr_id == PL_20C || xcvr_id == PL_20N )
        if (!memcmp(xcvrtypestr, "PL-20", 5))
        {
            if (isCENELEC == -1)
                isCENELEC = 1;
		    exitVal = set_protocol(-1, isCENELEC);
            if (exitVal != -1)
            {
                // Read the transceiver ID and the protocol again.
                int protocol = get_protocol(-1, NULL);
                printf("%s\n", (protocol == 1) ? "CENELEC_On" : "CENELEC_Off");
                int xcvr_id = read_xcvr_id(-1, N_U61);
                if (xcvr_id < STD_XCVR_NAMES_SIZE)
                {
                    if (protocol == 1)
                        xcvr_id = PL_20C;
                    else
	                    xcvr_id = PL_20N;
                    memcpy(xcvrtypestr, xcvr_name[xcvr_id], sizeof(xcvrtypestr));
                    update_xcvr_type(londevice, xcvr_name[xcvr_id]);
                }
                printf("device=%s protocol=%s xcvrType=%s\n", londevice, isCENELEC ? "CENELEC_On" : "CENELEC_Off", xcvrtypestr);				
            }
            else
            {
                exitVal = -1;
                printf("Failed to set CENELEC protocol to %s interface\n", londevice);
            }
        }
        else
        {
           	exitVal = -1;
            printf("%s is not a powerline interface\n", londevice);
        }
        closelog();
        return exitVal;
    }
	else if (read_nid)
    {
        // Only needs to read the Unique ID
        uint8_t nid_buf[6];
        exitVal = read_neuron_id(nid_buf, -1);
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
            nid_buf[0], nid_buf[1], nid_buf[2], nid_buf[3], nid_buf[4], nid_buf[5]);
        closelog();
        return exitVal;
    }

    // Don't become a daemon, it's incompatible with systemd Type=notify services!

    // Check to find out if this is the only LON device attached
    londevicecount = lon_device_count();
    syslog(LOG_DEBUG, "lon_device_count = %d", londevicecount);

    // Read domain one-byte prefix
    ipv6_domain_len_1_prefix = read_domain_len_1_prefix();
    syslog(LOG_DEBUG, "ipv6_domain_len_1_prefix = %d", ipv6_domain_len_1_prefix);

    if (signal(SIGPIPE,sigpipe_handler) == SIG_ERR)
        syslog(LOG_CRIT, "Cannot catch SIGPIPE\n");

    if ((serFd = setup_serial_interface(devstr, ldisc)) < 0) {
        syslog(LOG_CRIT, "failed to set up serial interface!\n");
        exitVal = -1;
    } else {
        if ((lonSock = setup_lon_iface(devstr, ldisc)) < 0) {
            syslog(LOG_CRIT, "failed to set up lon interface!\n");
            exitVal = -2;
        } else {
            sd_notify(0, "READY=1");
            for (;;) {
                usleep(100000); // 100 mS sleep
                if (!serial_valid(serFd)) {
                    syslog(LOG_CRIT, "TTY device removed, exiting!\n");
                    close(lonSock);
                    exitVal = -3;
                    break;
                }
                if (exiting) {
                    if (serial_valid(serFd))
                        close(serFd);
                    exitVal = -4;
                    break;
                }
            }
        }
    }

    syslog(LOG_CRIT, "process for %s is exiting (%d).\n", devstr, exitVal);
    closelog();
    return exitVal;
}
