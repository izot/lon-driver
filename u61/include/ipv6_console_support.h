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

/****************************************************************************

 *

 *  FILE DESCRIPTION:  

 *      This header file contains the definitions and function prototypes

 *      used for IPV6 tracing

 ***************************************************************************/

#ifndef _IPV6_CONSOLE_SUPPORT_H

#define _IPV6_CONSOLE_SUPPORT_H



#if IPV6_TRACE_ENABLED

#ifdef __cplusplus

extern "C" {            /* Assume C declarations for C++ */

#endif  /* __cplusplus */



#ifdef WIN32

#include <stdlib.h>

#endif



///////////////////////////////////////////////////////////////////////////////

// 

// Function prototypes 

//

///////////////////////////////////////////////////////////////////////////////



#ifdef WIN32

void FastLogToWindow(const char *format, ...);

#else

    #include "io_types.h"

    #if !USE_SIMPLE_IO

        extern system far void stdioInit(unsigned long baudRate);

    #endif

#endif



/******************************************************************************

  Function:  ipv6_print_string

   

  Summary:

    print a string on the console



  Parameters:

    string:         string to be displayed

*****************************************************************************/

void ipv6_print_string(const char * string);



/******************************************************************************

  Function:  ipv6_print_hex_byte

   

  Summary:

    print a single hex byte on the console



  Parameters:

    value:         value to be displayed

*****************************************************************************/

void ipv6_print_hex_byte(uint8_t value);



/******************************************************************************

  Function:  ipv6_print_hex_byte_ex

   

  Summary:

    print "%s%.2x\n" to the consle



  Parameters:

    title:         string to be displayed

    value:         value to be displayed

*****************************************************************************/

void ipv6_print_hex_byte_ex(const char *title, uint8_t value);



/******************************************************************************

  Function:  ipv6_print_hex_word

   

  Summary:

    print a 2 byte hex value on the console



  Parameters:

    value:         value to be displayed

*****************************************************************************/

void ipv6_print_hex_word(uint16_t value);



/******************************************************************************

  Function:  ipv6_print_hex_word_ex

   

  Summary:

    print "%s%.4x\n" to the console



  Parameters:

    title:         string to be displayed

    value:         value to be displayed

*****************************************************************************/

void ipv6_print_hex_word_ex(const char *title, uint16_t value);



/******************************************************************************

  Function:  ipv6_print_value

   

  Summary:

    print a 2 byte decimal value to the console



  Parameters:

    value:         value to be displayed

*****************************************************************************/

void ipv6_print_value(uint16_t value);



/******************************************************************************

  Function:  ipv6_print_value_ex

   

  Summary:

    print "%s%d\n" to the console



  Parameters:

    title:         string to be displayed

    value:         value to be displayed

*****************************************************************************/

void ipv6_print_value_ex(const char *title, uint16_t value);



/******************************************************************************

  Function:  ipv6_print_data

   

  Summary:

    print an array of data to the console



  Parameters:

    desc:          descriptive string to be displayed

    block:         pointer to the data

    length:        the length in bytes

*****************************************************************************/

void ipv6_print_data(const char* desc, const uint8_t* block, uint8_t length);

#ifdef __cplusplus

}

#endif  /* __cplusplus */



#else

#define ipv6_print_string(string)

#define ipv6_print_data(desc, block, length)

#define ipv6_print_hex_byte(value)

#define ipv6_print_hex_byte_ex(title, value)

#define ipv6_print_hex_word(value)

#define ipv6_print_hex_word_ex(title, value)

#define ipv6_print_value(value)

#define ipv6_print_value_ex(title, value)

#endif



#endif

